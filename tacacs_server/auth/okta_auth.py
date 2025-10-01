"""
Okta authentication backend (OAuth2 token endpoint) with in-memory caching.
"""
from typing import Dict, Any, Optional, Tuple
import time
import threading
import requests
import json
import base64
import datetime

from .base import AuthenticationBackend
from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)

def _parse_exp_from_jwt(token: str) -> Optional[int]:
    try:
        parts = token.split('.')
        if len(parts) < 2:
            return None
        payload_b64 = parts[1]
        padding = '=' * ((4 - len(payload_b64) % 4) % 4)
        payload_b64 += padding
        payload_bytes = base64.urlsafe_b64decode(payload_b64.encode('ascii'))
        payload = json.loads(payload_bytes.decode('utf-8'))
        exp = payload.get('exp')
        if isinstance(exp, (int, float)):
            return int(exp)
    except Exception:
        logger.debug("Failed to parse exp from JWT", exc_info=True)
    return None

class OktaAuthBackend(AuthenticationBackend):
    """
    Okta OAuth2 token-based backend.

    Config options (cfg dict):
      org_url                - base Okta url, e.g. https://dev-xxxx.okta.com (required)
      client_id              - OAuth2 client id for password grant (required)
      api_token              - Okta Management API token (SSWS) if groups queries are desired (optional)
      cache_default_ttl      - fallback TTL in seconds (default 60)
      verify_tls             - bool for requests.verify (default True)
      group_privilege_map    - JSON string or dict mapping group names -> privilege int
      require_group_for_auth - bool: require user to be member of mapped group to count as authorized (default False)
    """
    def __init__(self, cfg: Dict[str, Any]):
        super().__init__("okta")
        self.org_url = cfg.get("org_url") or cfg.get("okta_org_url")
        if not self.org_url:
            raise ValueError("Okta org_url must be provided in config (org_url)")
        self.client_id = cfg.get("client_id") or cfg.get("CLIENT_ID")
        if not self.client_id:
            raise ValueError("Okta client_id must be provided in config (client_id)")
        self.api_token = cfg.get("api_token") or cfg.get("OKTA_API_TOKEN")
        self.cache_default_ttl = int(cfg.get("cache_default_ttl", 60))
        self.verify_tls = bool(cfg.get("verify_tls", True))
        self.require_group_for_auth = bool(cfg.get("require_group_for_auth", False))

        # parse group_privilege_map if provided as JSON string
        gpm = cfg.get("group_privilege_map", {})
        if isinstance(gpm, str):
            try:
                gpm = json.loads(gpm)
            except Exception:
                gpm = {}
        # ensure keys are str and values int
        self.group_privilege_map: Dict[str, int] = {str(k): int(v) for k, v in (gpm or {}).items()}
        # sensible defaults if none provided
        if not self.group_privilege_map:
            self.group_privilege_map = {"Level15": 15, "Level7": 7, "Level1": 1}

        # endpoints
        self._token_endpoint = self.org_url.rstrip('/') + "/oauth2/default/v1/token"
        self._userinfo_endpoint = self.org_url.rstrip('/') + "/oauth2/default/v1/userinfo"
        self._groups_api_base = self.org_url.rstrip('/') + "/api/v1"

        # internal cache: username -> (result_bool, expiry_ts, attributes_dict)
        self._cache: Dict[str, Tuple[bool, int, Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def _cache_get(self, username: str) -> Optional[bool]:
        now = int(time.time())
        with self._lock:
            v = self._cache.get(username)
            if not v:
                return None
            result, expiry, _attrs = v
            if expiry and expiry > now:
                return result
            # expired
            del self._cache[username]
            return None

    def _cache_set(self, username: str, result: bool, expiry_ts: Optional[int], attributes: Optional[Dict[str, Any]] = None):
        if expiry_ts is None:
            expiry_ts = int(time.time()) + self.cache_default_ttl
        attrs = attributes or {}
        with self._lock:
            self._cache[username] = (result, int(expiry_ts), attrs)

    def _call_token_endpoint(self, username: str, password: str) -> Tuple[bool, Optional[int], Dict[str, Any]]:
        """
        Perform OAuth2 password grant against Okta token endpoint.
        Returns (success, expiry_ts_or_None, attributes)
        """
        try:
            headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
            data = {
                "grant_type": "password",
                "username": username,
                "password": password,
                "client_id": self.client_id,
                "scope": "openid profile groups offline_access"
            }
            resp = requests.post(self._token_endpoint, headers=headers, data=data, verify=self.verify_tls, timeout=10)
            if resp.status_code not in (200, 201):
                logger.debug("Okta token endpoint returned non-200: %s %s", resp.status_code, resp.text)
                return False, None, {}
            body = resp.json()
            access_token = body.get("access_token")
            expires_in = body.get("expires_in")
            expiry_ts = None
            if isinstance(expires_in, (int, float)):
                expiry_ts = int(time.time()) + int(expires_in)
            elif access_token:
                parsed = _parse_exp_from_jwt(access_token)
                if parsed:
                    expiry_ts = parsed
            attrs = {"access_token": access_token, "token_response": body}
            return True, expiry_ts, attrs
        except Exception:
            logger.exception("Okta token request failed")
            return False, None, {}

    def _get_privilege_for_user(self, access_token: str, username: str) -> int:
        """
        Option A: Use userinfo to get 'sub' then call /api/v1/users/{sub}/groups using Management API token (SSWS).
        Map groups to privilege levels using self.group_privilege_map.
        Returns the highest matched privilege (or 0).
        """
        try:
            # get userinfo (to retrieve sub)
            headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
            r = requests.get(self._userinfo_endpoint, headers=headers, timeout=10, verify=self.verify_tls)
            if r.status_code != 200:
                logger.debug("Okta userinfo failed: %s %s", r.status_code, r.text)
                return 0
            userinfo = r.json()
            okta_sub = userinfo.get("sub")
            if not okta_sub:
                logger.debug("Okta userinfo missing 'sub'")
                return 0

            if not self.api_token:
                logger.warning("OKTA API token not configured; cannot query groups API")
                return 0

            groups_url = f"{self._groups_api_base}/users/{okta_sub}/groups"
            headers = {"Authorization": f"SSWS {self.api_token}", "Accept": "application/json"}
            gresp = requests.get(groups_url, headers=headers, timeout=10, verify=self.verify_tls)
            if gresp.status_code != 200:
                logger.debug("Okta groups API failed: %s %s", gresp.status_code, gresp.text)
                return 0
            groups = [g.get("profile", {}).get("name") for g in gresp.json() if isinstance(g, dict)]
            # determine highest privilege matching map
            priv = 0
            for g in groups:
                if g in self.group_privilege_map:
                    try:
                        lv = int(self.group_privilege_map[g])
                        if lv > priv:
                            priv = lv
                    except Exception:
                        continue
            return priv
        except Exception:
            logger.exception("Failed to determine Okta groups/privilege")
            return 0

    def authenticate(self, username: str, password: str, **kwargs) -> bool:
        """
        Authenticate user via Okta token endpoint. On success cache until token expiry.
        If require_group_for_auth is True, authentication only considered successful if user belongs to a mapped group (>0 privilege).
        """
        cached = self._cache_get(username)
        if cached is not None:
            logger.debug("Okta cache hit for %s -> %s", username, cached)
            return cached

        success, expiry_ts, attrs = self._call_token_endpoint(username, password)
        if not success:
            # cache negative result shortly
            fail_ttl = int(kwargs.get("fail_ttl", 5))
            self._cache_set(username, False, int(time.time()) + fail_ttl, {})
            return False

        access_token = attrs.get("access_token")
        priv = 0
        if access_token and (self.api_token or self.require_group_for_auth):
            priv = self._get_privilege_for_user(access_token, username)

        # If require_group_for_auth true and no privilege found, treat as failure
        if self.require_group_for_auth and priv == 0:
            logger.info("Okta auth succeeded (token) but user not in required groups: %s", username)
            self._cache_set(username, False, expiry_ts or (int(time.time()) + self.cache_default_ttl), attrs)
            return False

        # Cache based on expiry_ts if available
        self._cache_set(username, True, expiry_ts, {"privilege": priv, **attrs})
        logger.info("Okta authentication success for %s (cached until %s) priv=%s", username, expiry_ts, priv)
        return True

    def get_user_attributes(self, username: str) -> Dict[str, Any]:
        with self._lock:
            v = self._cache.get(username)
            if v:
                return v[2] or {}
            return {}

    def reload(self) -> None:
        with self._lock:
            self._cache.clear()
            logger.info("OktaAuthBackend cache cleared")
