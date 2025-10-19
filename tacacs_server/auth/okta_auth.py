"""
Okta authentication backend with in-memory caching.

Uses the Okta Authentication API (AuthN). Group lookups use the Okta
Management API when an `api_token` is configured.
"""

import base64
import hmac
import json
import os
import random
import secrets
import threading
import time
from hashlib import sha256
from typing import Any
from typing import Any as _Any

import requests  # type: ignore[import-untyped]
from requests.adapters import HTTPAdapter  # type: ignore[import-untyped]

from tacacs_server.utils.logger import get_logger
from tacacs_server.utils.metrics import (
    okta_group_cache_hits,
    okta_group_cache_misses,
)
from tacacs_server.utils.simple_cache import TTLCache

from .base import AuthenticationBackend

logger = get_logger(__name__)

# Optional urllib3 Retry import after core imports to satisfy import-order linters
_Retry: _Any | None = None
try:  # urllib3 Retry may be missing in some environments
    from urllib3.util.retry import Retry as _Retry
except Exception:  # pragma: no cover
    _Retry = None


def _parse_exp_from_jwt(token: str) -> int | None:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1]
        padding = "=" * ((4 - len(payload_b64) % 4) % 4)
        payload_b64 += padding
        payload_bytes = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
        payload = json.loads(payload_bytes.decode("utf-8"))
        exp = payload.get("exp")
        if isinstance(exp, int | float):
            return int(exp)
    except Exception:
        logger.debug("Failed to parse exp from JWT", exc_info=True)
    return None


class OktaAuthBackend(AuthenticationBackend):
    """
    Okta authentication backend.

    Config options (cfg dict):
      org_url                - base Okta url, e.g. https://dev-xxxx.okta.com (required)
      api_token              - Okta Management API token (SSWS) if groups queries are
                               desired (optional)
      cache_default_ttl      - fallback TTL in seconds (default 60)
      verify_tls             - bool for requests.verify (default True)
      require_group_for_auth - bool: require user to be member of an allowed Okta group to count
                               as authorized (default False)
      authn_enabled          - bool: use Okta AuthN API (default True)
      mfa_enabled            - bool: enable simple MFA via password-suffix handling (default False)
      mfa_otp_digits         - int: number of digits for OTP suffix parsing (default 6)
      mfa_push_keyword       - str: keyword to trigger Okta Verify push when appended to password (default "push")
      mfa_timeout_seconds    - int: max seconds to wait for push approval (default 25)
      mfa_poll_interval      - float: seconds between push poll attempts (default 2.0)
    """

    def __init__(self, cfg: dict[str, Any]):
        super().__init__("okta")
        self.org_url = cfg.get("org_url") or cfg.get("okta_org_url")
        if not self.org_url:
            raise ValueError("Okta org_url must be provided in config (org_url)")
        # No client/app credentials needed for AuthN API
        self.client_id = None
        self.api_token = cfg.get("api_token") or cfg.get("OKTA_API_TOKEN")
        self.cache_default_ttl = int(cfg.get("cache_default_ttl", 60))
        vt = cfg.get("verify_tls", True)
        if isinstance(vt, str):
            self.verify_tls = vt.strip().lower() not in ("false", "0", "no")
        else:
            self.verify_tls = bool(vt)
        self.require_group_for_auth = bool(cfg.get("require_group_for_auth", False))
        # Default to AuthN API
        self.authn_enabled = bool(cfg.get("authn_enabled", True))
        # Simple MFA controls
        self.mfa_enabled = bool(cfg.get("mfa_enabled", False))
        try:
            self.mfa_otp_digits = int(cfg.get("mfa_otp_digits", 6))
        except Exception:
            self.mfa_otp_digits = 6
        self.mfa_push_keyword = str(cfg.get("mfa_push_keyword", "push")).strip().lower()
        try:
            self.mfa_timeout_seconds = int(cfg.get("mfa_timeout_seconds", 25))
        except Exception:
            self.mfa_timeout_seconds = 25
        try:
            self.mfa_poll_interval = float(cfg.get("mfa_poll_interval", 2.0))
        except Exception:
            self.mfa_poll_interval = 2.0

        # No static group-to-privilege mapping for Okta; privilege is determined later
        # via local user groups and the authorization policy engine.

        # endpoints
        self._authn_endpoint = self.org_url.rstrip("/") + "/api/v1/authn"
        self._groups_api_base = self.org_url.rstrip("/") + "/api/v1"

        # Auth cache: key=username+password HMAC -> (result_bool, expiry_ts, safe_attributes)
        # Never store raw passwords or tokens.
        self._cache: dict[str, tuple[bool, int, dict[str, Any]]] = {}
        self._lock = threading.Lock()
        # Separate safe attributes cache by username (no tokens)
        self._attr_cache: dict[str, dict[str, Any]] = {}
        # HMAC key for cache keys; allow override via env, else generate per-process
        self._hmac_key = (
            os.getenv("AUTH_CACHE_HMAC_KEY") or secrets.token_hex(32)
        ).encode("utf-8")

        # HTTP session with connection pooling and retries
        # Timeouts: (connect, read)
        connect_timeout = int(
            cfg.get("connect_timeout", cfg.get("request_timeout", 10))
        )
        read_timeout = int(cfg.get("read_timeout", cfg.get("request_timeout", 10)))
        self._timeout = (max(1, connect_timeout), max(1, read_timeout))
        pool_maxsize = int(cfg.get("pool_maxsize", 50))
        self._session = requests.Session()
        # Ignore system proxy env vars in controlled environments if configured
        self._trust_env_flag = bool(cfg.get("trust_env", False))
        if self._trust_env_flag is False:
            try:
                self._session.trust_env = False
            except Exception:
                pass
        adapter = HTTPAdapter(pool_connections=pool_maxsize, pool_maxsize=pool_maxsize)
        if _Retry is not None:
            retry = _Retry(
                total=int(cfg.get("max_retries", 2)),
                connect=int(cfg.get("max_retries_connect", cfg.get("max_retries", 2))),
                read=int(cfg.get("max_retries_read", cfg.get("max_retries", 2))),
                backoff_factor=float(cfg.get("backoff_factor", 0.3)),
                status_forcelist=(429, 500, 502, 503, 504),
                allowed_methods=frozenset({"GET", "POST"}),
                raise_on_status=False,
            )
            adapter.max_retries = retry
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

        # Group membership cache: username -> {"groups": [...], "priv": int}
        self._group_cache_ttl = int(cfg.get("group_cache_ttl", 1800))
        self._group_cache_fail_ttl = int(cfg.get("group_cache_fail_ttl", 60))
        self._group_cache = TTLCache[str, dict[str, Any]](
            ttl_seconds=self._group_cache_ttl,
            maxsize=int(cfg.get("group_cache_maxsize", 50000)),
        )

        # ROPC removed; always use AuthN API

        # No token introspection with AuthN-only flow
        self._introspect_enabled = False

        # Circuit breaker settings
        self._cb_fail_threshold = int(cfg.get("circuit_failures", 5))
        self._cb_cooldown = int(cfg.get("circuit_cooldown", 30))
        self._cb_consecutive_failures = 0
        self._cb_open_until = 0
        self._retries_429_total = 0

        # Strict group mode: require API token when require_group_for_auth=true
        self._strict_group_mode = bool(cfg.get("strict_group_mode", False))
        self._use_basic_auth_flag = False
        if (
            self.require_group_for_auth
            and not self.api_token
            and self._strict_group_mode
        ):
            raise ValueError(
                "Okta configuration invalid: require_group_for_auth=true but api_token missing and strict_group_mode=true"
            )

    def _cache_key(self, username: str, password: str) -> str:
        # HMAC(username || "\0" || password)
        msg = f"{username}\0{password}".encode()
        return hmac.new(self._hmac_key, msg, sha256).hexdigest()

    def _cache_get(self, key: str) -> bool | None:
        now = int(time.time())
        with self._lock:
            v = self._cache.get(key)
            if not v:
                return None
            result, expiry, _attrs = v
            if expiry and expiry > now:
                return result
            # expired
            del self._cache[key]
            return None

    def _cache_set(
        self,
        key: str,
        result: bool,
        expiry_ts: int | None,
        attributes: dict[str, Any] | None = None,
    ):
        # Add small negative-only jitter (<= 10%) to reduce synchronized expiries.
        # Never extend a token-derived expiry beyond the provided expiry_ts.
        base_ttl = self.cache_default_ttl
        now = int(time.time())
        if expiry_ts is None:
            # For fallback TTLs, subtract up to 10% jitter
            expiry_ts = now + base_ttl
            jitter = int(base_ttl * 0.1)
            if jitter > 0:
                expiry_ts -= random.randint(0, jitter)
        else:
            # For token-derived expiry, subtract a small jitter bounded by remaining TTL
            # Cap jitter by: 10% of base TTL, 10% of remaining, and an absolute max of 5s
            remaining = max(0, int(expiry_ts - now))
            jitter_cap = int(min(int(base_ttl * 0.1), int(remaining * 0.1), 5))
            if jitter_cap > 0:
                expiry_ts -= random.randint(0, jitter_cap)
        attrs = attributes or {}
        with self._lock:
            self._cache[key] = (result, int(expiry_ts), attrs)

    # ROPC token endpoint removed

    def _call_authn_endpoint(
        self, username: str, password: str
    ) -> tuple[bool, int | None, dict[str, Any]]:
        """
        Perform Okta Authentication API call to validate username/password.
        On success, returns (True, expiry_ts_or_None, {"okta_user_id": id}).
        The AuthN sessionToken is short-lived; we do not use it further. We
        cache success using default TTL with jitter.
        """
        try:
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            # Optional simple MFA handling via password suffix
            base_password = password
            requested_otp: str | None = None
            requested_push = False
            if self.mfa_enabled and isinstance(password, str):
                pw = password
                pws = pw.strip()
                kw = (self.mfa_push_keyword or "").lower()
                # Accept several separators or no separator: " push", "+push", ":push", "/push", ".push", "-push", "#push", "@push", or just "push"
                if kw:
                    candidates = [
                        " " + kw,
                        "+" + kw,
                        ":" + kw,
                        "/" + kw,
                        "." + kw,
                        "-" + kw,
                        "#" + kw,
                        "@" + kw,
                        kw,
                    ]
                    pws_l = pws.lower()
                    for suf in candidates:
                        if pws_l.endswith(suf):
                            requested_push = True
                            cut = len(pws) - len(suf)
                            base_password = pws[:cut]
                            break
                # If not push, detect trailing N digits as OTP
                if not requested_push:
                    d = self.mfa_otp_digits
                    if d >= 4 and len(pws) > d and pws[-d:].isdigit():
                        requested_otp = pws[-d:]
                        base_password = pws[:-d]

            body = {"username": username, "password": base_password}
            a_start = time.time()
            resp = requests.post(
                self._authn_endpoint,
                headers=headers,
                json=body,
                verify=self.verify_tls,
                timeout=self._timeout,
            )
            # Basic latency metric reuse (token latency) to avoid adding new metric
            try:
                from tacacs_server.utils.metrics import okta_token_latency

                okta_token_latency.observe(max(0.0, time.time() - a_start))
            except Exception:
                pass
            if resp.status_code not in (200, 201):
                logger.debug(
                    "Okta AuthN API returned non-200: %s %s",
                    resp.status_code,
                    resp.text,
                )
                return False, None, {}
            data = resp.json() or {}
            status_up = str(data.get("status", "")).upper()
            if status_up == "SUCCESS":
                pass
            elif status_up == "MFA_REQUIRED" and self.mfa_enabled:
                # Attempt MFA follow-up if caller supplied an OTP or push keyword
                state_token = data.get("stateToken")
                factors = (data.get("_embedded") or {}).get("factors", [])
                if not state_token or not isinstance(factors, list):
                    logger.debug("MFA required but stateToken/factors missing")
                    return False, None, {}
                # Prefer OTP if provided, else push if requested
                if requested_otp:
                    # Find a TOTP software token factor
                    verify_href = None
                    for f in factors:
                        try:
                            if f.get("factorType") in (
                                "token:software:totp",
                                "token:hotp",
                            ) and "verify" in (f.get("_links") or {}):
                                verify_href = f["_links"]["verify"]["href"]
                                break
                        except Exception:
                            continue
                    if not verify_href:
                        logger.debug("No TOTP factor available for OTP verification")
                        return False, None, {}
                    v = requests.post(
                        verify_href,
                        json={"stateToken": state_token, "passCode": requested_otp},
                        headers={"Accept": "application/json"},
                        verify=self.verify_tls,
                        timeout=self._timeout,
                    )
                    if v.status_code not in (200, 201):
                        logger.debug("OTP verify failed: %s %s", v.status_code, v.text)
                        return False, None, {}
                    data = v.json() or {}
                    if str(data.get("status", "")).upper() != "SUCCESS":
                        logger.debug(
                            "OTP verify did not reach SUCCESS: %s", data.get("status")
                        )
                        return False, None, {}
                elif requested_push:
                    # Find Okta Verify push factor
                    verify_href = None
                    for f in factors:
                        try:
                            if (
                                f.get("factorType") == "push"
                                and f.get("provider") == "OKTA"
                                and "verify" in (f.get("_links") or {})
                            ):
                                verify_href = f["_links"]["verify"]["href"]
                                break
                        except Exception:
                            continue
                    if not verify_href:
                        logger.debug("No Okta Verify push factor available")
                        return False, None, {}
                    # Initiate push and poll until SUCCESS or timeout
                    start_poll = time.time()
                    current = requests.post(
                        verify_href,
                        json={"stateToken": state_token},
                        headers={"Accept": "application/json"},
                        verify=self.verify_tls,
                        timeout=self._timeout,
                    )
                    if current.status_code not in (200, 201):
                        logger.debug(
                            "Push verify init failed: %s %s",
                            current.status_code,
                            current.text,
                        )
                        return False, None, {}
                    while (time.time() - start_poll) < max(5, self.mfa_timeout_seconds):
                        resp_data: dict[str, Any] = {}
                        try:
                            j = current.json()
                            if isinstance(j, dict):
                                resp_data = j
                        except Exception:
                            pass
                        st = str(resp_data.get("status", "")).upper()
                        if st == "SUCCESS":
                            data = resp_data
                            break
                        # Some responses include factorResult WAITING; retry same verify
                        poll_href = verify_href
                        links = (
                            resp_data.get("_links")
                            if isinstance(resp_data, dict)
                            else None
                        )
                        if isinstance(links, dict):
                            try:
                                next_link = links.get("next")
                                if isinstance(next_link, dict) and isinstance(
                                    next_link.get("href"), str
                                ):
                                    poll_href = next_link["href"]
                            except Exception:
                                poll_href = verify_href
                        time.sleep(max(0.5, self.mfa_poll_interval))
                        current = requests.post(
                            poll_href,
                            json={"stateToken": state_token},
                            headers={"Accept": "application/json"},
                            verify=self.verify_tls,
                            timeout=self._timeout,
                        )
                    else:
                        logger.debug("Push verify timed out")
                        return False, None, {}
                else:
                    logger.debug(
                        "MFA required but no OTP/push indicator present in password"
                    )
                    return False, None, {}
            else:
                logger.debug("Okta AuthN status not SUCCESS: %s", data.get("status"))
                return False, None, {}
            # Extract user id for group lookups
            user_id = (
                (data.get("_embedded") or {}).get("user", {}).get("id")
                if isinstance(data.get("_embedded"), dict)
                else None
            )
            attrs: dict[str, Any] = {}
            if user_id:
                attrs["okta_user_id"] = str(user_id)
            # No trusted expiry from AuthN; leave None to use default TTL in cache
            return True, None, attrs
        except Exception:
            logger.exception("Okta AuthN request failed")
            return False, None, {}

    # Userinfo-based group lookup removed; we resolve by user id directly

    def authenticate(self, username: str, password: str, **kwargs) -> bool:
        """
        Authenticate user via Okta AuthN. If require_group_for_auth is True or a
        device-scoped allowed Okta group list is provided, authentication is
        considered successful only if the user is a member of at least one of the
        allowed Okta groups.
        """
        # Circuit breaker with cooldown reset
        now_i = int(time.time())
        if self._cb_open_until and now_i >= self._cb_open_until:
            self._cb_open_until = 0
            self._cb_consecutive_failures = 0
            try:
                from tacacs_server.utils.metrics import okta_circuit_reset_total

                okta_circuit_reset_total.inc()
            except Exception:
                pass
        if self._cb_open_until and now_i < self._cb_open_until:
            logger.warning(
                "Okta circuit breaker open; denying authentication for stability"
            )
            try:
                from tacacs_server.utils.metrics import okta_circuit_open

                okta_circuit_open.set(1)
            except Exception:
                pass
            return False
        else:
            try:
                from tacacs_server.utils.metrics import okta_circuit_open

                okta_circuit_open.set(0)
            except Exception:
                pass

        # AuthN is the only supported flow
        use_authn = True

        key = self._cache_key(username, password)
        cached = self._cache_get(key)
        if cached is not None:
            logger.debug("Okta cache hit for %s -> %s", username, cached)
            return cached

        success, expiry_ts, attrs = self._call_authn_endpoint(username, password)
        if not success:
            # cache negative result shortly
            fail_ttl = int(kwargs.get("fail_ttl", 5))
            self._cache_set(key, False, int(time.time()) + fail_ttl, {})
            self._cb_consecutive_failures += 1
            if self._cb_consecutive_failures >= self._cb_fail_threshold:
                self._cb_open_until = int(time.time()) + self._cb_cooldown
                logger.warning(
                    "Okta circuit breaker opening: failures=%s cooldown=%ss",
                    self._cb_consecutive_failures,
                    self._cb_cooldown,
                )
                try:
                    from tacacs_server.utils.metrics import okta_circuit_open_total

                    okta_circuit_open_total.inc()
                except Exception:
                    pass
            return False

        priv = 0
        if use_authn:
            okta_user_id = attrs.get("okta_user_id")
            # Optional device-scoped allowed Okta groups
            allowed_okta_groups_kw = kwargs.get("allowed_okta_groups")
            allowed_set: set[str] | None = None
            if isinstance(allowed_okta_groups_kw, (list, set, tuple)):
                try:
                    allowed_set = {
                        str(x)
                        for x in allowed_okta_groups_kw
                        if isinstance(x, (str, int))
                    }
                except Exception:
                    allowed_set = None
            if (
                self.api_token or self.require_group_for_auth or allowed_set
            ) and okta_user_id:
                priv = self._get_privilege_for_userid(
                    str(okta_user_id), username, allowed_okta_groups=allowed_set
                )
        else:
            pass

        # If device-scoped allowed groups provided or require_group_for_auth true and no privilege, fail
        if (kwargs.get("allowed_okta_groups") and priv == 0) or (
            self.require_group_for_auth and priv == 0
        ):
            logger.warning(
                "Okta authentication valid but user lacks required Okta groups for device or mapping: %s",
                username,
            )
            if kwargs.get("allowed_okta_groups"):
                # Do not cache device-scoped denials to avoid cross-device side effects
                pass
            else:
                self._cache_set(
                    key,
                    False,
                    expiry_ts or (int(time.time()) + self.cache_default_ttl),
                    attrs,
                )
            return False

        # Cache based on expiry_ts; include minimal safe token metadata for tests
        safe_attrs = {"privilege": priv}
        if attrs.get("okta_user_id"):
            safe_attrs["okta_user_id"] = attrs["okta_user_id"]
        self._cache_set(key, True, expiry_ts, safe_attrs)
        with self._lock:
            self._attr_cache[username] = dict(safe_attrs)
        logger.info(
            "Okta authentication success for %s (cached until %s) priv=%s",
            username,
            expiry_ts,
            priv,
        )
        self._cb_consecutive_failures = 0
        return True

    def _get_privilege_for_userid(
        self,
        okta_user_id: str,
        username: str,
        *,
        allowed_okta_groups: set[str] | None = None,
    ) -> int:
        """
        Use Okta Management API to fetch groups for a given user id and map to privilege.
        """
        try:
            if not self.api_token:
                logger.warning(
                    "Okta groups lookup disabled: no API token configured (require_group_for_auth=%s)",
                    self.require_group_for_auth,
                )
                try:
                    self._group_cache.set(
                        username,
                        {"groups": [], "priv": 0},
                        ttl=self._group_cache_fail_ttl,
                    )
                except Exception:
                    pass
                return 0

            cached = self._group_cache.get(username)
            if cached is not None:
                try:
                    okta_group_cache_hits.inc()
                except Exception:
                    pass
                return int(cached.get("priv", 0))
            else:
                try:
                    okta_group_cache_misses.inc()
                except Exception:
                    pass

            groups_url = f"{self._groups_api_base}/users/{okta_user_id}/groups"
            headers = {
                "Authorization": f"SSWS {self.api_token}",
                "Accept": "application/json",
            }
            groups: list[str] = []
            group_ids: list[str] = []
            url_next: str | None = groups_url
            while url_next:
                g_start = time.time()
                r = requests.get(
                    url_next,
                    headers=headers,
                    timeout=self._timeout,
                    verify=self.verify_tls,
                )
                try:
                    from tacacs_server.utils.metrics import (
                        okta_group_latency,
                        okta_group_requests,
                        okta_retries_total,
                    )

                    okta_group_requests.inc()
                    okta_group_latency.observe(max(0.0, time.time() - g_start))
                    if r.status_code in (429, 500, 502, 503, 504):
                        okta_retries_total.inc()
                except Exception:
                    pass
                if r.status_code != 200:
                    logger.debug("Okta groups API failed: %s %s", r.status_code, r.text)
                    if r.status_code == 429:
                        try:
                            ra = r.headers.get("Retry-After")
                            if ra is not None:
                                ra_s = int(ra)
                                self._group_cache_fail_ttl = max(
                                    self._group_cache_fail_ttl, min(ra_s, 300)
                                )
                                self._retries_429_total += 1
                        except Exception:
                            pass
                    try:
                        self._group_cache.set(
                            username,
                            {"groups": [], "priv": 0},
                            ttl=self._group_cache_fail_ttl,
                        )
                    except Exception:
                        pass
                    break
                page = r.json()
                if isinstance(page, list):
                    for g in page:
                        if not isinstance(g, dict):
                            continue
                        name = str(g.get("profile", {}).get("name", ""))
                        gid = str(g.get("id", ""))
                        if name:
                            groups.append(name.lower())
                        if gid:
                            group_ids.append(gid)
                link = r.headers.get("Link") or r.headers.get("link")
                url_next = None
                if link and 'rel="next"' in link:
                    try:
                        for part in link.split(","):
                            if 'rel="next"' in part:
                                s = part.find("<")
                                e = part.find(">", s + 1)
                                if s != -1 and e != -1:
                                    url_next = part[s + 1 : e]
                                    break
                    except Exception:
                        url_next = None

            # Enforce device-scoped allowed list if provided (match by id or name)
            if allowed_okta_groups:
                try:
                    allowed_lc = {str(x).lower() for x in allowed_okta_groups}
                except Exception:
                    allowed_lc = set()
                has_match = any(g in allowed_lc for g in groups) or any(
                    gid in allowed_okta_groups for gid in group_ids
                )
                if not has_match:
                    logger.warning(
                        "Okta AuthN success but user not in allowed Okta groups for device: %s",
                        username,
                    )
                    try:
                        self._group_cache.set(
                            username,
                            {"groups": groups, "priv": 0},
                            ttl=self._group_cache_fail_ttl,
                        )
                    except Exception:
                        pass
                    return 0

            # Cache group names; privilege remains 0 (computed later by policy engine)
            try:
                self._group_cache.set(username, {"groups": groups, "priv": 0})
            except Exception:
                pass
            return 0
        except Exception:
            logger.exception("Failed to determine Okta groups/privilege (by user id)")
            return 0

    def get_user_attributes(self, username: str) -> dict[str, Any]:
        # Return only safe attributes (never tokens)
        with self._lock:
            return dict(self._attr_cache.get(username) or {})

    def reload(self) -> None:
        with self._lock:
            self._cache.clear()
            self._attr_cache.clear()
            logger.info("OktaAuthBackend cache cleared")

    def get_stats(self) -> dict[str, Any]:
        try:
            # Session adapters are stored in a dict
            adapters = getattr(self._session, "adapters", {}) or {}
            https_adapter = adapters.get("https://")
            pool_sz = None
            if https_adapter is not None:
                try:
                    pool_sz = getattr(https_adapter, "_pool_maxsize", None)
                except Exception:
                    pool_sz = None
            return {
                "org_url": self.org_url,
                "verify_tls": self.verify_tls,
                "pool_maxsize": pool_sz,
                "circuit_open": 1
                if (self._cb_open_until and int(time.time()) < self._cb_open_until)
                else 0,
                "retries_429_total": self._retries_429_total,
                "flags": {
                    "authn_enabled": True,
                    "strict_group_mode": self._strict_group_mode,
                    "trust_env": self._trust_env_flag,
                    "require_group_for_auth": self.require_group_for_auth,
                },
                "group_cache": {
                    "hits": getattr(self._group_cache, "hits", 0),
                    "misses": getattr(self._group_cache, "misses", 0),
                    "evictions": getattr(self._group_cache, "evictions", 0),
                    "ttl": self._group_cache_ttl,
                    "fail_ttl": self._group_cache_fail_ttl,
                },
                "timeouts": {"connect": self._timeout[0], "read": self._timeout[1]},
                "auth_cache_entries": len(self._cache),
            }
        except Exception:
            return {"org_url": self.org_url}

    def close(self) -> None:
        """Release HTTP session resources (sockets)."""
        try:
            self._session.close()
        except Exception:
            pass
