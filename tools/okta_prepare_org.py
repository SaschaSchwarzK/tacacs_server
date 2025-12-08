#!/usr/bin/env python3
"""
This script is used by tests to prepare an Okta developer org with apps/users/groups.
Any change to this script my result in test failures until the test manifests are updated.

Okta Phase-1 Org Preparer (CLI)

Creates (or ensures) test artifacts in an Okta *developer* org:
 - Two groups: tacacs-ops, tacacs-admin (names configurable)
 - Two users with passwords (operator/admin)
 - Optional OIDC Web app (not required for AuthN-only flow used by backend)
 - Assign user->group

Writes a JSON manifest with resource IDs for reuse by tests.
Supports a full teardown (--teardown) that deletes what it created.

USAGE:
  # Create/ensure resources, write manifest
  poetry run python tools/okta_prepare_org.py \
      --org-url "$OKTA_ORG_URL" \
      --api-token "$OKTA_API_TOKEN" \
      --output "./okta_test_data.json" \
      --no-app \
      --service-auth-method private_key_jwt \
      --service-scopes "okta.users.read,okta.groups.read" \
      --write-backend-config "config/okta.generated.conf"
  poetry run python tools/okta_prepare_org.py \
      --org-url "$OKTA_ORG_URL" \
      --api-token "$OKTA_API_TOKEN" \
      --output ./okta_test_data.json \
      --create-service-app  \
      --service-auth-method private_key_jwt \
      --service-scopes "okta.users.read,okta.groups.read" \
      --app-auth-method private_key_jwt \
      --write-backend-config "config/okta.generated.conf"

  # Teardown everything created from a previous run
  python okta_prepare_org.py \
      --org-url "$OKTA_ORG_URL" \
      --api-token "$OKTA_API_TOKEN" \
      --output "./okta_test_data.json" \
      --teardown

ENV VAR FALLBACKS:
  OKTA_ORG_URL, OKTA_API_TOKEN, OKTA_TEST_OUTPUT

NOTES:
  - Backend now uses Okta AuthN API for authentication; group lookups for
    authorization require an Okta Management API token with okta.users.read and
    okta.groups.read. This script accepts an SSWS API token (OKTA_API_TOKEN)
    and can verify basic permissions.
  - Users are created ACTIVE immediately (no email activation flow).
  - If you want activation links, create with --user-activate false and
    wire a separate activation step for your workflow.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import secrets as _secrets
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from typing import Any

import okta.models as models

# okta SDK (management)
from okta.client import Client as OktaClient


# ---------- Logging ----------
def setup_logger(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


# ---------- Helpers ----------
class RetryError(RuntimeError):
    pass


async def with_retries(
    func: Callable[[], Awaitable[Any]],
    *,
    attempts: int = 5,
    base_delay: float = 0.5,
    logger: logging.Logger,
    what: str,
) -> Any:
    """Simple async exponential backoff."""
    err: BaseException | None = None
    for i in range(1, attempts + 1):
        try:
            return await func()
        except Exception as e:  # noqa: BLE001
            err = e
            sleep_s = base_delay * (2 ** (i - 1))
            logger.debug("Retry %s/%s for %s after error: %s", i, attempts, what, e)
            if i < attempts:
                await asyncio.sleep(sleep_s)
    logger.error("%s failed after %s attempts; last error: %s", what, attempts, err)
    raise RetryError(f"{what} failed after {attempts} attempts: {err}") from err


async def aiter_or_list(iterable):
    """Normalize Okta SDK list_* results to a Python list.

    The Okta Python SDK may return:
      - an async iterator (preferred, newer versions), or
      - a concrete list (older or different code paths), or
      - a synchronous iterator.

    This helper accepts any of these and returns a list.
    """
    if iterable is None:
        return []
    # async iterator
    if hasattr(iterable, "__aiter__"):
        items = []
        async for item in iterable:
            items.append(item)
        return items
    # already a list/tuple
    if isinstance(iterable, (list, tuple)):
        return list(iterable)
    # fallback: try to consume as a synchronous iterable
    try:
        return list(iterable)
    except Exception:
        return [iterable]


# ---------- Manifest ----------
@dataclass
class GroupInfo:
    id: str
    name: str


@dataclass
class UserInfo:
    id: str
    login: str
    status: str


@dataclass
class AppInfo:
    id: str
    clientId: str | None = None
    clientSecret: str | None = None
    authMethod: str | None = None  # e.g., client_secret, private_key_jwt
    appType: str | None = None  # e.g., web, service
    privateKeyPath: str | None = None
    privateKeyId: str | None = None


@dataclass
class Manifest:
    groups: dict[str, GroupInfo]
    users: dict[str, UserInfo]
    app: AppInfo | None = None
    service_app: AppInfo | None = None

    def to_json(self) -> str:
        return json.dumps(
            {
                "groups": {k: asdict(v) for k, v in self.groups.items()},
                "users": {k: asdict(v) for k, v in self.users.items()},
                "app": asdict(self.app) if self.app else None,
                "service_app": asdict(self.service_app) if self.service_app else None,
            },
            indent=2,
        )

    @staticmethod
    def from_file(path: str) -> Manifest:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        groups = {k: GroupInfo(**v) for k, v in data.get("groups", {}).items()}
        users = {k: UserInfo(**v) for k, v in data.get("users", {}).items()}
        app = data.get("app")
        app_info = AppInfo(**app) if app else None
        svc = data.get("service_app")
        svc_info = AppInfo(**svc) if svc else None
        return Manifest(groups=groups, users=users, app=app_info, service_app=svc_info)

    def write(self, path: str) -> None:
        tmp = f"{path}.tmp-{int(time.time())}"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        os.replace(tmp, path)


# ---------- Okta Ops ----------
class OktaPreparer:
    def __init__(self, org_url: str, api_token: str, logger: logging.Logger):
        self.logger = logger
        self.org_url = org_url
        self.api_token = api_token
        self.client = OktaClient({"orgUrl": org_url, "token": api_token})

    async def verify_management_api_perms(self) -> bool:
        """Quickly verify that the token can list groups (okta.groups.read).

        Returns True on success, False otherwise. Does not raise.
        """
        try:
            groups_iter, _, _ = await self.client.list_groups(limit=1)
            _ = await aiter_or_list(groups_iter)
            self.logger.info("Okta token appears to have okta.groups.read permission")
            return True
        except Exception as e:  # noqa: BLE001
            self.logger.warning(
                "Could not verify groups read permission (token may lack okta.groups.read): %s",
                e,
            )
            return False

    # ---- Groups ----
    async def ensure_group(self, name: str, description: str = "") -> GroupInfo:
        async def _search():
            # list_groups supports q= substring search
            groups_iter, _, _ = await self.client.list_groups(q=name)
            groups = await aiter_or_list(groups_iter)
            for g in groups:
                if getattr(getattr(g, "profile", None), "name", None) == name:
                    return g
            return None

        existing = await with_retries(
            _search, logger=self.logger, what=f"find group {name}"
        )
        if existing:
            self.logger.info("Group exists: %s (%s)", name, existing.id)
            return GroupInfo(id=existing.id, name=name)

        async def _create():
            group_profile = models.GroupProfile()
            group_profile.name = name
            group_profile.description = description
            group = models.Group()
            group.profile = group_profile
            created, _, err = await self.client.create_group(group)
            if err:
                raise RuntimeError(err)
            return created

        created = await with_retries(
            _create, logger=self.logger, what=f"create group {name}"
        )
        self.logger.info("Group created: %s (%s)", name, created.id)
        return GroupInfo(id=created.id, name=name)

    async def delete_group(self, group_id: str) -> None:
        async def _del():
            _, _, err = await self.client.delete_group(group_id)
            if err:
                raise RuntimeError(err)

        await with_retries(_del, logger=self.logger, what=f"delete group {group_id}")
        self.logger.info("Group deleted: %s", group_id)

    # ---- Users ----
    async def ensure_user_with_password(
        self,
        first: str,
        last: str,
        email: str,
        login: str,
        password: str,
        activate: bool = True,
    ) -> UserInfo:
        async def _find():
            # Search by login
            users_iter, _, _ = await self.client.list_users(q=login)
            users = await aiter_or_list(users_iter)
            for u in users:
                if getattr(u.profile, "login", None) == login:
                    return u
            return None

        existing = await with_retries(
            _find, logger=self.logger, what=f"find user {login}"
        )
        if existing:
            self.logger.info(
                "User exists: %s (%s) status=%s", login, existing.id, existing.status
            )
            return UserInfo(id=existing.id, login=login, status=existing.status)

        async def _create():
            profile = models.UserProfile(
                firstName=first,
                lastName=last,
                email=email,
                login=login,
            )
            credentials = models.UserCredentials(
                password=models.PasswordCredential(value=password)
            )
            req = models.CreateUserRequest(profile=profile, credentials=credentials)
            user, _, err = await self.client.create_user(req, activate=activate)
            if err:
                raise RuntimeError(err)
            return user

        created = await with_retries(
            _create, logger=self.logger, what=f"create user {login}"
        )
        self.logger.info(
            "User created: %s (%s) status=%s", login, created.id, created.status
        )
        return UserInfo(id=created.id, login=login, status=created.status)

    async def delete_user(self, user_id: str) -> None:
        # Must deactivate before delete
        async def _deactivate():
            _, _, err = await self.client.deactivate_or_delete_user(user_id)
            if err:
                raise RuntimeError(err)

        async def _delete():
            _, _, err = await self.client.delete_user(user_id)
            if err:
                raise RuntimeError(err)

        # some orgs require explicit deactivate then delete; do both defensively
        try:
            await with_retries(
                _deactivate, logger=self.logger, what=f"deactivate user {user_id}"
            )
        except RetryError:
            # continue; user might already be deactivated
            pass
        await with_retries(_delete, logger=self.logger, what=f"delete user {user_id}")
        self.logger.info("User deleted: %s", user_id)

    async def add_user_to_group(self, user_id: str, group_id: str) -> None:
        async def _add():
            # Prefer SDK method if available; otherwise fall back to direct REST call
            meth = getattr(self.client, "add_user_to_group", None)
            if callable(meth):
                _, _, err = await meth(group_id, user_id)
                if err:
                    raise RuntimeError(err)
                return True
            # Fallback: PUT /api/v1/groups/{groupId}/users/{userId}
            import requests

            url = f"{self.org_url.rstrip('/')}/api/v1/groups/{group_id}/users/{user_id}"
            headers = {
                "Authorization": f"SSWS {self.api_token}",
                "Accept": "application/json",
            }

            def _do_put():
                return requests.put(url, headers=headers, timeout=15)

            resp = await asyncio.to_thread(_do_put)
            if resp.status_code in (200, 204, 409):
                # 409 may indicate already a member
                return True
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text}")

        try:
            await with_retries(
                _add, logger=self.logger, what=f"add user {user_id} to group {group_id}"
            )
            self.logger.info("Added user %s to group %s", user_id, group_id)
        except RetryError as e:
            # It might already be a member; try to confirm membership to avoid failing idempotency
            if await self.is_user_in_group(user_id, group_id):
                self.logger.info("User %s already in group %s", user_id, group_id)
            else:
                raise e

    async def assign_users_to_app(self, app_id: str, user_ids: list[str]) -> None:
        """Assign multiple users to an app via REST (idempotent)."""
        import requests

        headers = {
            "Authorization": f"SSWS {self.api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        url = f"{self.org_url.rstrip('/')}/api/v1/apps/{app_id}/users"

        def _do_post(uid: str):
            return requests.post(url, headers=headers, json={"id": uid}, timeout=15)

        for uid in user_ids:
            if not uid:
                continue
            try:
                resp = await asyncio.to_thread(_do_post, uid)
                if resp.status_code not in (200, 201, 204, 409):
                    self.logger.warning(
                        "Assign user %s to app %s failed: %s %s",
                        uid,
                        app_id,
                        resp.status_code,
                        resp.text,
                    )
            except Exception as e:  # noqa: BLE001
                self.logger.warning(
                    "Assign user %s to app %s failed: %s", uid, app_id, e
                )

    async def assign_group_to_app(self, app_id: str, group_id: str) -> None:
        """Assign a group to an app via REST."""
        import requests

        url = f"{self.org_url.rstrip('/')}/api/v1/apps/{app_id}/groups/{group_id}"
        headers = {
            "Authorization": f"SSWS {self.api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        def _do_put():
            return requests.put(url, headers=headers, timeout=15)

        try:
            resp = await asyncio.to_thread(_do_put)
            if resp.status_code in (200, 201, 204, 409):
                self.logger.info("Assigned group %s to app %s", group_id, app_id)
            else:
                self.logger.warning(
                    "Assign group %s to app %s failed: %s %s",
                    group_id,
                    app_id,
                    resp.status_code,
                    resp.text,
                )
        except Exception as e:  # noqa: BLE001
            self.logger.warning(
                "Assign group %s to app %s failed: %s", group_id, app_id, e
            )

    async def configure_groups_claim_filter(self, app_id: str) -> None:
        """Ensure groups claim exists (prefers app claims, falls back to default auth server)."""
        import requests

        claim_payload = {
            "name": "groups",
            "claimType": "RESOURCE",
            "valueType": "GROUPS",
            "value": "groups",
            "group_filter_type": "STARTS_WITH",
            "conditions": {"include": [{"type": "STARTS_WITH", "value": "tacacs"}]},
            "alwaysIncludeInToken": True,
        }
        headers = {
            "Authorization": f"SSWS {self.api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        base = self.org_url.rstrip("/")

        async def _configure_app_claim(
            path: str,
        ) -> tuple[bool, int | None, str | None]:
            """Try to configure claim via a given app claim endpoint path."""

            def _list_claims():
                return requests.get(
                    f"{base}{path}",
                    headers=headers,
                    timeout=15,
                )

            def _create_claim():
                return requests.post(
                    f"{base}{path}",
                    headers=headers,
                    json=claim_payload,
                    timeout=15,
                )

            lst = await asyncio.to_thread(_list_claims)
            status = lst.status_code
            if status == 200:
                claims = lst.json() or []
                if any(
                    isinstance(c, dict) and str(c.get("name")).lower() == "groups"
                    for c in claims
                ):
                    self.logger.info("Groups claim already present on app %s", app_id)
                    return True, status, None
            created = await asyncio.to_thread(_create_claim)
            status = created.status_code
            if status in (200, 201):
                self.logger.info("Configured groups claim for app %s", app_id)
                return True, status, None
            # 404/405/401/403 are common when the endpoint isn't supported or not allowed; try next.
            if status not in (200, 201, 204, 404, 405, 401, 403):
                self.logger.warning(
                    "App-claim creation failed for app %s via %s (status=%s): %s",
                    app_id,
                    path,
                    status,
                    created.text,
                )
            return False, status, created.text

        # Try both claim endpoints (newer orgs use /federated-claims)
        app_claim_paths = [
            f"/api/v1/apps/{app_id}/federated-claims",
            f"/api/v1/apps/{app_id}/claims",
        ]
        for path in app_claim_paths:
            try:
                self.logger.debug("Attempting groups claim via %s", path)
                ok, status, body = await _configure_app_claim(path)
                if ok:
                    return
                if status not in (404, 405, 401, 403):
                    # only warn for unexpected failures; common statuses are silent
                    self.logger.warning(
                        "Groups claim via %s not available (status=%s): %s",
                        path,
                        status,
                        body,
                    )
            except Exception:
                # Swallow and try the next path/fallback
                continue

        # Fallback for cases where /apps/{id}/claims is not supported: use default auth server
        def _list_as_claims():
            return requests.get(
                f"{base}/api/v1/authorizationServers/default/claims",
                headers=headers,
                timeout=15,
            )

        def _create_as_claim():
            payload = {
                "name": "groups",
                "claimType": "IDENTITY",
                "valueType": "GROUPS",
                "value": "groups",
                "group_filter_type": "STARTS_WITH",
                "conditions": {
                    "scopes": ["openid", "profile", "email", "groups"],
                    "groups": {
                        "filterType": "STARTS_WITH",
                        "filterValue": "tacacs",
                    },
                },
                "status": "ACTIVE",
                "alwaysIncludeInToken": True,
            }
            return requests.post(
                f"{base}/api/v1/authorizationServers/default/claims",
                headers=headers,
                json=payload,
                timeout=15,
            )

        try:
            lst2 = await asyncio.to_thread(_list_as_claims)
            if lst2.status_code == 200:
                claims = lst2.json() or []
                if any(
                    isinstance(c, dict) and str(c.get("name")).lower() == "groups"
                    for c in claims
                ):
                    self.logger.info(
                        "Groups claim already present on default auth server"
                    )
                    return
            created2 = await asyncio.to_thread(_create_as_claim)
            if created2.status_code in (200, 201):
                self.logger.info(
                    "Configured groups claim on default auth server for app %s", app_id
                )
            else:
                self.logger.warning(
                    "Failed to configure groups claim via auth server for app %s: %s %s",
                    app_id,
                    created2.status_code,
                    created2.text,
                )
        except Exception as e:  # noqa: BLE001
            self.logger.warning(
                "Configure groups claim (fallback) for app %s failed: %s", app_id, e
            )

    async def is_user_in_group(self, user_id: str, group_id: str) -> bool:
        async def _list():
            meth = getattr(self.client, "list_user_groups", None)
            if callable(meth):
                groups_iter, _, _ = await meth(user_id)
                return await aiter_or_list(groups_iter)
            # Fallback REST: GET /api/v1/users/{userId}/groups
            import requests

            url = f"{self.org_url.rstrip('/')}/api/v1/users/{user_id}/groups"
            headers = {
                "Authorization": f"SSWS {self.api_token}",
                "Accept": "application/json",
            }

            def _do_get():
                return requests.get(url, headers=headers, timeout=15)

            resp = await asyncio.to_thread(_do_get)
            if resp.status_code != 200:
                raise RuntimeError(f"HTTP {resp.status_code}: {resp.text}")
            return resp.json() or []

        groups = await with_retries(
            _list, logger=self.logger, what=f"list groups for user {user_id}"
        )
        # Support SDK objects and REST JSON dicts
        for g in groups:
            gid = getattr(g, "id", None)
            if gid is None and isinstance(g, dict):
                gid = g.get("id")
            if gid == group_id:
                return True
        return False

    # ---- Applications (OIDC Web) ----
    async def ensure_oidc_web_app(
        self,
        label: str,
        redirect_uris: list[str],
        client_uri: str | None = None,
        grant_types: list[str] | None = None,
        response_types: list[str] | None = None,
        auth_method: str = "client_secret",
        public_jwk: dict[str, Any] | None = None,
    ) -> AppInfo:
        import requests

        grant_types = grant_types or ["authorization_code"]
        response_types = response_types or ["code"]
        # Determine token_endpoint_auth_method based on auth_method parameter
        token_auth_method = (
            "private_key_jwt"
            if auth_method == "private_key_jwt"
            else "client_secret_post"
        )

        async def _search():
            apps_iter, _, _ = await self.client.list_applications(q=label)
            apps = await aiter_or_list(apps_iter)
            for a in apps:
                if getattr(a, "label", None) == label:
                    return a
            return None

        existing = await with_retries(
            _search, logger=self.logger, what=f"find app {label}"
        )
        if existing:
            client_id = None
            client_secret = None
            creds = getattr(existing, "credentials", None)
            if creds and getattr(creds, "oauthClient", None):
                client_id = getattr(creds.oauthClient, "client_id", None)
                client_secret = getattr(creds.oauthClient, "client_secret", None)
            # For client_secret auth, attempt to ensure a secret exists
            if auth_method == "client_secret":
                if not client_secret:
                    cid, csec = await self.fetch_app_credentials(existing.id)
                    client_id = client_id or cid
                    client_secret = client_secret or csec
                if not client_secret:
                    client_secret = await self.generate_app_client_secret(existing.id)
                if not client_secret:
                    client_secret = await self.rotate_client_secret(existing.id)
            # For private_key_jwt, ensure jwks and auth method are set via REST
            if auth_method == "private_key_jwt" and public_jwk:
                base = self.org_url.rstrip("/")
                headers = {
                    "Authorization": f"SSWS {self.api_token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                }
                try:
                    # Upload/ensure the key
                    requests.post(
                        f"{base}/api/v1/apps/{existing.id}/credentials/keys",
                        headers=headers,
                        json={"keys": [public_jwk]},
                        timeout=15,
                    )
                    # Patch token_endpoint_auth_method + jwks
                    requests.post(
                        f"{base}/api/v1/apps/{existing.id}",
                        headers=headers,
                        json={
                            "settings": {
                                "oauthClient": {
                                    "token_endpoint_auth_method": "private_key_jwt",
                                    "jwks": {"keys": [public_jwk]},
                                }
                            }
                        },
                        timeout=15,
                    )
                except Exception:
                    self.logger.debug(
                        "Failed to patch existing web app for private_key_jwt"
                    )
            self.logger.info("App exists: %s (%s)", label, existing.id)
            return AppInfo(
                id=existing.id,
                clientId=client_id,
                clientSecret=client_secret,
                authMethod=auth_method,
                appType="web",
            )

        async def _create():
            # The SDK classes differ by version; prefer OpenIdConnectApplicationSettingsClient.
            client_cls = getattr(models, "OpenIdConnectApplicationSettingsClient", None)
            settings_cls = getattr(models, "OpenIdConnectApplicationSettings", None)
            oauth_client_settings = {
                "client_uri": client_uri,
                "redirect_uris": redirect_uris,
                "response_types": response_types,
                "grant_types": grant_types,
                "application_type": "web",
                "token_endpoint_auth_method": token_auth_method,
            }
            if auth_method == "private_key_jwt" and public_jwk:
                oauth_client_settings["jwks"] = {"keys": [public_jwk]}

            if client_cls and settings_cls:
                oauth_client = client_cls(**oauth_client_settings)
                settings = settings_cls(oauthClient=oauth_client)
            else:
                # Fallback: construct via generic dicts if SDK classes are missing
                settings = {"oauthClient": oauth_client_settings}
            app_obj = models.OpenIdConnectApplication(
                label=label, signOnMode="OPENID_CONNECT", settings=settings
            )
            created, _, err = await self.client.create_application(app_obj)
            if err:
                raise RuntimeError(err)
            return created

        created = await with_retries(
            _create, logger=self.logger, what=f"create app {label}"
        )
        client_id = None
        client_secret = None
        creds = getattr(created, "credentials", None)
        if creds and getattr(creds, "oauthClient", None):
            client_id = getattr(creds.oauthClient, "client_id", None)
            client_secret = getattr(creds.oauthClient, "client_secret", None)
        if not client_secret:
            cid, csec = await self.fetch_app_credentials(created.id)
            client_id = client_id or cid
            client_secret = client_secret or csec
        if not client_secret:
            client_secret = await self.generate_app_client_secret(created.id)
        if not client_secret:
            client_secret = await self.rotate_client_secret(created.id)
        self.logger.info("App created: %s (%s)", label, created.id)
        return AppInfo(
            id=created.id,
            clientId=client_id,
            clientSecret=client_secret,
            authMethod=auth_method,
            appType="web",
        )

    async def delete_app(self, app_id: str) -> None:
        # deactivate + delete to be safe
        async def _deactivate():
            _, _, err = await self.client.deactivate_application(app_id)
            if err:
                raise RuntimeError(err)

        async def _delete():
            _, _, err = await self.client.delete_application(app_id)
            if err:
                raise RuntimeError(err)

        try:
            await with_retries(
                _deactivate, logger=self.logger, what=f"deactivate app {app_id}"
            )
        except RetryError:
            pass
        await with_retries(_delete, logger=self.logger, what=f"delete app {app_id}")
        self.logger.info("App deleted: %s", app_id)

    # ---- Service App (OAuth 2.0 client_credentials) ----
    async def ensure_service_app(
        self,
        label: str,
        auth_method: str = "client_secret",
        public_jwk: dict[str, Any] | None = None,
    ) -> AppInfo:
        """Create or return an OAuth 2.0 Service App for Okta API access.

        - auth_method: "client_secret" or "private_key_jwt"
        - public_jwk: required when auth_method==private_key_jwt
        """

        import requests

        # First try to find existing app by label
        async def _search():
            try:
                apps_iter, _, _ = await self.client.list_applications(q=label)
                apps = await aiter_or_list(apps_iter)
            except Exception:
                apps = []
            for a in apps:
                if getattr(a, "label", None) == label:
                    client_id = None
                    client_secret = None
                    creds = getattr(a, "credentials", None)
                    if creds and getattr(creds, "oauthClient", None):
                        client_id = getattr(creds.oauthClient, "client_id", None)
                        client_secret = getattr(
                            creds.oauthClient, "client_secret", None
                        )
                    return AppInfo(
                        id=a.id,
                        clientId=client_id,
                        clientSecret=client_secret,
                        authMethod=auth_method,
                        appType="service",
                    )
            return None

        existing = await with_retries(
            _search, logger=self.logger, what=f"find service app {label}"
        )
        if existing:
            self.logger.info("Service app exists: %s (%s)", label, existing.id)
            # Update JWK if using private_key_jwt and a new public_jwk is provided
            if auth_method == "private_key_jwt" and public_jwk:
                import requests
                # First, get the current app to preserve required fields
                get_url = f"{self.org_url.rstrip('/')}/api/v1/apps/{existing.id}"
                headers = {
                    "Authorization": f"SSWS {self.api_token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                }
                def _do_get():
                    return requests.get(get_url, headers=headers, timeout=20)
                get_resp = await asyncio.to_thread(_do_get)
                if get_resp.status_code == 200:
                    current_app = get_resp.json()
                    # Update only the JWK in settings.oauthClient
                    if "settings" not in current_app:
                        current_app["settings"] = {}
                    if "oauthClient" not in current_app["settings"]:
                        current_app["settings"]["oauthClient"] = {}
                    current_app["settings"]["oauthClient"]["jwks"] = {"keys": [public_jwk]}
                    
                    def _do_update():
                        return requests.put(get_url, headers=headers, json=current_app, timeout=20)
                    resp = await asyncio.to_thread(_do_update)
                    if resp.status_code in (200, 201):
                        self.logger.info("Updated JWK for service app %s (kid=%s)", label, public_jwk.get("kid"))
                    else:
                        self.logger.warning("Failed to update JWK for service app %s: HTTP %s %s", label, resp.status_code, resp.text)
                else:
                    self.logger.warning("Failed to get current app config for %s: HTTP %s", label, get_resp.status_code)
            return existing

        # Build REST payload for service app creation
        token_auth_method = (
            "client_secret_post"
            if auth_method == "client_secret"
            else "private_key_jwt"
        )
        payload: dict[str, Any] = {
            "name": "oidc_client",
            "label": label,
            "signOnMode": "OPENID_CONNECT",
            "credentials": {
                "oauthClient": {
                    "token_endpoint_auth_method": token_auth_method,
                }
            },
            "settings": {
                "oauthClient": {
                    "application_type": "service",
                    "grant_types": ["client_credentials"],
                    "response_types": ["token"],
                }
            },
        }
        if auth_method == "private_key_jwt":
            if not public_jwk:
                raise ValueError(
                    "public_jwk is required for private_key_jwt service app"
                )
            # JWKs are provided under settings.oauthClient
            payload["settings"]["oauthClient"]["jwks"] = {"keys": [public_jwk]}

        url = f"{self.org_url.rstrip('/')}/api/v1/apps"
        headers = {
            "Authorization": f"SSWS {self.api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        def _do_post():
            return requests.post(url, headers=headers, json=payload, timeout=20)

        resp = await asyncio.to_thread(_do_post)
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"Create service app failed: HTTP {resp.status_code} {resp.text}"
            )
        data = resp.json()
        app_id = data.get("id")
        creds = data.get("credentials", {}).get("oauthClient", {})
        client_id = creds.get("client_id")
        client_secret = creds.get("client_secret")
        self.logger.info("Service app created: %s (%s)", label, app_id)
        return AppInfo(
            id=str(app_id),
            clientId=client_id,
            clientSecret=client_secret,
            authMethod=auth_method,
            appType="service",
        )

    async def grant_okta_api_scopes(self, app_id: str, scopes: list[str]) -> None:
        """Grant Okta API scopes to an app via app grants API."""
        import requests

        url_base = f"{self.org_url.rstrip('/')}/api/v1/apps/{app_id}/grants"
        headers = {
            "Authorization": f"SSWS {self.api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        async def _grant(scope_id: str) -> None:
            def _do_post():
                payload = {"scopeId": scope_id, "issuer": self.org_url.rstrip("/")}
                return requests.post(
                    url_base, headers=headers, json=payload, timeout=15
                )

            resp = await asyncio.to_thread(_do_post)
            if resp.status_code in (200, 201, 204, 409):
                return
            # Handle idempotent case where Okta returns 400 but indicates already granted
            try:
                data = resp.json() or {}
                summary = (data.get("errorSummary") or "").lower()
                causes = data.get("errorCauses") or []
                already = "already been granted" in summary or any(
                    "already been granted" in str(c.get("errorSummary", "")).lower()
                    for c in causes
                )
                if already:
                    return
            except Exception:
                pass
            raise RuntimeError(
                f"Grant {scope_id} failed: HTTP {resp.status_code} {resp.text}"
            )

        for s in scopes:
            await with_retries(
                lambda s=s: _grant(s), logger=self.logger, what=f"grant scope {s}"
            )

    # ---- Key generation (RSA) for private_key_jwt ----
    @staticmethod
    def generate_rsa_keypair_and_jwk(
        kid: str | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """Generate RSA private key (PEM) and corresponding public JWK.

        Returns (private_key_pem, public_jwk_dict)
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_numbers = key.public_key().public_numbers()
        n_int = public_numbers.n
        e_int = public_numbers.e

        def _b64u(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

        def _int_to_b64u(i: int) -> str:
            # convert int to big-endian bytes without leading zeros
            length = (i.bit_length() + 7) // 8
            return _b64u(i.to_bytes(length, byteorder="big"))

        jwk = {
            "kty": "RSA",
            "n": _int_to_b64u(n_int),
            "e": _int_to_b64u(e_int),
            "alg": "RS256",
            "use": "sig",
        }
        jwk["kid"] = kid or _secrets.token_hex(8)
        return priv_pem, jwk

    async def fetch_app_credentials(self, app_id: str) -> tuple[str | None, str | None]:
        """Fetch client_id and client_secret for an application via REST."""
        import requests

        url = f"{self.org_url.rstrip('/')}/api/v1/apps/{app_id}"
        headers = {
            "Authorization": f"SSWS {self.api_token}",
            "Accept": "application/json",
        }

        def _do_get():
            return requests.get(url, headers=headers, timeout=15)

        resp = await asyncio.to_thread(_do_get)
        if resp.status_code != 200:
            return None, None
        data = resp.json() or {}
        creds = (data.get("credentials") or {}).get("oauthClient", {})
        return creds.get("client_id"), creds.get("client_secret")

    async def rotate_client_secret(self, app_id: str) -> str | None:
        """Rotate/generate client secret for confidential apps via REST."""
        import requests

        url = f"{self.org_url.rstrip('/')}/oauth2/v1/clients/{app_id}/lifecycle/rotateSecret"
        headers = {
            "Authorization": f"SSWS {self.api_token}",
            "Accept": "application/json",
        }

        def _do_post():
            return requests.post(url, headers=headers, timeout=15)

        resp = await asyncio.to_thread(_do_post)
        if resp.status_code not in (200, 201):
            return None
        data = resp.json() or {}
        creds = (
            data.get("client") or data
        )  # rotateSecret returns {client:{client_id,client_secret}}
        return (
            (creds.get("client_secret") or creds.get("secret"))
            if isinstance(creds, dict)
            else None
        )

    async def generate_app_client_secret(self, app_id: str) -> str | None:
        """Rotate/generate a new client secret for an app and return it."""
        import requests

        url = f"{self.org_url.rstrip('/')}/api/v1/apps/{app_id}/lifecycle/newSecret"
        headers = {
            "Authorization": f"SSWS {self.api_token}",
            "Accept": "application/json",
        }

        def _do_post():
            return requests.post(url, headers=headers, timeout=15)

        resp = await asyncio.to_thread(_do_post)
        if resp.status_code not in (200, 201):
            return None
        data = resp.json() or {}
        creds = (data.get("credentials") or {}).get("oauthClient", {})
        return creds.get("client_secret")


# ---------- CLI ----------
def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Prepare/teardown Okta dev org test artifacts."
    )
    p.add_argument(
        "--org-url",
        default=os.getenv("OKTA_ORG_URL"),
        required=False,
        help="Okta org URL",
    )
    p.add_argument(
        "--api-token",
        default=os.getenv("OKTA_API_TOKEN"),
        required=False,
        help="Okta API token",
    )
    p.add_argument(
        "--output",
        default=os.getenv("OKTA_TEST_OUTPUT", "okta_test_data.json"),
        help="Manifest path",
    )
    p.add_argument(
        "--verbosity",
        "-v",
        action="count",
        default=0,
        help="Increase log verbosity (-v, -vv)",
    )

    # Resource names / data
    p.add_argument("--group-ops", default="tacacs-ops", help="Operators group name")
    p.add_argument("--group-admin", default="tacacs-admin", help="Admins group name")
    p.add_argument(
        "--group-web-admin",
        default="tacacs-web-admin",
        help="Web admin OpenID group name",
    )

    p.add_argument(
        "--op-login",
        default="test.operator.okta@example.com",
        help="Operator user login/email",
    )
    p.add_argument(
        "--op-password", default="Op3rator!Passw0rd", help="Operator password"
    )

    p.add_argument(
        "--ad-login",
        default="test.admin.okta@example.com",
        help="Admin user login/email",
    )
    p.add_argument("--ad-password", default="Adm1n!Passw0rd", help="Admin password")

    p.add_argument(
        "--user-activate",
        type=lambda x: x.lower() != "false",
        default=True,
        help="Create users in ACTIVE state (default true)",
    )

    p.add_argument("--app-label", default="tacacs-test-app", help="OIDC app label")
    p.add_argument(
        "--redirect-uri",
        action="append",
        default=["https://example.local/callback"],
        help="OIDC redirect URI for TACACS backend (can repeat)",
    )
    p.add_argument(
        "--admin-redirect-uri",
        action="append",
        default=["https://example.local/admin/login/openid-callback"],
        help="OIDC redirect URI for web admin OpenID (can repeat)",
    )
    p.add_argument(
        "--client-uri", default="https://example.local", help="OIDC client URI"
    )
    p.add_argument(
        "--app-auth-method",
        choices=["client_secret", "private_key_jwt"],
        default="client_secret",
        help="OIDC web app token endpoint auth method",
    )
    p.add_argument(
        "--app-public-jwk-file",
        default=None,
        help="Path to public JWK (JSON) for web app when using private_key_jwt",
    )
    p.add_argument(
        "--app-private-key-out",
        default="okta_app_private_key.pem",
        help="Where to write generated private key PEM for web app (private_key_jwt)",
    )
    p.add_argument(
        "--app-public-jwk-out",
        default="okta_app_public_jwk.json",
        help="Where to write generated public JWK JSON for web app (private_key_jwt)",
    )
    p.add_argument("--no-app", action="store_true", help="Skip creating OIDC web app")
    p.add_argument(
        "--verify-perms",
        action="store_true",
        help="Verify token can list groups (okta.groups.read) and log result",
    )
    # Service app (OAuth for Okta APIs)
    p.add_argument(
        "--create-service-app",
        action="store_true",
        help="Create OAuth 2.0 service app for Okta API access",
    )
    p.add_argument(
        "--service-app-label", default="tacacs-service-app", help="Service app label"
    )
    p.add_argument(
        "--service-auth-method",
        choices=["client_secret", "private_key_jwt"],
        default="client_secret",
        help="Service app token endpoint auth method",
    )
    p.add_argument(
        "--service-public-jwk-file",
        default=None,
        help="Path to public JWK (JSON) when using private_key_jwt",
    )
    p.add_argument(
        "--service-private-key-out",
        default="okta_service_private_key.pem",
        help="Where to write generated private key PEM (private_key_jwt)",
    )
    p.add_argument(
        "--service-public-jwk-out",
        default="okta_service_public_jwk.json",
        help="Where to write generated public JWK JSON (private_key_jwt)",
    )
    p.add_argument(
        "--service-scopes",
        default="okta.users.read,okta.groups.read",
        help="Comma-separated Okta API scopes to grant",
    )
    # Backend config writer
    p.add_argument(
        "--write-backend-config",
        default=None,
        help="Write an [okta] backend config file using created resources",
    )

    p.add_argument(
        "--teardown",
        action="store_true",
        help="Delete resources from manifest and exit",
    )

    args = p.parse_args(argv)
    if not args.org_url or not args.api_token:
        p.error(
            "Missing --org-url and/or --api-token (or set OKTA_ORG_URL/OKTA_API_TOKEN)."
        )
    return args


async def do_prepare(args: argparse.Namespace, logger: logging.Logger) -> int:
    okta = OktaPreparer(args.org_url, args.api_token, logger)

    # Optionally verify token permissions for group reads (used by backend when require_group_for_auth=true)
    if args.verify_perms:
        await okta.verify_management_api_perms()

    # Ensure groups
    g_ops = await okta.ensure_group(args.group_ops, "Operators for TACACS tests")
    g_admin = await okta.ensure_group(args.group_admin, "Admins for TACACS tests")
    g_web_admin = await okta.ensure_group(
        args.group_web_admin, "Web Admin OpenID group"
    )

    # Ensure users
    u_op = await okta.ensure_user_with_password(
        first="Test",
        last="Operator",
        email=args.op_login,
        login=args.op_login,
        password=args.op_password,
        activate=args.user_activate,
    )
    u_ad = await okta.ensure_user_with_password(
        first="Test",
        last="Admin",
        email=args.ad_login,
        login=args.ad_login,
        password=args.ad_password,
        activate=args.user_activate,
    )

    # Assign groups
    await okta.add_user_to_group(u_op.id, g_ops.id)
    await okta.add_user_to_group(u_ad.id, g_admin.id)
    await okta.add_user_to_group(u_ad.id, g_web_admin.id)

    # Ensure OIDC app unless disabled (not required by AuthN-only backend flow)
    app = None
    if not args.no_app:
        all_redirects = list(
            dict.fromkeys((args.redirect_uri or []) + (args.admin_redirect_uri or []))
        )
        app_public_jwk = None
        app_generated_kid = None
        app_generated_priv_path = None
        if args.app_auth_method == "private_key_jwt":
            if args.app_public_jwk_file:
                try:
                    with open(args.app_public_jwk_file, encoding="utf-8") as f:
                        app_public_jwk = json.load(f)
                except Exception as e:  # noqa: BLE001
                    raise SystemExit(f"Failed to read app public JWK: {e}")
            else:
                # Generate new RSA keypair and JWK
                priv_pem, app_public_jwk = OktaPreparer.generate_rsa_keypair_and_jwk()
                app_generated_kid = app_public_jwk.get("kid")
                # Save private key and public JWK
                try:
                    with open(args.app_private_key_out, "w", encoding="utf-8") as f:
                        f.write(priv_pem)
                    with open(args.app_public_jwk_out, "w", encoding="utf-8") as f:
                        json.dump(app_public_jwk, f, indent=2)
                    app_generated_priv_path = args.app_private_key_out
                    logger.info(
                        "Generated RSA keypair for web app (kid=%s)", app_generated_kid
                    )
                except Exception as e:  # noqa: BLE001
                    raise SystemExit(f"Failed to write generated app keys: {e}")
        app = await okta.ensure_oidc_web_app(
            label=args.app_label,
            redirect_uris=all_redirects,
            client_uri=args.client_uri,
            auth_method=args.app_auth_method,
            public_jwk=app_public_jwk,
        )
        # Attach key metadata if generated
        if app and app_generated_kid:
            app.privateKeyId = app_generated_kid
        if app and app_generated_priv_path:
            app.privateKeyPath = app_generated_priv_path
        if app and app.id:
            # Assign app to web_admin group
            await okta.assign_group_to_app(app.id, g_web_admin.id)
            # Configure Groups claim filter in OpenID Connect ID Token
            await okta.configure_groups_claim_filter(app.id)
            # Assign users to app
            await okta.assign_users_to_app(
                app.id,
                [u_ad.id if u_ad else None, u_op.id if u_op else None],
            )

    # Optionally create service app for Okta API scopes (OAuth 2.0 client_credentials)
    svc_app = None
    if args.create_service_app:
        public_jwk = None
        generated_kid = None
        generated_priv_path = None
        if args.service_auth_method == "private_key_jwt":
            if args.service_public_jwk_file:
                try:
                    with open(args.service_public_jwk_file, encoding="utf-8") as f:
                        public_jwk = json.load(f)
                except Exception as e:  # noqa: BLE001
                    raise SystemExit(f"Failed to read public JWK: {e}")
            else:
                # Generate new RSA keypair and JWK
                priv_pem, public_jwk = OktaPreparer.generate_rsa_keypair_and_jwk()
                generated_kid = public_jwk.get("kid")
                # Save private key and public JWK
                try:
                    with open(args.service_private_key_out, "w", encoding="utf-8") as f:
                        f.write(priv_pem)
                    with open(args.service_public_jwk_out, "w", encoding="utf-8") as f:
                        json.dump(public_jwk, f, indent=2)
                    generated_priv_path = args.service_private_key_out
                    logger.info(
                        "Generated RSA keypair for service app (kid=%s)", generated_kid
                    )
                except Exception as e:  # noqa: BLE001
                    raise SystemExit(f"Failed to write generated keys: {e}")
        svc_app = await okta.ensure_service_app(
            label=args.service_app_label,
            auth_method=args.service_auth_method,
            public_jwk=public_jwk,
        )
        scopes = [s.strip() for s in args.service_scopes.split(",") if s.strip()]
        await okta.grant_okta_api_scopes(svc_app.id, scopes)
        # Attach key metadata if generated
        if generated_kid:
            svc_app.privateKeyId = generated_kid
        if generated_priv_path:
            svc_app.privateKeyPath = generated_priv_path

    # If client_id was not populated by creation/search, fetch explicitly
    if svc_app and not svc_app.clientId:
        try:
            cid, csec = await okta.fetch_app_credentials(svc_app.id)
            if cid:
                svc_app.clientId = cid
            if csec and not svc_app.clientSecret:
                svc_app.clientSecret = csec
        except Exception as e:  # noqa: BLE001
            logger.warning("Could not fetch service app credentials: %s", e)

    # Ensure app client_secret is populated in manifest
    if app and not app.clientSecret:
        try:
            cid, csec = await okta.fetch_app_credentials(app.id)
            if cid:
                app.clientId = cid
            if csec:
                app.clientSecret = csec
        except Exception as e:  # noqa: BLE001
            logger.warning("Could not fetch app credentials: %s", e)

    manifest = Manifest(
        groups={"ops": g_ops, "admin": g_admin, "web_admin": g_web_admin},
        users={"operator": u_op, "admin": u_ad},
        app=app,
        service_app=svc_app,
    )
    manifest.write(args.output)
    logger.info("Wrote manifest: %s", args.output)
    # Optionally write backend config file
    if args.write_backend_config:
        cfg_lines: list[str] = []
        cfg_lines.append("[okta]")
        cfg_lines.append(f"org_url = {args.org_url}")
        cfg_lines.append("verify_tls = true")
        if svc_app and svc_app.authMethod == "private_key_jwt":
            cfg_lines.append("auth_method = private_key_jwt")
            if svc_app.clientId:
                cfg_lines.append(f"client_id = {svc_app.clientId}")
            if svc_app.privateKeyPath:
                cfg_lines.append(f"private_key = {svc_app.privateKeyPath}")
            if svc_app.privateKeyId:
                cfg_lines.append(f"private_key_id = {svc_app.privateKeyId}")
        elif svc_app and svc_app.authMethod == "client_secret":
            cfg_lines.append("auth_method = client_secret")
            if svc_app.clientId:
                cfg_lines.append(f"client_id = {svc_app.clientId}")
            if svc_app.clientSecret:
                cfg_lines.append(f"client_secret = {svc_app.clientSecret}")
        else:
            # Fallback SSWS (legacy) template if no service app was created
            cfg_lines.append("# auth_method = ssws")
            cfg_lines.append("# api_token = ${OKTA_API_TOKEN}")
        cfg_content = "\n".join(cfg_lines) + "\n"
        try:
            out_path = args.write_backend_config
            os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(cfg_content)
            logger.info("Wrote backend config: %s", out_path)
        except Exception as e:  # noqa: BLE001
            logger.error("Failed to write backend config: %s", e)
    # Provide config hints matching backend expectations
    if svc_app and svc_app.authMethod == "private_key_jwt":
        logger.info(
            "Okta backend config (private_key_jwt):\n"
            "[okta]\n"
            "org_url = %s\n"
            "auth_method = private_key_jwt\n"
            "client_id = %s\n"
            "private_key = %s\n"
            "private_key_id = %s\n"
            "# token_endpoint defaults to %s/oauth2/v1/token\n"
            "# require_group_for_auth = true   # optional\n",
            args.org_url,
            svc_app.clientId,
            svc_app.privateKeyPath or "<path-to-private-key.pem>",
            svc_app.privateKeyId or "<kid>",
            args.org_url.rstrip("/"),
        )
    elif svc_app and svc_app.authMethod == "client_secret":
        logger.info(
            "Okta backend config (client_secret):\n"
            "[okta]\n"
            "org_url = %s\n"
            "auth_method = client_secret\n"
            "client_id = %s\n"
            "client_secret = %s\n"
            "# token_endpoint defaults to %s/oauth2/v1/token\n"
            "# require_group_for_auth = true   # optional\n",
            args.org_url,
            svc_app.clientId,
            (svc_app.clientSecret or "<client-secret>"),
            args.org_url.rstrip("/"),
        )
    else:
        logger.info(
            "Okta backend (SSWS or AuthN only):\n"
            "[okta]\n"
            "org_url = %s\n"
            "# api_token = <SSWS token>   # if using SSWS for groups\n"
            "# require_group_for_auth = false\n",
            args.org_url,
        )
    return 0


async def do_teardown(args: argparse.Namespace, logger: logging.Logger) -> int:
    if not os.path.exists(args.output):
        logger.error("Manifest not found: %s", args.output)
        return 2

    manifest = Manifest.from_file(args.output)
    okta = OktaPreparer(args.org_url, args.api_token, logger)

    # Delete app(s) first (less dependencies)
    if manifest.app and manifest.app.id:
        try:
            await okta.delete_app(manifest.app.id)
        except Exception as e:  # noqa: BLE001
            logger.warning("Delete app failed: %s", e)
    if manifest.service_app and manifest.service_app.id:
        try:
            await okta.delete_app(manifest.service_app.id)
        except Exception as e:  # noqa: BLE001
            logger.warning("Delete service app failed: %s", e)

    # Delete users
    for key, user in list(manifest.users.items()):
        try:
            await okta.delete_user(user.id)
        except Exception as e:  # noqa: BLE001
            logger.warning("Delete user %s failed: %s", key, e)

    # Delete groups
    for key, grp in list(manifest.groups.items()):
        try:
            await okta.delete_group(grp.id)
        except Exception as e:  # noqa: BLE001
            logger.warning("Delete group %s failed: %s", key, e)

    logger.info("Teardown complete.")
    return 0


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    setup_logger(args.verbosity)
    logger = logging.getLogger("okta-preparer")

    try:
        if args.teardown:
            return asyncio.run(do_teardown(args, logger))
        return asyncio.run(do_prepare(args, logger))
    except KeyboardInterrupt:
        logger.error("Interrupted.")
        return 130
    except RetryError as re:
        logger.exception(str(re))
        return 75
    except Exception as e:  # noqa: BLE001
        logger.exception("Fatal error: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
