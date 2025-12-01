from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from tacacs_server.utils.logger import get_logger
from tacacs_server.utils.policy import PolicyContext, PolicyResult, evaluate_policy

logger = get_logger("tacacs_server.radius.auth", component="radius")


@dataclass
class AuthServices:
    """Shared services needed for policy evaluation."""

    local_user_group_service: Any | None = None


def authenticate_user(
    backends: list[Any], username: str, password: str, **kwargs
) -> tuple[bool, str]:
    """Authenticate user against backends with diagnostic detail."""
    if not backends:
        return False, "no authentication backends configured"

    last_error: str | None = None
    for backend in backends:
        try:
            if backend.authenticate(username, password, **kwargs):
                logger.debug(
                    "RADIUS backend authentication succeeded",
                    event="radius.backend.auth_success",
                    backend=getattr(backend, "name", None),
                    username=username,
                )
                return True, f"backend={backend.name}"
        except Exception as e:
            message = f"backend={backend.name} error={e}"
            logger.error(
                "RADIUS backend authentication error",
                event="radius.backend.auth_error",
                backend=getattr(backend, "name", None),
                error=str(e),
            )
            last_error = message

    if last_error:
        return False, last_error

    return False, "no backend accepted credentials"


def get_user_attributes(backends: list[Any], username: str) -> dict[str, Any]:
    """Get user attributes from backends."""
    for backend in backends:
        try:
            attrs = backend.get_user_attributes(username)
            if attrs:
                if isinstance(attrs, Mapping):
                    return dict(attrs)
                logger.warning(
                    "Backend returned non-mapping user attributes; ignoring",
                    event="radius.backend.attributes_invalid",
                    backend=getattr(backend, "name", None),
                    attr_type=type(attrs).__name__,
                )
        except Exception as e:
            logger.error(
                "Error getting attributes from backend",
                event="radius.backend.attributes_error",
                backend=getattr(backend, "name", None),
                error=str(e),
            )
    return {}


def apply_policy(
    client: Any, user_attrs: dict[str, Any], services: AuthServices
) -> tuple[bool, str]:
    """Apply user-group policy and update privilege level."""
    context = PolicyContext(
        device_group_name=getattr(client, "group", None),
        allowed_user_groups=getattr(client, "allowed_user_groups", []),
        user_groups=user_attrs.get("groups", []) or [],
        fallback_privilege=user_attrs.get("privilege_level", 1),
    )

    def _lookup_privilege(group_name: str) -> int | None:
        if not services.local_user_group_service:
            return None
        record = services.local_user_group_service.get_group(group_name)
        return getattr(record, "privilege_level", None)

    result: PolicyResult = evaluate_policy(context, _lookup_privilege)
    user_attrs["privilege_level"] = result.privilege_level
    return result.allowed, result.denial_message


__all__ = ["AuthServices", "authenticate_user", "get_user_attributes", "apply_policy"]
