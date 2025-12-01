from dataclasses import dataclass
from typing import Any

from tacacs_server.utils.logger import get_logger

from ..auth.privilege_resolver import resolve_privilege_level
from .constants import (
    ATTR_CLASS,
    ATTR_IDLE_TIMEOUT,
    ATTR_REPLY_MESSAGE,
    ATTR_SERVICE_TYPE,
    ATTR_SESSION_TIMEOUT,
    RADIUS_ACCESS_ACCEPT,
    RADIUS_ACCESS_REJECT,
    SERVICE_TYPE_ADMINISTRATIVE,
)
from .packet import RADIUSPacket
from .vsa_builder import apply_vsa_from_metadata

logger = get_logger("tacacs_server.radius.response", component="radius")


@dataclass
class ResponseContext:
    """Context for building RADIUS responses."""

    local_user_group_service: Any | None = None


class ResponseBuilder:
    """Builder for RADIUS Access-Accept/Reject packets."""

    def __init__(self, context: ResponseContext):
        self.context = context

    def create_access_accept(
        self, request: RADIUSPacket, user_attrs: dict[str, Any]
    ) -> RADIUSPacket:
        response = RADIUSPacket(
            code=RADIUS_ACCESS_ACCEPT,
            identifier=request.identifier,
            authenticator=bytes(16),  # Will be calculated in pack()
        )

        response.add_string(ATTR_REPLY_MESSAGE, "Authentication successful")
        response.add_integer(ATTR_SERVICE_TYPE, SERVICE_TYPE_ADMINISTRATIVE)

        group_metadata: dict[str, Any] | None = None
        user_groups = user_attrs.get("groups", []) or []
        if user_groups and self.context.local_user_group_service:
            for group_name in user_groups:
                try:
                    group = self.context.local_user_group_service.get_group(group_name)
                    group_metadata = group.metadata
                    if apply_vsa_from_metadata(response, group_metadata):
                        logger.debug(
                            "Applied VSA from group metadata",
                            event="radius.vsa.applied",
                            group=group_name,
                        )
                        break
                except Exception as exc:
                    logger.debug(
                        "Failed to apply VSA from group",
                        event="radius.vsa.group_metadata_failed",
                        group=group_name,
                        error=str(exc),
                    )

        if "session_timeout" in user_attrs and not response.get_attribute(
            ATTR_SESSION_TIMEOUT
        ):
            response.add_integer(ATTR_SESSION_TIMEOUT, user_attrs["session_timeout"])

        if "idle_timeout" in user_attrs and not response.get_attribute(
            ATTR_IDLE_TIMEOUT
        ):
            response.add_integer(ATTR_IDLE_TIMEOUT, user_attrs["idle_timeout"])

        effective_privilege = resolve_privilege_level(user_attrs, group_metadata)
        user_attrs["privilege_level"] = effective_privilege

        if not response.get_cisco_avpairs():
            response.add_cisco_avpair(f"shell:priv-lvl={effective_privilege}")
            logger.debug(
                "Added fallback Cisco AVPair",
                event="radius.vsa.fallback",
                privilege=effective_privilege,
            )

        response.add_string(ATTR_CLASS, f"priv{effective_privilege}")

        return response

    @staticmethod
    def create_access_reject(
        request: RADIUSPacket, message: str = "Authentication failed"
    ) -> RADIUSPacket:
        response = RADIUSPacket(
            code=RADIUS_ACCESS_REJECT,
            identifier=request.identifier,
            authenticator=bytes(16),
        )
        response.add_string(ATTR_REPLY_MESSAGE, message)
        return response


def send_response(
    auth_socket,
    acct_socket,
    response: RADIUSPacket,
    addr: tuple[str, int],
    secret: bytes,
    request_auth: bytes,
):
    """Send a RADIUS response on the appropriate socket."""
    try:
        packet_data = response.pack(secret, request_auth)

        if response.code in (RADIUS_ACCESS_ACCEPT, RADIUS_ACCESS_REJECT):
            if auth_socket is not None:
                auth_socket.sendto(packet_data, addr)
        else:
            if acct_socket is not None:
                acct_socket.sendto(packet_data, addr)

    except Exception as e:
        logger.error(
            "Error sending RADIUS response",
            event="radius.response.send_error",
            address=str(addr),
            error=str(e),
        )


__all__ = ["ResponseContext", "ResponseBuilder", "send_response"]
