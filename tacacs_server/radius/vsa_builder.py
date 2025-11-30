"""VSA attribute builder from user group metadata."""

from typing import TYPE_CHECKING, Any

from tacacs_server.auth.metadata_schema import UserGroupMetadata
from tacacs_server.radius.constants import ATTR_IDLE_TIMEOUT, ATTR_SESSION_TIMEOUT
from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)

if TYPE_CHECKING:
    from tacacs_server.radius.server import RADIUSPacket


def apply_vsa_from_metadata(
    packet: "RADIUSPacket",
    metadata: dict[str, Any],
    vendor_filter: list[str] | None = None,
) -> bool:
    """Apply VSA attributes from user group metadata to RADIUS packet.

    Returns True if metadata parsed and applied successfully, False otherwise.
    """
    try:
        config = UserGroupMetadata(**metadata)
    except Exception as exc:
        logger.warning(
            "Invalid metadata for VSA generation",
            event="radius.vsa.metadata_invalid",
            error=str(exc),
        )
        return False

    vsa_config = config.radius_vsa

    if (not vendor_filter or "cisco" in vendor_filter) and vsa_config.cisco:
        for avpair in vsa_config.cisco.avpairs:
            value = f"{avpair['key']}={avpair['value']}"
            packet.add_cisco_avpair(value)
            logger.debug(
                "Added Cisco AVPair",
                event="radius.vsa.cisco.added",
                avpair=value,
            )
        if (
            vsa_config.cisco.timeout
            and not packet.get_attribute(ATTR_SESSION_TIMEOUT)
            and not config.session_timeouts.session_timeout
        ):
            packet.add_integer(ATTR_SESSION_TIMEOUT, vsa_config.cisco.timeout)

    if (not vendor_filter or "juniper" in vendor_filter) and vsa_config.juniper:
        if vsa_config.juniper.local_user_name:
            packet.add_juniper_role(vsa_config.juniper.local_user_name)

    if (not vendor_filter or "fortinet" in vendor_filter) and vsa_config.fortinet:
        for group in vsa_config.fortinet.group_names:
            packet.add_fortinet_group(group)

    if (not vendor_filter or "pfsense" in vendor_filter) and vsa_config.pfsense:
        if vsa_config.pfsense.client_ip_override:
            packet.add_pfsense_client_ip(vsa_config.pfsense.client_ip_override)

    if (not vendor_filter or "palo_alto" in vendor_filter) and vsa_config.palo_alto:
        if vsa_config.palo_alto.user_role:
            packet.add_palo_alto_role(vsa_config.palo_alto.user_role)

    if (not vendor_filter or "arista" in vendor_filter) and vsa_config.arista:
        packet.add_arista_privilege(vsa_config.arista.privilege_level)

    if config.session_timeouts.session_timeout:
        packet.add_integer(
            ATTR_SESSION_TIMEOUT, config.session_timeouts.session_timeout
        )
    if config.session_timeouts.idle_timeout:
        packet.add_integer(ATTR_IDLE_TIMEOUT, config.session_timeouts.idle_timeout)

    return True
