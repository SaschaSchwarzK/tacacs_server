"""Privilege level resolution with VSA precedence."""

from typing import Any

from tacacs_server.auth.metadata_schema import UserGroupMetadata
from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


def resolve_privilege_level(
    user_attrs: dict[str, Any],
    group_metadata: dict[str, Any] | None = None,
) -> int:
    """Resolve effective privilege level with VSA precedence.

    Precedence (highest to lowest):
    1. VSA metadata privilege (Cisco shell:priv-lvl or Arista privilege_level)
    2. User privilege_level
    3. User group privilege_level
    4. Default (1)
    """
    metadata: UserGroupMetadata | None = None
    if group_metadata:
        try:
            metadata = UserGroupMetadata(**group_metadata)
        except Exception as exc:
            logger.warning(
                "Failed to parse VSA metadata for privilege",
                error=str(exc),
            )

    if metadata and metadata.radius_vsa.cisco:
        for avpair in metadata.radius_vsa.cisco.avpairs:
            if avpair.get("key") != "shell:priv-lvl":
                continue
            try:
                vsa_priv = int(avpair["value"])
                if 0 <= vsa_priv <= 15:
                    logger.debug(
                        "Using VSA privilege from Cisco AVPair",
                        privilege=vsa_priv,
                        source="vsa_cisco",
                    )
                    return vsa_priv
                logger.warning(
                    "Ignoring out-of-range VSA privilege",
                    privilege=vsa_priv,
                    min=0,
                    max=15,
                )
            except (TypeError, ValueError) as exc:
                logger.warning("Non-integer privilege in VSA", error=str(exc))

    if metadata and metadata.radius_vsa.arista:
        vsa_priv = metadata.radius_vsa.arista.privilege_level
        logger.debug(
            "Using VSA privilege from Arista",
            privilege=vsa_priv,
            source="vsa_arista",
        )
        return vsa_priv

    if "privilege_level" in user_attrs:
        try:
            user_priv = int(user_attrs["privilege_level"])
        except (TypeError, ValueError):
            user_priv = 1
        logger.debug(
            "Using user privilege level",
            privilege=user_priv,
            source="user",
        )
        return user_priv

    if metadata:
        group_priv = int(metadata.privilege_level)
        logger.debug(
            "Using group privilege level",
            privilege=group_priv,
            source="group_metadata",
        )
        return group_priv

    logger.debug("Using default privilege level", privilege=1, source="default")
    return 1
