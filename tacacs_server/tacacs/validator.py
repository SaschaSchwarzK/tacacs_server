"""Packet validation logic"""

try:
    import json as _json

    _HAS_JSON = True
except Exception:
    _HAS_JSON = False

from tacacs_server.tacacs.constants import (
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_PACKET_TYPE,
    TAC_PLUS_VERSION,
)
from tacacs_server.tacacs.packet import TacacsPacket
from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


class PacketValidator:
    """Validates TACACS+ packets"""

    def __init__(self, max_packet_length: int = 4096):
        self.max_packet_length = max_packet_length

    def validate_header(self, packet: TacacsPacket) -> bool:
        """Validate packet header"""
        # major_version = packet.version >> 4 & 15
        # if major_version != TAC_PLUS_MAJOR_VER:
        #     self._log_invalid_version(packet.session_id, major_version)
        #     return False
        # Check the complete version byte, not just the major version
        if packet.version != TAC_PLUS_VERSION:
            self._log_invalid_version(packet.session_id, packet.version)
            return False

        if packet.packet_type not in [
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR,
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT,
        ]:
            self._log_invalid_type(packet.session_id, packet.packet_type)
            return False

        if packet.seq_no < 1 or (packet.seq_no % 2) != 1:
            self._log_invalid_sequence(packet.session_id, packet.seq_no)
            return False

        return True

    def validate_size(self, length: int) -> bool:
        """Validate packet size"""
        return length <= self.max_packet_length

    def _log_invalid_version(self, session_id: int, got_version: int):
        if _HAS_JSON:
            try:
                logger.warning(
                    _json.dumps(
                        {
                            "event": "invalid_major_version",
                            "session": f"0x{session_id:08x}",
                            "got": got_version,
                            "expected": TAC_PLUS_MAJOR_VER,
                        }
                    )
                )
            except Exception as e:
                logger.debug("Failed to log invalid major version: %s", e)
        else:
            logger.warning("Invalid major version: %s", got_version)

    def _log_invalid_type(self, session_id: int, packet_type: int):
        if _HAS_JSON:
            try:
                logger.warning(
                    _json.dumps(
                        {
                            "event": "invalid_packet_type",
                            "session": f"0x{session_id:08x}",
                            "type": packet_type,
                        }
                    )
                )
            except Exception as e:
                logger.debug("Failed to log invalid packet type: %s", e)
        else:
            logger.warning("Invalid packet type: %s", packet_type)

    def _log_invalid_sequence(self, session_id: int, seq_no: int):
        if _HAS_JSON:
            try:
                logger.warning(
                    _json.dumps(
                        {
                            "event": "invalid_sequence_number",
                            "session": f"0x{session_id:08x}",
                            "got": seq_no,
                            "require": "odd>=1",
                        }
                    )
                )
            except Exception as e:
                logger.debug("Failed to log invalid sequence number: %s", e)
        else:
            logger.warning("Invalid sequence number for request: %s", seq_no)
