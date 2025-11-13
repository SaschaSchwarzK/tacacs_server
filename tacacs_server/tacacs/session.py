"""Session management for TACACS+ connections"""

import threading

from tacacs_server.utils.logger import get_logger
from tacacs_server.utils.simple_cache import LRUDict

logger = get_logger(__name__)


class SessionManager:
    """Manages TACACS+ sessions, secrets, and sequence tracking"""

    def __init__(self, max_sessions: int = 10000):
        self._session_lock = threading.RLock()
        self._seq_lock = threading.RLock()
        self.session_secrets: LRUDict[int, str] = LRUDict(max_sessions)
        self._last_request_seq: dict[int, int] = {}
        self.session_device: dict[int, object] = {}

    def get_or_create_secret(
        self, session_id: int, device_record, default_secret: str
    ) -> str:
        """Get or create session secret, preferring device-specific keys"""
        with self._session_lock:
            secret = self.session_secrets.get(session_id)
            if secret is None:
                secret = self._resolve_secret(device_record) or default_secret
                self.session_secrets[session_id] = secret
                if device_record is not None:
                    self.session_device[session_id] = device_record
            elif device_record is not None and session_id not in self.session_device:
                self.session_device[session_id] = device_record
            else:
                self.session_secrets.touch(session_id)
            return str(secret)

    def _resolve_secret(self, device_record) -> str | None:
        """Resolve TACACS shared secret from device group configuration"""
        if not device_record:
            return None

        group = getattr(device_record, "group", None)
        if not group:
            return None

        if getattr(group, "tacacs_secret", None):
            return str(getattr(group, "tacacs_secret"))

        metadata = getattr(group, "metadata", {}) or {}
        if isinstance(metadata, dict):
            secret_obj = metadata.get("tacacs_secret")
            if secret_obj is not None:
                return str(secret_obj)

        return None

    def cleanup_session(self, session_id: int, handlers=None) -> None:
        """Clean up session data"""
        with self._session_lock:
            try:
                self.session_secrets.pop(session_id)
            except KeyError:
                pass
            try:
                if handlers:
                    handlers.cleanup_session(session_id)
            except Exception as e:
                logger.warning("Failed to cleanup session %s: %s", session_id, e)

        with self._seq_lock:
            self._last_request_seq.pop(session_id, None)

    def cleanup_sessions(self, session_ids: set[int], handlers=None) -> None:
        """Clean up multiple sessions"""
        if not session_ids:
            return

        with self._session_lock:
            for session_id in session_ids:
                try:
                    self.session_secrets.pop(session_id)
                except KeyError:
                    pass
                try:
                    if handlers:
                        handlers.cleanup_session(session_id)
                except Exception as e:
                    logger.warning("Failed to cleanup session %s: %s", session_id, e)

        with self._seq_lock:
            for session_id in session_ids:
                self._last_request_seq.pop(session_id, None)

    def validate_sequence(self, session_id: int, seq_no: int) -> bool:
        """Validate sequence number for monotonic progression"""
        with self._seq_lock:
            last = self._last_request_seq.get(session_id)
            if last is not None:
                if seq_no <= last:
                    if (last - seq_no) < 100:
                        logger.warning(
                            "Out-of-order sequence: sess=0x%08x last=%s got=%s",
                            session_id,
                            last,
                            seq_no,
                        )
                        return False
                    # Session reset
                    self._last_request_seq[session_id] = seq_no
                    return True

                if ((seq_no - last) % 2) != 0:
                    logger.warning(
                        "Invalid sequence step: sess=0x%08x last=%s got=%s",
                        session_id,
                        last,
                        seq_no,
                    )
                    return False

            self._last_request_seq[session_id] = seq_no
            return True
