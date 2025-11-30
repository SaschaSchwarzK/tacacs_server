"""Unit tests for metadata schema validation."""

import pytest

from tacacs_server.auth.metadata_schema import (
    CiscoVSAConfig,
    UserGroupMetadata,
    validate_metadata,
)


class TestMetadataValidation:
    def test_valid_cisco_avpair(self):
        metadata = {
            "radius_vsa": {
                "cisco": {"avpairs": [{"key": "shell:priv-lvl", "value": "15"}]}
            }
        }
        validated = validate_metadata(metadata)
        assert validated["radius_vsa"]["cisco"]["avpairs"][0]["key"] == "shell:priv-lvl"

    def test_invalid_avpair_format(self):
        with pytest.raises(ValueError, match="must contain ':'"):
            CiscoVSAConfig(avpairs=[{"key": "invalid", "value": "15"}])

    def test_schema_version_check(self):
        with pytest.raises(ValueError, match="Unsupported schema version"):
            UserGroupMetadata(schema_version="2.0")

    def test_privilege_level_bounds(self):
        with pytest.raises(ValueError):
            UserGroupMetadata(privilege_level=16)

    def test_pfsense_ip_validation(self):
        with pytest.raises(ValueError, match="Invalid IP address"):
            validate_metadata(
                {"radius_vsa": {"pfsense": {"client_ip_override": "999.1.1.1"}}}
            )
