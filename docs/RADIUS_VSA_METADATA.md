# VSA Metadata in User Groups

Store vendor-specific RADIUS attributes (VSAs) directly in `LocalUserGroupRecord.metadata`. This allows centralized, per-vendor privilege and session behavior.

## Schema Overview
- `schema_version`: currently `"1.0"`
- `privilege_level`: default fallback (0–15)
- `radius_vsa`: vendor-specific blocks (cisco, juniper, fortinet, pfsense, palo_alto, arista)
- `session_timeouts`: standard RADIUS `Session-Timeout` / `Idle-Timeout`
- `custom_attributes`: free-form extras (preserved but not validated)

Example:
```json
{
  "schema_version": "1.0",
  "privilege_level": 10,
  "radius_vsa": {
    "cisco": {
      "avpairs": [
        {"key": "shell:priv-lvl", "value": "15"},
        {"key": "shell:roles", "value": "network-admin"}
      ],
      "timeout": 3600
    },
    "arista": {"privilege_level": 14},
    "pfsense": {"client_ip_override": "10.0.0.50"}
  },
  "session_timeouts": {
    "session_timeout": 28800,
    "idle_timeout": 1800
  }
}
```

## Vendor Blocks
- **cisco**: `avpairs` (e.g., `shell:priv-lvl=15`), optional `timeout` (seconds) applied as `Session-Timeout` when no other timeout is set.
- **juniper**: `local_user_name`, `user_permissions` (list).
- **fortinet**: `group_names` (list).
- **pfsense**: `client_ip_override` (validated IP).
- **palo_alto**: `user_role`.
- **arista**: `privilege_level` (0–15).

## Privilege Resolution Precedence
1) VSA privilege (`cisco` `shell:priv-lvl`, `arista` `privilege_level`)  
2) User `privilege_level`  
3) Group `privilege_level` (from metadata)  
4) Default `1`

If no Cisco AVPair is added by metadata, a fallback `shell:priv-lvl=<effective>` AVPair is injected to ensure devices receive a privilege.

## Validation
Metadata is validated via Pydantic:
- Bounds checks (privilege 0–15, timeouts 0–86400)
- Cisco AVPair requires a `:` in the key
- pfSense IP is validated
- Extra fields are preserved (`extra="allow"`)

## Access-Accept Behavior
During RADIUS `Access-Accept`:
- First matching user group’s metadata is parsed.
- VSAs are added per vendor (Cisco AVPairs, Juniper role, Fortinet groups, pfSense client IP, Palo Alto role, Arista privilege).
- Session/idle timeouts applied from `session_timeouts`; Cisco `timeout` used if no other session timeout is set.
- Effective privilege is resolved using the precedence above; fallback Cisco AVPair added if none present.

## Quick How-To
Create or update a group with metadata:
```python
service.create_group(
    "network-admins",
    metadata={
        "privilege_level": 10,
        "radius_vsa": {
            "cisco": {
                "avpairs": [
                    {"key": "shell:priv-lvl", "value": "15"},
                    {"key": "shell:roles", "value": "network-admin"}
                ],
                "timeout": 3600
            }
        },
        "session_timeouts": {"session_timeout": 28800, "idle_timeout": 1800}
    }
)
```

Retrieve vendor config:
```python
service.get_vsa_config("network-admins", "cisco")
# -> {"avpairs": [...], "timeout": 3600}
```