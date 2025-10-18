# API and Protocol Notes

## OpenAPI

The REST API is documented via the generated OpenAPI schema. Key categories:
- Status & Health, Devices, Device Groups, Users, User Groups, Authentication, Accounting, RADIUS

To view:
- Swagger UI: `/docs`
- ReDoc: `/redoc`

## TACACS+ Extensions/Deviations

- Per-device-group secrets: The server selects TACACS+ shared secrets from the device group rather than a global secret.
- Sequence checks: The server enforces odd sequence numbers and monotonic progression, with a tolerant reset window for client restarts.
- Max packet length: Configurable `max_packet_length` (default 4096). Packets exceeding this are rejected.
- Minimal authorization: If no command is requested and user attributes are missing, the server grants a minimal service profile to satisfy certain device behaviors.
- Command authorization hook: Optional pluggable policy engine can evaluate `cmd` requests with group and privilege context.
- Accounting: Persisted to SQLite with materialized daily aggregates for reporting.

These behaviors are implemented to balance interoperability and security, and are called out in code comments and logs where relevant.

