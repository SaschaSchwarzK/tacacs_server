# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
### Added
- Admin CLI `tacacs-admin` with `check-config`, `generate-bcrypt`, `audit-hashes`, `migrate-hashes`.
- Security headers middleware across web apps.
- Readiness (`/ready`) and liveness (`/health`) endpoints.
- Per-IP connection cap (configurable) and extended rate limiting.
- Multi-stage Dockerfile with ACA/ACI profiles and ACI deployment template.
- Property-based and golden-vector tests for TACACS packet/validation and malformed inputs.

### Changed
- Admin auth now bcrypt-only; legacy SHA-256 rejected with clear guidance.
- Local user password verification centralized with rehash-on-login for legacy.

### Fixed
- Test environment uses isolated temp DBs; avoids polluting production DB.

