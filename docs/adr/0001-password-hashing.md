# ADR 0001: Password Hashing Strategy

## Context
The project historically allowed unsalted SHA-256 hashes for local users and admin. This is weak and easily brute-forced.

## Decision
- Enforce bcrypt for admin; reject legacy SHA-256 admin hashes.
- For local users, support rehash-on-login: if a legacy SHA-256 hash verifies, replace with bcrypt.
- Provide audit and migration tooling.

## Consequences
- Admin configs must update `ADMIN_PASSWORD_HASH` to bcrypt.
- Legacy user accounts transparently upgrade on next successful login or via CLI migration.

