# Security Policy

## Supported Versions
The `main` and `develop` branches are actively maintained. Security updates are released as needed.

## Reporting a Vulnerability
Please open a private security advisory on GitHub (Security > Advisories) or contact the maintainers.

## Guidelines
- Do not include secrets in code or images. Provide secrets via environment variables or mounted files.
- Admin passwords must use bcrypt. Legacy hashes are not supported for admin and are auto-migrated for local users on login.
- Enable HTTPS in production and ensure `SECURE_COOKIES=true`.

