# ADR 0002: Readiness Semantics

## Context
We need a reliable readiness probe for container orchestrators.

## Decision
`/ready` returns 200 only when:
- TACACS server is running and the TCP socket is bound.
- At least one authentication backend is loaded.
- Configuration validates without issues.

`/health` (liveness) always returns 200 when the process is responsive.

## Consequences
- Orchestrators can gate traffic using `/ready` and monitor liveness with `/health`.

