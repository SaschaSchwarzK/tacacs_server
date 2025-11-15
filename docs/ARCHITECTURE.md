# Architecture Overview

## Components and Data Flow

```mermaid
flowchart LR
  subgraph Clients
    TAC["Network Devices (TACACS+)"]
    RAD["Network Devices (RADIUS)"]
    Admin[Admin UI / API]
  end

  %% Servers
  TAC -->|"TCP/49\n(PROXY v2 optional)"| TS[TacacsServer]
  RAD -->|UDP/1812/1813| RS[RADIUS Server]
  Admin -->|HTTP/WS| Web[Web Monitoring/API]

  %% Shared services
  TS <--> Auth["Auth Backends\nLocal / LDAP / Okta"]
  RS <--> Auth
  TS <--> DevStore["Device Store\n(SQLITE)"]
  RS <--> DevStore
  Web <--> DevStore
  TS --> AcctDB["Accounting DB"]
  RS --> AcctDB

  %% Monitoring/metrics
  TS -. Prometheus .-> Web
  RS -. Prometheus .-> Web
```

## TACACS+ Authentication (PAP)

```mermaid
sequenceDiagram
  participant Dev as Network Device
  participant TS as TacacsServer
  participant AH as AAAHandlers
  participant BE as Auth Backends

  Dev->>TS: TCP connect (+ optional PROXY v2)
  alt PROXY v2 present
    TS-->>TS: Validate header (reject_invalid default true)
  end
  Dev->>TS: TACACS+ AUTHEN START (user, pass)
  TS->>AH: handle_authentication
  AH->>BE: authenticate(user, pass) with timeout
  alt backend accepts
    BE-->>AH: ok
    AH-->>AH: Evaluate device-scoped group policy\n(Local/LDAP/Okta/RADIUS mapping)
    alt AAA allows
      AH-->>TS: PASS
    else AAA denies
      AH-->>TS: FAIL (group_not_allowed)
    end
    TS-->>Dev: AUTHEN REPLY PASS
  else all backends reject
    BE-->>AH: fail/error
    AH-->>TS: FAIL (detail)
    TS-->>Dev: AUTHEN REPLY FAIL
  end
```

## TACACS+ Authorization (Command + Exec)

```mermaid
flowchart TD
  A[Start Authorization] --> B{User attributes found?}
  B -- No --> C[If only service requested\nreturn minimal PASS] --> G[End]
  B -- Yes --> D["Build Context\n(user groups, device group, priv)"]
  D --> E{cmd present?}
  E -- No --> I[Grant base attrs]
  E -- Yes --> O{Privilege check order}
  O -- before --> P{req priv > user priv?}
  P -- Yes --> F[FAIL insufficient privilege]
  P -- No --> Q
  O -- after/none --> Q
  Q["Evaluate Command Rules\n(engine: exact/prefix/regex/wildcard;\nmin/max priv; user/device groups)"] --> R{Match}
  R -- No --> S["Apply default_action\n(permit/deny)"]
  R -- Yes --> T{Rule action}
  T -- deny --> F
  T -- permit --> U["Grant attrs per response_mode\n(pass_add or pass_repl)"]
  I --> G
  F --> G
```

Notes
- Privilege enforcement order is configurable: `before` (default), `after`, or `none`.
- When no rule matches, `default_action` decides allow/deny, and `response_mode` controls PASS_ADD vs PASS_REPL for allowed results.

## Web Monitoring and Admin

- FastAPI app exposes:
  - Admin UI under `/admin/*` (requires authenticated session)
  - REST API under `/api/*` (disabled unless `API_TOKEN` is configured; enforces token or admin session)
  - Health, status, metrics, and device/user management endpoints
- Security headers middleware sets CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, X-XSS-Protection, and removes `Server` header.

## PROXY Protocol v2 Handling

- Optional HAProxy PROXY v2 parsing on TCP accept for TACACS+:
  - Detects signature via peek with short retries
  - Parses header; on invalid/unsupported headers, rejects by default (`reject_invalid=true`)
  - On success, sets `(client_ip, proxy_ip)` for device resolution and metrics
- Device matching supports proxy-aware groups via `proxy_network` with exact + fallback tiers and longest-prefix selection.
