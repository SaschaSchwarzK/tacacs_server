# System Architecture

This document provides a high‑level overview of the AAA appliance: TACACS+ and RADIUS, and how they share core components.

## TACACS+ Components

```mermaid
flowchart TD
    client["Client (Network Device)"]
    subgraph TacacsServer[TACACS+ Server]
      PH[Protocol Handler\n- Packet decode/encode\n- MD5 encryption]
      AAA["AAA Handlers\n- Authentication\n- Authorization (incl. Command Auth Engine)\n- Accounting"]
      BE[(Auth Backends)]
      subgraph Backends[Pluggable Backends]
        L[Local]
        LDAP[LDAP]
        OKTA[Okta]
      end
      DL[(Data Layer\nSQLite)]
      WEBS[Webhooks\n- URLs\n- Headers\n- Template\n- Thresholds]
    end

    client -- TACACS+ (port 49) --> PH --> AAA
    AAA --> BE --> Backends
    AAA --> DL
    AAA --> WEBS
```

## TACACS+ Request Flow (AuthN/AuthZ)

```mermaid
sequenceDiagram
    participant Dev as Network Device
    participant PH as Protocol Handler
    participant AAA as AAA Handlers
    participant BE as Backends
    participant CA as Command Auth Engine
    participant DB as SQLite
    participant WH as Webhooks

    Dev->>PH: TACACS+ packet (AUTHEN/AUTHOR)
    PH->>AAA: Decoded request
    AAA->>BE: Authenticate (local/LDAP/Okta)
    BE-->>AAA: Result + user attrs
    AAA->>CA: Check command policy (if AUTHOR)
    CA-->>AAA: allow/deny (+reason)
    AAA->>DB: Record accounting (if applicable)
    AAA->>WH: Notify (auth/author failures, thresholds)
    AAA-->>PH: Decision + attributes
    PH-->>Dev: TACACS+ response
```

## RADIUS Components

RADIUS support provides Authentication and Accounting per RFC 2865/2866. Authorization is TACACS+-specific; in RADIUS, attributes are returned on Access‑Accept.

Key implementation: `tacacs_server/radius/server.py`

```mermaid
flowchart TD
    client["Client (Network Device)"]
    subgraph RadiusServer[RADIUS Server]
      RPH["Protocol Handler\n- Packet encode/decode\n- Authenticator calc (MD5 per RFC)"]
      RAAA["RADIUS Handlers\n- Access-Request\n- Accounting-Request"]
      RCL["(Client Registry\n- Per group/device secrets\n- Allowed user groups\n- Attributes)"]
      BE[(Auth Backends)]
      DL[(Data Layer\nSQLite)]
    end

    client -- RADIUS 1812/udp (Auth) --> RPH --> RAAA
    client -- RADIUS 1813/udp (Acct) --> RPH --> RAAA
    RAAA --> BE
    RAAA --> RCL
    RAAA --> DL
```

### RADIUS Request Flows

Authentication (Access‑Request):

```mermaid
sequenceDiagram
    participant Dev as Network Device
    participant RPH as RADIUS Protocol Handler
    participant RAAA as RADIUS Logic
    participant BE as Auth Backends
    participant DS as Device/Group Store

    Dev->>RPH: Access-Request (User-Name, User-Password, …)
    RPH->>RAAA: Parsed packet (+client IP)
    RAAA->>DS: Resolve client/network → secret, group, attrs
    RAAA->>BE: Authenticate user (shared with TACACS+)
    BE-->>RAAA: Result + user attributes
    RAAA-->>Dev: Access‑Accept/Reject (+Reply‑Message, attrs)
```

Accounting (Accounting‑Request):

```mermaid
sequenceDiagram
    participant Dev as Network Device
    participant RPH as RADIUS Protocol Handler
    participant RAAA as RADIUS Logic
    participant DB as SQLite

    Dev->>RPH: Accounting-Request (Start/Stop/Interim)
    RPH->>RAAA: Parsed packet
    RAAA->>DB: Persist accounting record (service="radius")
    RAAA-->>Dev: Accounting-Response
```

### Shared Components and Integration

- Authentication Backends: TACACS+ and RADIUS share the same pluggable backends (`tacacs_server/auth/*`).
- Device/Group Store: RADIUS client definitions (networks, secrets, allowed groups, attributes) are resolved from the device store and group metadata.
- Accounting: Records are written via the shared accounting logger with `service="radius"`.
- Monitoring/Admin: The web monitoring layer exposes RADIUS stats and configured clients; the Admin UI summarizes auth/acct metrics and per‑group RADIUS secret status.

## Notes

- Command Authorization is implemented via a policy engine (permit/deny rules) invoked by AAA Handlers.
- Webhooks support templated JSON payloads, headers, timeouts, and threshold notifications.
- REST API is disabled by default unless `API_TOKEN` is configured. Admin UI is disabled unless an admin bcrypt password hash is configured.
