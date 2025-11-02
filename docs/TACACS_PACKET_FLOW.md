```mermaid
flowchart TD
    A[Client Connection] --> B[PROXY Protocol v2 Check]
    B -->|PROXY Header Detected| C[Parse PROXY Header]
    B -->|No PROXY Header| D[Use Direct Connection]
    C --> E[Validate Proxy IP]
    E -->|Valid| F[Use Client IP from PROXY]
    E -->|Invalid| G[Reject if Strict Mode]
    D --> H[Rate Limiting Check]
    F --> H
    H -->|Allowed| I[Device Lookup]
    H -->|Rate Limited| J[Close Connection]
    I -->|Device Found| K[Use Device Secret]
    I -->|Device Not Found| L{Auto-register?}
    L -->|Yes| M[Create New Device]
    L -->|No| N[Reject Connection]
    M --> O[Use Default Group Secret]
    K --> P[Process TACACS Packet]
    O --> P
    P --> Q[Validate Packet Header]
    Q --> R[Check Encryption]
    R -->|Encrypted| S[Decrypt Packet]
    R -->|Unencrypted| T{Encryption Required?}
    T -->|Yes| U[Reject]
    T -->|No| V[Process as Plaintext]
    S --> W[Process TACACS Packet]
    V --> W
    W --> X[Route to Handler]
    X -->|AUTH| Y[Authentication Handler]
    X -->|AUTHOR| Z[Authorization Handler]
    X -->|ACCT| AA[Accounting Handler]
    Y --> AB[Validate Credentials]
    Z --> AC[Check Permissions]
    AA --> AD[Log Session]
    AB --> AE[Send Response]
    AC --> AE
    AD --> AE
    AE --> AF[Encrypt if Needed]
    AF --> AG[Send to Client]
    ```