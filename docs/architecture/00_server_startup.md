# Server Startup Process

## Container Startup Orchestration (0-5000ms)

### Phase 0: Pre-startup Recovery
- Checks for Azure Storage configuration
- Restores from latest backup if available
- Downloads configuration from cloud storage
- Validates minimum required settings
- Determines which config file to use

### 1. Configuration Loading (0-100ms)
- Loads and validates configuration (from selected source)
- Initializes configuration store
- Sets up logging
- Validates all configuration values

### 2. Core Services (100-500ms)
- **Authentication Service**: Sets up authentication backends
- **Database Services**: Initializes SQLite connections
- **Backup Service**: Verifies backup locations
- **Device Store**: Loads devices and default device group; honors `devices.auto_register`
- **TACACS+ Server**: Binds to network ports

### 3. Web Services (500-1000ms)
- **Web Server**: Starts FastAPI application
- **API Endpoints**: Registers all routes
- **Admin Interface**: Initializes frontend assets
- **WebSocket**: Sets up real-time channels

### 4. Background Services (1000ms+)
- **Scheduler**: Starts scheduled jobs
- **Monitoring**: Begins collecting metrics
- **Housekeeping**: Starts cleanup tasks

## Service Dependencies

```mermaid
graph TD
    A[Configuration Service] --> B[Authentication Service]
    A --> C[Database Services]
    B --> D[Web Interface]
    C --> D
    C --> E[Backup Service]
    C --> F[Device Store]
    D --> E
    A --> F[TACACS+ Server]
    B --> F
    C --> F
```

## Configuration Overrides

### Environment Variables
- `TACACS_CONFIG`: Path to config file
- `ADMIN_USERNAME`: Web admin username
- `ADMIN_PASSWORD`: Web admin password (hashed)
- `LOG_LEVEL`: Logging verbosity

### Command Line Arguments
- `--config`: Path to config file
- `--port`: Web server port
- `--host`: Bind address
- `--debug`: Enable debug mode

## Error Handling

### Startup Errors
- Missing configuration: Exits with error code 1
- Port in use: Tries next available port
- Permission issues: Checks and suggests fixes

### Runtime Recovery
- Automatic reconnection for databases
- Graceful degradation of features
- Fallback to safe defaults

## Performance Considerations
- Lazy loading of non-essential components
- Background initialization of heavy services
- Progressive enhancement of features
