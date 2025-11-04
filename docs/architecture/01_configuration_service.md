# Configuration Service

## Overview
The Configuration Service is the foundation of the TACACS+ server, responsible for managing all runtime configuration. It's the first service to initialize and is a dependency for all other services.

## Key Components

### 1. Configuration Loading
- **Primary Config File**: `tacacs.conf` (INI format)
- **Default Location**: Server working directory
- **Required Sections**:
  - `[server]`: Core server settings
  - `[auth]`: Authentication settings
  - `[logging]`: Logging configuration

### 2. Configuration Store
- **Location**: `data/config_overrides.db` (SQLite)
- **Purpose**: Tracks runtime configuration changes
- **Features**:
  - Maintains change history
  - Supports rollback to previous versions
  - Tracks which values are overridden

### 3. Default Values
- Defined in `TacacsConfig` class
- Validated during initialization
- Can be overridden by environment variables

## Runtime Behavior

### Initialization
1. Loads configuration from file
2. Applies environment variable overrides
3. Initializes configuration store
4. Validates all settings
5. Makes configuration available to other services

### Configuration Changes
1. **Via API**:
   - Validates new values
   - Updates in-memory configuration
   - Records changes in config store
   - Notifies dependent services

2. **Via File**:
   - Detects file changes (optional)
   - Validates new configuration
   - Applies changes with rollback on failure

## Dependencies
- **Depends On**: None (first service to start)
- **Required By**: All other services

## Error Handling
- **Missing Config**: Creates default config if file not found
- **Invalid Values**: Logs error and uses defaults
- **Corrupt Store**: Rebuilds from file with warning

## Performance Considerations
- In-memory cache for fast access
- Lazy loading of rarely used settings
- Background validation of complex rules
