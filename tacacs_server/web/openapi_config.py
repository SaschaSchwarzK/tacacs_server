"""
OpenAPI/Swagger Configuration for TACACS+ Server

This module configures comprehensive OpenAPI documentation with:
- Detailed API documentation
- Authentication schemes
- Request/response examples
- Multiple documentation UIs (Swagger, ReDoc, RapiDoc)

Location: tacacs_server/web/openapi_config.py
"""

from typing import Any

from fastapi import FastAPI
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.openapi.utils import get_openapi


def custom_openapi_schema(app: FastAPI) -> dict[str, Any]:
    """
    Generate custom OpenAPI schema with enhanced documentation.

    This function creates a comprehensive API specification including:
    - Detailed descriptions
    - Examples for requests and responses
    - Authentication schemes
    - Server information
    - Contact and license information
    """
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="TACACS+ Server API",
        version="1.0.0",
        description="""
# TACACS+ Server REST API

A modern, enterprise-grade TACACS+/RADIUS appliance REST API.

## Features

- **Device Management**: Manage network devices and device groups
- **User Management**: Local user accounts with group assignments
- **Authentication**: Multiple backends (Local, LDAP, Okta)
- **Monitoring**: Real-time metrics and health checks
- **Accounting**: Comprehensive audit trail and accounting records
- **Configuration**: Dynamic configuration management

## Authentication

Most endpoints require authentication using session cookies or API keys.

### Session Authentication
1. Login via `POST /api/admin/login`
2. Use returned session cookie for subsequent requests

### API Key Authentication (if implemented)
Pass API key in header: `X-API-Key: your-api-key`

## Rate Limiting

API requests are rate limited to prevent abuse:
- Default: 60 requests per minute per client
- Configurable via server configuration

## Pagination

List endpoints support pagination:
- `limit`: Number of items per page (default: 50, max: 1000)
- `offset`: Number of items to skip (default: 0)
- `page`: Page number (alternative to offset)

## Filtering and Sorting

List endpoints support filtering and sorting:
- Filter by any field: `?field=value`
- Sort: `?sort=field` or `?sort=-field` (descending)
- Multiple filters: `?field1=value1&field2=value2`

## Error Responses

All errors follow consistent format:
```json
{
  "error": "Error message",
  "details": "Additional error details",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## WebSocket Support

Real-time updates available via WebSocket:
- `ws://host:port/ws/metrics` - Live metrics updates

## Useful Links

- [Full Documentation](https://github.com/SaschaSchwarzK/tacacs_server/blob/develop/docs/API_REFERENCE.md)
- [GitHub Repository](https://github.com/SaschaSchwarzK/tacacs_server)
- [Issue Tracker](https://github.com/SaschaSchwarzK/tacacs_server/issues)
        """,
        routes=app.routes,
        tags=[
            {
                "name": "Status & Health",
                "description": "Server status, health checks, and metrics",
            },
            {"name": "Devices", "description": "Network device management operations"},
            {
                "name": "Device Groups",
                "description": "Device group management and configuration",
            },
            {"name": "Users", "description": "Local user account management"},
            {
                "name": "User Groups",
                "description": "User group management and permissions",
            },
            {
                "name": "Authentication",
                "description": "Authentication backend status and testing",
            },
            {"name": "Accounting", "description": "Accounting records and audit logs"},
            {
                "name": "Administration",
                "description": "Administrative operations (config, logs, backups)",
            },
            {"name": "RADIUS", "description": "RADIUS server status and configuration"},
        ],
    )

    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "SessionAuth": {
            "type": "apiKey",
            "in": "cookie",
            "name": "session_id",
            "description": "Session-based authentication using cookies",
        },
        "APIKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "API key authentication (if enabled)",
        },
    }

    # Add server information
    openapi_schema["servers"] = [
        {"url": "http://localhost:8080", "description": "Development server"},
        {"url": "http://127.0.0.1:8080", "description": "Local server"},
        {
            "url": "https://tacacs.example.com",
            "description": "Production server (HTTPS)",
        },
    ]

    # Add contact and license information
    openapi_schema["info"]["contact"] = {
        "name": "TACACS+ Server Support",
        "url": "https://github.com/SaschaSchwarzK/tacacs_server",
        "email": "support@example.com",
    }

    openapi_schema["info"]["license"] = {
        "name": "MIT License with Attribution",
        "url": "https://github.com/SaschaSchwarzK/tacacs_server/blob/develop/LICENSE",
    }

    # Add common response schemas
    openapi_schema["components"]["schemas"]["ErrorResponse"] = {
        "type": "object",
        "properties": {
            "error": {
                "type": "string",
                "description": "Error message",
                "example": "Resource not found",
            },
            "details": {
                "type": "string",
                "description": "Additional error details",
                "example": "Device with ID 123 does not exist",
            },
            "timestamp": {
                "type": "string",
                "format": "date-time",
                "description": "Error timestamp",
                "example": "2024-01-01T12:00:00Z",
            },
        },
        "required": ["error"],
    }

    openapi_schema["components"]["schemas"]["PaginatedResponse"] = {
        "type": "object",
        "properties": {
            "items": {"type": "array", "items": {}, "description": "Array of items"},
            "total": {
                "type": "integer",
                "description": "Total number of items",
                "example": 100,
            },
            "page": {
                "type": "integer",
                "description": "Current page number",
                "example": 1,
            },
            "page_size": {
                "type": "integer",
                "description": "Items per page",
                "example": 50,
            },
            "total_pages": {
                "type": "integer",
                "description": "Total number of pages",
                "example": 2,
            },
        },
    }

    # Add common parameters
    openapi_schema["components"]["parameters"] = {
        "LimitParam": {
            "name": "limit",
            "in": "query",
            "description": "Maximum number of items to return",
            "required": False,
            "schema": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 50},
        },
        "OffsetParam": {
            "name": "offset",
            "in": "query",
            "description": "Number of items to skip",
            "required": False,
            "schema": {"type": "integer", "minimum": 0, "default": 0},
        },
        "PageParam": {
            "name": "page",
            "in": "query",
            "description": "Page number",
            "required": False,
            "schema": {"type": "integer", "minimum": 1, "default": 1},
        },
        "SortParam": {
            "name": "sort",
            "in": "query",
            "description": "Sort field (prefix with - for descending)",
            "required": False,
            "schema": {"type": "string", "example": "-created_at"},
        },
    }

    app.openapi_schema = openapi_schema
    return app.openapi_schema


def configure_openapi_ui(app: FastAPI):
    """
    Configure multiple documentation UIs for the API.

    Sets up:
    - Swagger UI at /docs
    - ReDoc at /redoc
    - RapiDoc at /rapidoc (modern alternative)
    """

    # Override default Swagger UI with custom configuration
    @app.get("/docs", include_in_schema=False)
    async def custom_swagger_ui_html():
        return get_swagger_ui_html(
            openapi_url=app.openapi_url,
            title=f"{app.title} - Swagger UI",
            oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
            swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
            swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
            swagger_ui_parameters={
                "deepLinking": True,
                "displayRequestDuration": True,
                "filter": True,
                "showExtensions": True,
                "showCommonExtensions": True,
                "tryItOutEnabled": True,
                "persistAuthorization": True,
                "docExpansion": "none",  # Can be "none", "list", or "full"
                "defaultModelsExpandDepth": 3,
                "defaultModelExpandDepth": 3,
                "displayOperationId": True,
                "syntaxHighlight.theme": "monokai",
            },
        )

    # Override default ReDoc with custom configuration
    @app.get("/redoc", include_in_schema=False)
    async def custom_redoc_html():
        return get_redoc_html(
            openapi_url=app.openapi_url,
            title=f"{app.title} - ReDoc",
            redoc_js_url="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js",
            redoc_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
            with_google_fonts=True,
        )

    # Add RapiDoc (modern alternative)
    from fastapi.responses import HTMLResponse

    @app.get("/rapidoc", include_in_schema=False)
    async def rapidoc_html():
        html_content = f"""
        <!doctype html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>{app.title} - RapiDoc</title>
            <script type="module" src="https://unpkg.com/rapidoc/dist/rapidoc-min.js"></script>
        </head>
        <body>
            <rapi-doc
                spec-url="{app.openapi_url}"
                theme="dark"
                bg-color="#1e1e1e"
                text-color="#f0f0f0"
                header-color="#2d2d2d"
                primary-color="#4a9eff"
                render-style="read"
                show-header="true"
                show-info="true"
                allow-authentication="true"
                allow-try="true"
                allow-spec-url-load="false"
                allow-spec-file-load="false"
                schema-style="tree"
                schema-expand-level="2"
                default-schema-tab="model"
                response-area-height="400px"
                show-curl-before-try="true"
                layout="column"
                fill-request-fields-with-example="true"
            >
                <div slot="logo" style="padding: 10px;">
                    <h2>🔐 {app.title}</h2>
                </div>
            </rapi-doc>
        </body>
        </html>
        """
        return HTMLResponse(content=html_content)

    # Add API documentation index page
    @app.get("/api-docs", include_in_schema=False)
    async def api_docs_index():
        html_content = """
        <!doctype html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>TACACS+ Server API Documentation</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                .container {
                    max-width: 800px;
                    background: white;
                    border-radius: 20px;
                    padding: 40px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                }
                h1 {
                    color: #333;
                    margin-bottom: 10px;
                    font-size: 2.5em;
                }
                .subtitle {
                    color: #666;
                    margin-bottom: 30px;
                    font-size: 1.1em;
                }
                .docs-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-top: 30px;
                }
                .doc-card {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    border-radius: 15px;
                    padding: 30px;
                    text-decoration: none;
                    color: white;
                    transition: transform 0.3s, box-shadow 0.3s;
                    text-align: center;
                }
                .doc-card:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                }
                .doc-card h3 {
                    margin-bottom: 10px;
                    font-size: 1.3em;
                }
                .doc-card p {
                    opacity: 0.9;
                    font-size: 0.9em;
                }
                .info-box {
                    background: #f8f9fa;
                    border-left: 4px solid #667eea;
                    padding: 20px;
                    margin-top: 30px;
                    border-radius: 5px;
                }
                .info-box h3 {
                    color: #333;
                    margin-bottom: 10px;
                }
                .info-box code {
                    background: #e9ecef;
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-family: 'Courier New', monospace;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔐 TACACS+ Server API</h1>
                <p class="subtitle">Choose your preferred API documentation format</p>
                
                <div class="docs-grid">
                    <a href="/docs" class="doc-card">
                        <h3>📘 Swagger UI</h3>
                        <p>Interactive API explorer with try-it-out functionality</p>
                    </a>
                    
                    <a href="/redoc" class="doc-card">
                        <h3>📗 ReDoc</h3>
                        <p>Clean, responsive documentation with advanced features</p>
                    </a>
                    
                    <a href="/rapidoc" class="doc-card">
                        <h3>📙 RapiDoc</h3>
                        <p>Modern documentation UI with dark mode support</p>
                    </a>
                </div>
                
                <div class="info-box">
                    <h3>Quick Start</h3>
                    <p>1. Authenticate: <code>POST /api/admin/login</code></p>
                    <p>2. Get server status: <code>GET /api/status</code></p>
                    <p>3. View devices: <code>GET /api/devices</code></p>
                </div>
                
                <div class="info-box" style="margin-top: 15px;">
                    <h3>OpenAPI Spec</h3>
                    <p>Download the raw OpenAPI specification: <a href="/openapi.json"><code>/openapi.json</code></a></p>
                </div>
            </div>
        </body>
        </html>
        """
        return HTMLResponse(content=html_content)


def add_openapi_examples():
    """
    Example schemas and request/response examples for OpenAPI.
    Use these in your route decorators.
    """
    return {
        "user_create_example": {
            "summary": "Create new user",
            "description": "Create a new local user account",
            "value": {
                "username": "jsmith",
                "password": "SecurePassword123!",
                "email": "jsmith@example.com",
                "privilege_level": 5,
                "enabled": True,
            },
        },
        "device_create_example": {
            "summary": "Create new device",
            "description": "Register a new network device",
            "value": {
                "name": "router-01",
                "ip_address": "192.168.1.1",
                "device_group_id": 1,
                "enabled": True,
                "metadata": {
                    "location": "Datacenter-A",
                    "rack": "R12",
                    "model": "Cisco-7200",
                },
            },
        },
        "device_group_create_example": {
            "summary": "Create device group",
            "description": "Create a new device group with secrets",
            "value": {
                "name": "Branch-Office-Routers",
                "description": "All routers in branch offices",
                "tacacs_secret": "TacacsSecret123!",
                "radius_secret": "RadiusSecret123!",
                "allowed_user_groups": [1, 2],
            },
        },
        "login_example": {
            "summary": "Admin login",
            "description": "Authenticate to get session cookie",
            "value": {"username": "admin", "password": "admin123"},
        },
    }


# Example usage in route definitions:
"""
from fastapi import APIRouter, Body
from .openapi_config import add_openapi_examples

router = APIRouter()
examples = add_openapi_examples()

@router.post(
    "/api/users",
    tags=["Users"],
    summary="Create new user",
    description="Create a new local user account with specified privileges",
    response_description="Created user object",
    responses={
        201: {"description": "User created successfully"},
        400: {"description": "Invalid input data"},
        409: {"description": "User already exists"}
    }
)
async def create_user(
    user_data: UserCreate = Body(..., examples=[examples["user_create_example"]])
):
    # Implementation
    pass
"""
