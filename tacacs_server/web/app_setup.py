# ruff: noqa
"""
FastAPI Application Setup with OpenAPI/Swagger Integration

Location: tacacs_server/web/app_setup.py

This file shows how to integrate OpenAPI documentation into your existing FastAPI app.
"""

import logging
import time
from datetime import datetime

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from .api_models import ErrorResponse
from .openapi_config import configure_openapi_ui, custom_openapi_schema

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """
    Create and configure FastAPI application with OpenAPI documentation.

    Returns:
        Configured FastAPI application instance
    """

    # Initialize FastAPI with custom OpenAPI configuration
    app = FastAPI(
        title="TACACS+ Server API",
        description="Enterprise-grade TACACS+/RADIUS appliance REST API",
        version="1.0.0",
        docs_url=None,  # Disable default docs, we'll use custom
        redoc_url=None,  # Disable default redoc, we'll use custom
        openapi_url="/openapi.json",  # OpenAPI schema endpoint
        openapi_tags=[
            {
                "name": "Status & Health",
                "description": "Server status, health checks, and metrics",
            },
            {
                "name": "Devices",
                "description": "Network device management operations",
            },
            {
                "name": "Device Groups",
                "description": "Device group management and configuration",
            },
            {
                "name": "Users",
                "description": "Local user account management",
            },
            {
                "name": "User Groups",
                "description": "User group management and permissions",
            },
            {
                "name": "Authentication",
                "description": "Authentication backend status and testing",
            },
            {
                "name": "Accounting",
                "description": "Accounting records and audit logs",
            },
            {
                "name": "Administration",
                "description": "Administrative operations (config, logs, backups)",
            },
            {
                "name": "RADIUS",
                "description": "RADIUS server status and configuration",
            },
        ],
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure based on your needs
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add GZip compression
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    # Add request timing middleware
    @app.middleware("http")
    async def add_process_time_header(request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        return response

    # Custom exception handlers
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ):
        """Handle validation errors with detailed responses"""
        errors = []
        for error in exc.errors():
            errors.append(
                {
                    "field": ".".join(str(loc) for loc in error["loc"]),
                    "message": error["msg"],
                    "type": error["type"],
                }
            )

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "Validation failed",
                "validation_errors": errors,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        """Handle general exceptions"""
        logger.error(f"Unhandled exception: {exc}", exc_info=True)

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal server error",
                "details": str(exc) if app.debug else "An unexpected error occurred",
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    # Configure custom OpenAPI schema (set in main app if desired)
    # app.openapi = lambda: custom_openapi_schema(app)

    # Configure documentation UIs
    configure_openapi_ui(app)

    # Add startup event
    @app.on_event("startup")
    async def startup_event():
        logger.info("TACACS+ Server API starting up...")
        logger.info("API Documentation available at:")
        logger.info("  - Swagger UI: http://localhost:8080/docs")
        logger.info("  - ReDoc: http://localhost:8080/redoc")
        logger.info("  - RapiDoc: http://localhost:8080/rapidoc")
        logger.info("  - Docs Index: http://localhost:8080/api-docs")
        logger.info("  - OpenAPI Spec: http://localhost:8080/openapi.json")

    @app.on_event("shutdown")
    async def shutdown_event():
        logger.info("TACACS+ Server API shutting down...")

    return app


# Example of how to define routes with OpenAPI documentation
def setup_routes(app: FastAPI):
    """
    Example of setting up routes with comprehensive OpenAPI documentation.

    This shows how to use the enhanced models with proper documentation.
    """

    from fastapi import APIRouter, Body, Query

    from .api_models import (
        DeviceCreate,
        DeviceResponse,
        HealthCheck,
        LoginRequest,
        LoginResponse,
        ServerStatus,
    )

    # Status & Health Router
    status_router = APIRouter(prefix="/api", tags=["Status & Health"])

    @status_router.get(
        "/status",
        response_model=ServerStatus,
        summary="Get server status",
        description=(
            "Retrieve current server status including uptime, statistics, "
            "and service health"
        ),
        responses={
            200: {
                "description": "Server status retrieved successfully",
                "model": ServerStatus,
            }
        },
    )
    async def get_status():
        """Get comprehensive server status and statistics"""
        # Implementation here
        return {
            "status": "running",
            "uptime_seconds": 86400.5,
            "version": "1.0.0",
            "tacacs": {
                "enabled": True,
                "port": 49,
                "active_connections": 5,
                "total_requests": 1000,
                "success_rate": 98.5,
            },
            "radius": {"enabled": True, "auth_port": 1812, "acct_port": 1813},
        }

    @status_router.get(
        "/health",
        response_model=HealthCheck,
        summary="Health check",
        description="Perform health check on all system components",
        responses={
            200: {"description": "System is healthy", "model": HealthCheck},
            503: {
                "description": "System is unhealthy or degraded",
                "model": HealthCheck,
            },
        },
    )
    async def health_check():
        """
        Comprehensive health check.

        Returns the health status of all system components:
        - Database connectivity
        - TACACS+ server
        - RADIUS server
        - Authentication backends
        """
        # Implementation here
        return {
            "status": "healthy",
            "checks": {
                "database": True,
                "tacacs_server": True,
                "radius_server": True,
                "auth_backends": True,
            },
            "timestamp": datetime.utcnow(),
        }

    # Device Management Router
    device_router = APIRouter(prefix="/api/devices", tags=["Devices"])

    @device_router.get(
        "",
        response_model=list[DeviceResponse],
        summary="List devices",
        description="Retrieve a list of network devices with optional filtering",
        responses={200: {"description": "List of devices retrieved successfully"}},
    )
    async def list_devices(
        limit: int = Query(50, ge=1, le=1000, description="Maximum number of devices"),
        offset: int = Query(0, ge=0, description="Number of devices to skip"),
        search: str | None = Query(None, description="Search by name or IP"),
        device_group_id: int | None = Query(None, description="Filter by device group"),
        enabled: bool | None = Query(None, description="Filter by enabled status"),
    ):
        """
        List all network devices with filtering and pagination.

        Filters:
        - Search by device name or IP address
        - Filter by device group
        - Filter by enabled/disabled status
        """
        # Implementation here
        pass

    @device_router.post(
        "",
        response_model=DeviceResponse,
        status_code=status.HTTP_201_CREATED,
        summary="Create device",
        description="Register a new network device",
        responses={
            201: {"description": "Device created successfully"},
            400: {"description": "Invalid input data"},
            409: {"description": "Device already exists"},
        },
    )
    async def create_device(
        device_data: DeviceCreate = Body(...),
    ):
        """
        Register a new network device.

        The device will inherit TACACS+ and RADIUS secrets from its device group.

        IP address can be:
        - Single IP: 192.168.1.1
        - CIDR notation: 192.168.1.0/24
        """
        # Implementation here
        pass

    # Authentication Router
    auth_router = APIRouter(prefix="/api/admin", tags=["Authentication"])

    @auth_router.post(
        "/login",
        response_model=LoginResponse,
        summary="Admin login",
        description="Authenticate admin user and receive session cookie",
        responses={
            200: {"description": "Login successful"},
            401: {"description": "Invalid credentials"},
            429: {"description": "Too many failed attempts, account locked"},
        },
    )
    async def admin_login(
        credentials: LoginRequest = Body(
            ..., example={"username": "admin", "password": "admin123"}
        ),
    ):
        """
        Authenticate admin user.

        Returns a session cookie that should be included in subsequent requests.

        Security features:
        - Rate limiting after failed attempts
        - Account lockout after multiple failures
        - Session expiration after inactivity
        """
        # Implementation here
        pass

    @auth_router.post(
        "/logout",
        summary="Admin logout",
        description="Invalidate current session",
        responses={
            200: {"description": "Logout successful"},
            401: {"description": "Not authenticated"},
        },
    )
    async def admin_logout():
        """
        Logout and invalidate session.

        The session cookie will be cleared.
        """
        # Implementation here
        pass

    # Register all routers
    app.include_router(status_router)
    # Note: user_router would be defined where user endpoints exist
    app.include_router(device_router)
    app.include_router(auth_router)

    return app


# Example: How to integrate this into your existing main.py
def integrate_with_existing_app():
    """
    Example showing how to integrate OpenAPI docs into your existing application.

    Add this to your existing tacacs_server/main.py or web/monitoring.py
    """

    # If you already have a FastAPI app
    from fastapi import FastAPI

    from .openapi_config import configure_openapi_ui, custom_openapi_schema

    # Your existing app
    app = FastAPI(
        title="TACACS+ Server API",
        version="1.0.0",
        docs_url=None,  # Disable default docs
        redoc_url=None,  # Disable default redoc
    )

    # Add custom OpenAPI configuration (set in main app if desired)
    # app.openapi = lambda: custom_openapi_schema(app)

    # Configure documentation UIs
    configure_openapi_ui(app)

    # Continue with your existing routes...
    # @app.get("/api/status")
    # async def get_status():
    #     ...

    return app


# Example: Adding OpenAPI documentation to existing routes
def enhance_existing_routes_example():
    """
    Example of how to enhance your existing routes with OpenAPI documentation.

    You don't need to rewrite everything - just add the decorators!
    """

    from fastapi import APIRouter, Query

    from .api_models import ErrorResponse, UserResponse

    router = APIRouter()

    # Before (minimal documentation)
    # @router.get("/api/users")
    # async def get_users():
    #     pass

    # After (enhanced with OpenAPI)
    @router.get(
        "/api/users",
        response_model=list[UserResponse],
        summary="List users",
        description="Retrieve list of all users",
        tags=["Users"],
        responses={
            200: {
                "description": "List retrieved successfully",
                "model": list[UserResponse],
            },
            401: {"description": "Authentication required", "model": ErrorResponse},
        },
    )
    async def get_users(
        limit: int = Query(50, description="Max items to return"),
        search: str | None = Query(None, description="Search term"),
    ):
        """
        Get all users with pagination and search.

        This endpoint supports:
        - Pagination via limit parameter
        - Search by username or email
        - Sorting by various fields
        """
        pass


# Example: Security scheme integration
def add_security_to_routes():
    """
    Example of adding security requirements to routes.
    """
    from fastapi import Depends, HTTPException, status
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

    security = HTTPBearer()

    async def verify_token(
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ):
        """Verify JWT token or API key"""
        token = credentials.credentials
        # Verify token here
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )
        return token

    # Use in routes
    from fastapi import APIRouter

    router = APIRouter()

    @router.get(
        "/api/protected",
        dependencies=[Depends(verify_token)],
        summary="Protected endpoint",
        description="This endpoint requires authentication",
    )
    async def protected_endpoint():
        """Access protected resource"""
        return {"message": "You have access!"}


# Testing the OpenAPI documentation
def test_openapi_endpoints():
    """
    Test that OpenAPI documentation is accessible.

    Add this to your test suite.
    """
    from fastapi.testclient import TestClient

    app = create_app()
    setup_routes(app)
    client = TestClient(app)

    # Test OpenAPI schema
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["title"] == "TACACS+ Server API"
    assert "paths" in schema

    # Test Swagger UI
    response = client.get("/docs")
    assert response.status_code == 200
    assert "swagger-ui" in response.text.lower()

    # Test ReDoc
    response = client.get("/redoc")
    assert response.status_code == 200
    assert "redoc" in response.text.lower()

    # Test RapiDoc
    response = client.get("/rapidoc")
    assert response.status_code == 200
    assert "rapidoc" in response.text.lower()

    # Test API docs index
    response = client.get("/api-docs")
    assert response.status_code == 200
    assert "API Documentation" in response.text


if __name__ == "__main__":
    """
    Run the application with OpenAPI documentation enabled.
    """
    import uvicorn

    app = create_app()
    setup_routes(app)

    print("Starting TACACS+ Server with OpenAPI documentation...")
    print("Documentation available at:")
    print("  - http://localhost:8080/api-docs (Documentation Index)")
    print("  - http://localhost:8080/docs (Swagger UI)")
    print("  - http://localhost:8080/redoc (ReDoc)")
    print("  - http://localhost:8080/rapidoc (RapiDoc)")
    print("  - http://localhost:8080/openapi.json (OpenAPI Spec)")

    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
