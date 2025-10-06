# tacacs_server/web/api/devices.py

"""Device API endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Query, HTTPException, status
from fastapi import Path as PathParam

from ...devices.service import (
    DeviceService,
    DeviceNotFound,
    GroupNotFound,
    DeviceValidationError
)
from ..api_models import (
    DeviceResponse,
    DeviceCreate,
    DeviceUpdate,
    DeviceGroupResponse,
    DeviceGroupCreate,
    DeviceGroupUpdate
)

router = APIRouter(prefix="/api/devices", tags=["Devices"])


def get_device_service() -> DeviceService:
    """Get device service instance (you'll need to inject this properly)."""
    # This needs to be injected from your main app
    # For now, it's a placeholder
    from tacacs_server.main import get_device_service
    return get_device_service()


# ============================================================================
# Device Endpoints
# ============================================================================

@router.get(
    "",
    response_model=List[DeviceResponse],
    summary="List devices",
    description="Get a list of all network devices with optional filtering"
)
async def list_devices(
    limit: int = Query(50, ge=1, le=1000, description="Maximum number of devices"),
    offset: int = Query(0, ge=0, description="Number of devices to skip"),
    search: Optional[str] = Query(None, description="Search by name or IP address"),
    device_group_id: Optional[int] = Query(None, description="Filter by device group ID"),
    enabled: Optional[bool] = Query(None, description="Filter by enabled status")
):
    """List all network devices with filtering and pagination."""
    try:
        service = get_device_service()
        devices = service.get_devices(
            limit=limit,
            offset=offset,
            search=search,
            device_group_id=device_group_id,
            enabled=enabled
        )
        return devices
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list devices: {str(e)}")


@router.get(
    "/{device_id}",
    response_model=DeviceResponse,
    summary="Get device",
    description="Get details of a specific device by ID"
)
async def get_device(
    device_id: int = PathParam(..., ge=1, description="Device ID", example=1)
):
    """Get detailed information about a specific device."""
    try:
        service = get_device_service()
        device = service.get_device_by_id(device_id)
        if not device:
            raise HTTPException(status_code=404, detail=f"Device with ID {device_id} not found")
        return device
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get device: {str(e)}")


@router.post(
    "",
    response_model=DeviceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create device",
    description="Register a new network device"
)
async def create_device(device: DeviceCreate):
    """Create a new network device."""
    try:
        service = get_device_service()
        new_device = service.create_device_from_dict(
            name=device.name,
            ip_address=device.ip_address,
            device_group_id=device.device_group_id,
            enabled=device.enabled,
            metadata=device.metadata
        )
        return new_device
    except (GroupNotFound, DeviceValidationError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create device: {str(e)}")


@router.put(
    "/{device_id}",
    response_model=DeviceResponse,
    summary="Update device",
    description="Update device details"
)
async def update_device(
    device_id: int = PathParam(..., ge=1, description="Device ID"),
    device: DeviceUpdate = None
):
    """Update device details."""
    try:
        service = get_device_service()
        updated_device = service.update_device_from_dict(
            device_id=device_id,
            name=device.name,
            ip_address=device.ip_address,
            device_group_id=device.device_group_id,
            enabled=device.enabled,
            metadata=device.metadata
        )
        return updated_device
    except DeviceNotFound:
        raise HTTPException(status_code=404, detail=f"Device with ID {device_id} not found")
    except (GroupNotFound, DeviceValidationError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update device: {str(e)}")


@router.delete(
    "/{device_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete device",
    description="Delete a network device"
)
async def delete_device(
    device_id: int = PathParam(..., ge=1, description="Device ID")
):
    """Delete a device."""
    try:
        service = get_device_service()
        service.delete_device(device_id)
        return None
    except DeviceNotFound:
        raise HTTPException(status_code=404, detail=f"Device with ID {device_id} not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete device: {str(e)}")