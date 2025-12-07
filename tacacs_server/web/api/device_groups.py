# tacacs_server/web/api/device_groups.py

"""Device Group API endpoints."""

from typing import cast

from fastapi import APIRouter, Body, HTTPException, Query, status
from fastapi import Path as PathParam

from ...devices.service import DeviceService, DeviceValidationError
from ..api_models import DeviceGroupCreate, DeviceGroupResponse, DeviceGroupUpdate

router = APIRouter(prefix="/api/device-groups", tags=["Device Groups"])


def get_device_service() -> DeviceService:
    """
    Get device service instance.

    Note: This needs to be properly injected from your application.
    """
    # This will be injected from your main app
    # Placeholder for now - you'll need to implement proper dependency injection
    from tacacs_server.web.web import get_device_service as _get

    service = _get()
    if service is None:
        from fastapi import HTTPException, status

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Device service unavailable",
        )
    return cast(DeviceService, service)


# ============================================================================
# Device Group Endpoints
# ============================================================================


@router.get(
    "",
    response_model=list[DeviceGroupResponse],
    summary="List device groups",
    description="Get a list of all device groups",
)
async def list_device_groups(
    limit: int = Query(
        50, ge=1, le=1000, description="Maximum number of groups to return"
    ),
    offset: int = Query(0, ge=0, description="Number of groups to skip for pagination"),
):
    """
    List all device groups.

    Returns a paginated list of device groups with:
    - Group details
    - Secret status (not the actual secrets)
    - Device count
    - Allowed user groups
    """
    try:
        service = get_device_service()
        groups = service.get_device_groups(limit=limit, offset=offset)
        return groups
    except Exception as e:
        import traceback
        import logging
        logger = logging.getLogger(__name__)
        logger.exception(f"Failed to list device groups: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to list device groups: {str(e)}\n{traceback.format_exc()}"
        )


@router.get(
    "/{group_id}",
    response_model=DeviceGroupResponse,
    summary="Get device group",
    description="Get details of a specific device group by ID",
)
async def get_device_group(
    group_id: int = PathParam(..., ge=1, description="Device group ID"),
):
    """
    Get detailed information about a device group.

    Returns:
    - Group configuration
    - Number of devices in the group
    - Whether secrets are configured (not the actual secrets)
    - Allowed user groups
    """
    try:
        service = get_device_service()
        group = service.get_device_group_by_id(group_id)

        if not group:
            raise HTTPException(
                status_code=404, detail=f"Device group with ID {group_id} not found"
            )

        return group

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to get device group: {str(e)}"
        )


@router.post(
    "",
    response_model=DeviceGroupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create device group",
    description="Create a new device group with TACACS+ and RADIUS secrets",
)
async def create_device_group(group: DeviceGroupCreate | dict = Body(...)):
    """
    Create a new device group.

    The group stores:
    - TACACS+ shared secret (encrypted)
    - RADIUS shared secret (encrypted)
    - Access control policies
    - Configuration profiles

    All devices in this group will inherit these secrets.

    **Security Note:** Secrets are stored securely and never returned in API responses.
    Only a boolean indicating if they're set is returned.
    """
    try:
        service = get_device_service()

        # Support legacy payloads where secrets are under metadata
        if isinstance(group, dict):
            payload = group
            name = str(payload.get("name") or "").strip()
            description = payload.get("description")
            meta = payload.get("metadata") or {}
            tac_sec = meta.get("tacacs_secret") or payload.get("tacacs_secret")
            rad_sec = meta.get("radius_secret") or payload.get("radius_secret")
            allowed_vals = payload.get("allowed_user_groups")
            proxy_id = payload.get("proxy_id")
            proxy_network = payload.get("proxy_network")
        else:
            name = group.name
            description = group.description
            tac_sec = group.tacacs_secret
            rad_sec = group.radius_secret
            allowed_vals = group.allowed_user_groups
            proxy_id = getattr(group, "proxy_id", None)
            proxy_network = getattr(group, "proxy_network", None)

        # Normalize allowed_user_groups to local user group NAMES
        aug_allowed = None
        if allowed_vals is not None:
            raw_vals = [str(x) for x in allowed_vals]
            # Attempt to resolve numeric IDs to names using the user group service
            try:
                from tacacs_server.web.api.usergroups import (
                    get_group_service as _get_gsvc,
                )

                gsvc = _get_gsvc()
                id_to_name = {
                    int(cast(int, rec.id)): rec.name
                    for rec in gsvc.list_groups()
                    if getattr(rec, "id", None)
                }
                names: list[str] = []
                for v in raw_vals:
                    if v.isdigit() and int(v) in id_to_name:
                        names.append(id_to_name[int(v)])
                    else:
                        names.append(v)
                aug_allowed = names
            except Exception:
                # Fallback: accept provided values as names
                aug_allowed = raw_vals
        new_group = service.create_device_group(
            name=name,
            description=description,
            tacacs_secret=tac_sec,
            radius_secret=rad_sec,
            allowed_user_groups=aug_allowed,
            proxy_network=proxy_network,
            proxy_id=proxy_id,
        )

        return new_group

    except DeviceValidationError as e:
        # Map duplicate/exists errors to HTTP 409 Conflict for idempotent creates
        msg = str(e)
        if "already exists" in msg.lower() or "duplicate" in msg.lower():
            raise HTTPException(status_code=409, detail=msg)
        raise HTTPException(status_code=400, detail=msg)
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to create device group: {str(e)}"
        )


@router.put(
    "/{group_id}",
    response_model=DeviceGroupResponse,
    summary="Update device group",
    description="Update device group details and configuration",
)
async def update_device_group(
    group_id: int = PathParam(..., ge=1, description="Device group ID"),
    group: DeviceGroupUpdate | None = Body(None),
):
    """
    Update device group details.

    Supports partial updates - only provided fields will be updated.

    **Updating Secrets:**
    - Provide new secret to update it
    - Provide empty string to clear the secret
    - Omit field to keep existing secret

    **Note:** All devices in the group will use the updated secrets
    for future authentications.
    """
    try:
        service = get_device_service()

        # Check if group exists
        existing_group = service.get_device_group_by_id(group_id)
        if not existing_group:
            raise HTTPException(
                status_code=404, detail=f"Device group with ID {group_id} not found"
            )

        # Update group
        aug_allowed = None
        if group and group.allowed_user_groups is not None:
            raw_vals = [str(x) for x in group.allowed_user_groups]
            try:
                from tacacs_server.web.api.usergroups import (
                    get_group_service as _get_gsvc,
                )

                gsvc = _get_gsvc()
                id_to_name = {
                    int(cast(int, rec.id)): rec.name
                    for rec in gsvc.list_groups()
                    if getattr(rec, "id", None)
                }
                names: list[str] = []
                for v in raw_vals:
                    if v.isdigit() and int(v) in id_to_name:
                        names.append(id_to_name[int(v)])
                    else:
                        names.append(v)
                aug_allowed = names
            except Exception:
                aug_allowed = raw_vals
        updated_group = service.update_device_group(
            group_id=group_id,
            name=(group.name if group else None),
            description=(group.description if group else None),
            tacacs_secret=(group.tacacs_secret if group else None),
            radius_secret=(group.radius_secret if group else None),
            allowed_user_groups=aug_allowed,
            proxy_id=(group.proxy_id if group else None),
        )

        return updated_group

    except HTTPException:
        raise
    except DeviceValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to update device group: {str(e)}"
        )


@router.delete(
    "/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete device group",
    description="Delete a device group",
)
async def delete_device_group(
    group_id: int = PathParam(..., ge=1, description="Device group ID"),
):
    """
    Delete a device group.

    **Warning:**
    - This action cannot be undone
    - Cannot delete a group that has devices assigned to it
    - Remove all devices from the group first

    **Returns:**
    - 204 No Content on successful deletion
    - 404 if group not found
    - 409 if group has devices
    """
    try:
        service = get_device_service()

        # Check if group exists
        existing_group = service.get_device_group_by_id(group_id)
        if not existing_group:
            raise HTTPException(
                status_code=404, detail=f"Device group with ID {group_id} not found"
            )

        # Check if group has devices
        device_count = existing_group.get("device_count", 0)
        if device_count > 0:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Cannot delete device group with {device_count} device(s). "
                    "Remove all devices from the group first."
                ),
            )

        # Delete group
        service.delete_device_group(group_id)
        return None

    except HTTPException:
        raise
    except DeviceValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to delete device group: {str(e)}"
        )


# ============================================================================
# Additional Endpoints (Optional but useful)
# ============================================================================


@router.get(
    "/{group_id}/devices",
    response_model=list,
    summary="Get devices in group",
    description="Get all devices assigned to a specific device group",
)
async def get_devices_in_group(
    group_id: int = PathParam(..., ge=1, description="Device group ID"),
):
    """
    Get all devices in a specific device group.

    Useful for:
    - Viewing all devices using the same secrets
    - Managing device group membership
    - Bulk operations on devices in a group
    """
    try:
        service = get_device_service()

        # Check if group exists
        group = service.get_device_group_by_id(group_id)
        if not group:
            raise HTTPException(
                status_code=404, detail=f"Device group with ID {group_id} not found"
            )

        # Get devices in this group
        devices = service.get_devices(device_group_id=group_id)
        return devices

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to get devices in group: {str(e)}"
        )


@router.post(
    "/{group_id}/test-secret",
    summary="Test group secrets",
    description="Test if TACACS+/RADIUS secrets are configured correctly",
)
async def test_group_secrets(
    group_id: int = PathParam(..., ge=1, description="Device group ID"),
):
    """
    Test if secrets are configured for this group.

    **Note:** This doesn't reveal the actual secrets, just checks if they exist
    and meet minimum requirements.

    Returns:
    - tacacs_configured: boolean
    - radius_configured: boolean
    - warnings: list of any issues
    """
    try:
        service = get_device_service()

        group = service.get_device_group_by_id(group_id)
        if not group:
            raise HTTPException(
                status_code=404, detail=f"Device group with ID {group_id} not found"
            )

        warnings = []

        if not group.get("tacacs_secret_set"):
            warnings.append("TACACS+ secret not configured")

        if not group.get("radius_secret_set"):
            warnings.append("RADIUS secret not configured")

        return {
            "group_id": group_id,
            "group_name": group["name"],
            "tacacs_configured": group.get("tacacs_secret_set", False),
            "radius_configured": group.get("radius_secret_set", False),
            "warnings": warnings,
            "status": "ok" if not warnings else "warning",
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to test group secrets: {str(e)}"
        )
