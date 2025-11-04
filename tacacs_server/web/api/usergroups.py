"""User group API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Body, HTTPException, Query, status
from fastapi import Path as PathParam

from tacacs_server.auth.local_user_group_service import (
    LocalUserGroupExists,
    LocalUserGroupNotFound,
    LocalUserGroupService,
    LocalUserGroupValidationError,
)
from tacacs_server.auth.local_user_service import LocalUserService
from tacacs_server.web.api_models import (
    UserGroupCreate,
    UserGroupResponse,
    UserGroupUpdate,
)

router = APIRouter(prefix="/api/user-groups", tags=["User Groups"])


def get_group_service() -> LocalUserGroupService:
    from tacacs_server.web.web import get_local_user_group_service

    service = get_local_user_group_service()
    if not service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="User group service unavailable",
        )
    return service


def _get_user_service() -> LocalUserService | None:
    from tacacs_server.web.web import get_local_user_service

    return get_local_user_service()


def _build_member_counts(users) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in users:
        for group_name in record.groups:
            counts[group_name] = counts.get(group_name, 0) + 1
    return counts


def _group_to_response(record, member_counts: dict[str, int]) -> dict:
    return {
        "id": record.id or 0,
        "name": record.name,
        "description": record.description,
        "privilege_level": record.privilege_level,
        "metadata": dict(record.metadata),
        "ldap_group": record.ldap_group,
        "okta_group": record.okta_group,
        "member_count": member_counts.get(record.name, 0),
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    }


@router.get(
    "",
    response_model=list[UserGroupResponse],
    summary="List user groups",
    description="Retrieve all local user groups with optional filtering",
)
async def list_user_groups(
    limit: int = Query(
        50, ge=1, le=1000, description="Maximum number of groups to return"
    ),
    offset: int = Query(0, ge=0, description="Number of groups to skip for pagination"),
    search: str | None = Query(None, description="Filter by group name substring"),
):
    try:
        group_service = get_group_service()
        user_service = _get_user_service()
        users = user_service.list_users() if user_service else []
        member_counts = _build_member_counts(users)
        records = group_service.list_groups()
        groups = [_group_to_response(record, member_counts) for record in records]
        if search:
            lowered = search.lower()
            groups = [group for group in groups if lowered in group["name"].lower()]
        return groups[offset : offset + limit]
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list user groups: {exc}",
        ) from exc


@router.get(
    "/{group_name}",
    response_model=UserGroupResponse,
    summary="Get user group",
    description="Retrieve a local user group by name",
)
async def get_user_group(
    group_name: str = PathParam(..., min_length=1, description="User group name"),
):
    try:
        group_service = get_group_service()
        user_service = _get_user_service()
        users = user_service.list_users() if user_service else []
        member_counts = _build_member_counts(users)
        record = group_service.get_group(group_name)
        return _group_to_response(record, member_counts)
    except LocalUserGroupNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc


@router.post(
    "",
    response_model=UserGroupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create user group",
    description="Create a new local user group",
)
async def create_user_group(group: UserGroupCreate):
    group_service = get_group_service()
    user_service = _get_user_service()
    try:
        record = group_service.create_group(
            name=group.name,
            description=group.description,
            metadata=group.metadata,
            ldap_group=group.ldap_group,
            okta_group=group.okta_group,
            privilege_level=group.privilege_level,
        )
        users = user_service.list_users() if user_service else []
        member_counts = _build_member_counts(users)
        return _group_to_response(record, member_counts)
    except LocalUserGroupExists as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc
    except (LocalUserGroupValidationError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create user group: {exc}",
        ) from exc


@router.put(
    "/{group_name}",
    response_model=UserGroupResponse,
    summary="Update user group",
    description="Update an existing local user group",
)
async def update_user_group(
    group_name: str = PathParam(..., min_length=1, description="User group name"),
    payload: UserGroupUpdate | None = Body(None),
):
    group_service = get_group_service()
    user_service = _get_user_service()
    try:
        data = payload.model_dump(exclude_unset=True) if payload else {}
        update_kwargs = {}
        if "description" in data:
            update_kwargs["description"] = data["description"]
        if "privilege_level" in data:
            update_kwargs["privilege_level"] = data["privilege_level"]
        if "metadata" in data:
            update_kwargs["metadata"] = data["metadata"]
        if "ldap_group" in data:
            update_kwargs["ldap_group"] = data["ldap_group"]
        if "okta_group" in data:
            update_kwargs["okta_group"] = data["okta_group"]

        record = group_service.update_group(group_name, **update_kwargs)
        users = user_service.list_users() if user_service else []
        member_counts = _build_member_counts(users)
        return _group_to_response(record, member_counts)
    except LocalUserGroupNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    except LocalUserGroupValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update user group: {exc}",
        ) from exc


@router.delete(
    "/{group_name}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete user group",
    description="Delete a local user group",
)
async def delete_user_group(
    group_name: str = PathParam(..., min_length=1, description="User group name"),
):
    group_service = get_group_service()
    try:
        group_service.delete_group(group_name)
    except LocalUserGroupNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete user group: {exc}",
        ) from exc
    return None
