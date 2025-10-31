"""User API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Body, HTTPException, Query, status
from fastapi import Path as PathParam

from tacacs_server.auth.local_user_service import (
    LocalUserExists,
    LocalUserNotFound,
    LocalUserService,
    LocalUserValidationError,
)
from tacacs_server.web.api_models import UserCreate, UserResponse, UserUpdate

router = APIRouter(prefix="/api/users", tags=["Users"])


def get_user_service() -> LocalUserService:
    from tacacs_server.web.web import get_local_user_service

    service = get_local_user_service()
    if not service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="User service unavailable",
        )
    return service


def _user_to_response(record) -> dict:
    return {
        "id": record.id or 0,
        "username": record.username,
        "privilege_level": record.privilege_level,
        "service": record.service,
        "groups": list(record.groups),
        "enabled": record.enabled,
        "description": record.description,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    }


@router.get(
    "",
    response_model=list[UserResponse],
    summary="List users",
    description="Retrieve all local users with optional filtering",
)
async def list_users(
    limit: int = Query(
        50, ge=1, le=1000, description="Maximum number of users to return"
    ),
    offset: int = Query(0, ge=0, description="Number of users to skip for pagination"),
    search: str | None = Query(None, description="Filter by username substring"),
    group: str | None = Query(None, description="Filter by group membership"),
):
    try:
        service = get_user_service()
        records = service.list_users()
        users = [_user_to_response(record) for record in records]
        if search:
            lowered = search.lower()
            users = [user for user in users if lowered in user["username"].lower()]
        if group:
            users = [user for user in users if group in user["groups"]]
        return users[offset : offset + limit]
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list users: {exc}",
        ) from exc


@router.get(
    "/{username}",
    response_model=UserResponse,
    summary="Get user",
    description="Retrieve a single local user by username",
)
async def get_user(
    username: str = PathParam(..., min_length=1, description="Username"),
):
    try:
        service = get_user_service()
        record = service.get_user(username)
        return _user_to_response(record)
    except LocalUserNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create user",
    description="Create a new local user",
)
async def create_user(user: UserCreate):
    service = get_user_service()
    try:
        record = service.create_user(
            username=user.username,
            password=user.password,
            password_hash=user.password_hash,
            privilege_level=user.privilege_level,
            service=user.service,
            groups=user.groups,
            enabled=user.enabled,
            description=user.description,
        )
        return _user_to_response(record)
    except (LocalUserValidationError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except LocalUserExists as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create user: {exc}",
        ) from exc


@router.put(
    "/{username}",
    response_model=UserResponse,
    summary="Update user",
    description="Update an existing local user",
)
async def update_user(
    username: str = PathParam(..., min_length=1, description="Username"),
    payload: UserUpdate | None = Body(None),
):
    service = get_user_service()
    try:
        data = payload.model_dump(exclude_unset=True) if payload else {}
        update_kwargs = {}
        if "privilege_level" in data:
            update_kwargs["privilege_level"] = data["privilege_level"]
        if "service" in data:
            update_kwargs["service"] = data["service"]
        if "groups" in data:
            update_kwargs["groups"] = data["groups"]
        if "enabled" in data:
            update_kwargs["enabled"] = data["enabled"]
        if "description" in data:
            update_kwargs["description"] = data["description"]

        record = None
        if update_kwargs:
            record = service.update_user(username, **update_kwargs)
        if "password" in data:
            record = service.set_password(username, data["password"])
        if record is None:
            record = service.get_user(username)
        return _user_to_response(record)
    except LocalUserNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    except LocalUserValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update user: {exc}",
        ) from exc


@router.delete(
    "/{username}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete user",
    description="Delete a local user",
)
async def delete_user(
    username: str = PathParam(..., min_length=1, description="Username"),
):
    service = get_user_service()
    try:
        service.delete_user(username)
    except LocalUserNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete user: {exc}",
        ) from exc
    return None
