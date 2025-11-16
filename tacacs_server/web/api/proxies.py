# tacacs_server/web/api/proxies.py

from importlib import import_module

from fastapi import APIRouter, HTTPException, Query, status

from tacacs_server.utils.logger import get_logger

from ...devices.service import DeviceService, DeviceValidationError
from ..api_models import BaseModel, Field
from .device_groups import get_device_service

router = APIRouter(prefix="/api/proxies", tags=["Proxies"])

logger = get_logger("tacacs.api.proxies")


class ProxyCreate(BaseModel):
    name: str = Field(..., description="Proxy name", example="Proxy-A")
    network: str = Field(..., description="Proxy network CIDR", example="10.0.0.0/8")
    metadata: dict[str, object] | None = Field(default=None, description="Metadata")


class ProxyUpdate(BaseModel):
    name: str | None = Field(None, description="New name")
    network: str | None = Field(None, description="New network CIDR")
    metadata: dict[str, object] | None = Field(None, description="New metadata")


class ProxyResponse(BaseModel):
    id: int
    name: str
    network: str
    metadata: dict[str, object] | None = None


def _to_resp(p) -> ProxyResponse:
    return ProxyResponse(
        id=p.id, name=p.name, network=str(p.network), metadata=p.metadata
    )


def _get_config_lazy():
    """Lazily import monitoring.get_config to avoid circular imports."""
    try:
        mon = import_module("tacacs_server.web.web")
        cfg = getattr(mon, "get_config", lambda: None)()
        if cfg is None:
            logger.debug(
                "Proxy configuration not available from web module; get_config() returned None"
            )
        return cfg
    except Exception as exc:
        logger.debug("Failed to import proxy configuration accessor: %s", exc)
        return None


def _ensure_enabled():
    cfg = _get_config_lazy()
    if cfg is None:
        logger.debug(
            "Proxy feature check skipped because configuration service is unavailable"
        )
        return
    try:
        net = cfg.get_server_network_config()
        if not bool(net.get("proxy_enabled", False)):
            logger.info("Proxy functionality disabled by configuration")
            raise HTTPException(status_code=503, detail="Proxy functionality disabled")
    except Exception as cfg_exc:
        logger.debug("Failed to get proxy configuration status: %s", cfg_exc)


@router.get(
    "",
    response_model=list[ProxyResponse],
    summary="List proxies",
    description="Return configured TACACS+/RADIUS proxies (requires proxy feature enabled)",
)
async def list_proxies(limit: int = Query(100, ge=1, le=1000)):
    _ensure_enabled()
    logger.info("Listing proxies (limit=%d)", limit)
    svc: DeviceService = get_device_service()
    items = svc.list_proxies()[:limit]
    logger.debug("Returning %d proxies", len(items))
    return [_to_resp(p) for p in items]


@router.post(
    "",
    response_model=ProxyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create proxy",
    description="Create a new proxy with name and network CIDR",
)
async def create_proxy(payload: ProxyCreate):
    _ensure_enabled()
    logger.info("Creating proxy name=%s network=%s", payload.name, payload.network)
    svc: DeviceService = get_device_service()
    try:
        p = svc.create_proxy(
            payload.name, payload.network, metadata=payload.metadata or {}
        )
        logger.info("Proxy created id=%s name=%s", p.id, p.name)
        return _to_resp(p)
    except DeviceValidationError as e:
        logger.warning("Proxy creation failed validation: %s", e)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("Unexpected error creating proxy")
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/{proxy_id}",
    response_model=ProxyResponse,
    summary="Get proxy",
    description="Get a proxy by ID",
)
async def get_proxy(proxy_id: int):
    _ensure_enabled()
    logger.info("Fetching proxy id=%s", proxy_id)
    svc: DeviceService = get_device_service()
    try:
        p = svc.get_proxy(proxy_id)
        logger.debug("Proxy fetched id=%s name=%s", p.id, p.name)
        return _to_resp(p)
    except DeviceValidationError as e:
        logger.warning("Proxy not found: %s (id=%s)", e, proxy_id)
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception("Unexpected error fetching proxy id=%s", proxy_id)
        raise HTTPException(status_code=500, detail=str(e))


@router.put(
    "/{proxy_id}",
    response_model=ProxyResponse,
    summary="Update proxy",
    description="Update proxy name, network, or metadata",
)
async def update_proxy(proxy_id: int, payload: ProxyUpdate):
    _ensure_enabled()
    logger.info(
        "Updating proxy id=%s fields name=%s network=%s has_metadata=%s",
        proxy_id,
        payload.name is not None,
        payload.network is not None,
        payload.metadata is not None,
    )
    svc: DeviceService = get_device_service()
    try:
        p = svc.update_proxy(
            proxy_id,
            name=payload.name,
            network=payload.network,
            metadata=payload.metadata,
        )
        logger.info("Proxy updated id=%s name=%s", p.id, p.name)
        return _to_resp(p)
    except DeviceValidationError as e:
        logger.warning(
            "Proxy update failed validation/not found: %s (id=%s)",
            e,
            proxy_id,
        )
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception("Unexpected error updating proxy id=%s", proxy_id)
        raise HTTPException(status_code=500, detail=str(e))


@router.delete(
    "/{proxy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete proxy",
    description="Delete a proxy by ID",
)
async def delete_proxy(proxy_id: int):
    _ensure_enabled()
    logger.info("Deleting proxy id=%s", proxy_id)
    svc: DeviceService = get_device_service()
    ok = svc.delete_proxy(proxy_id)
    if not ok:
        logger.warning("Proxy delete requested but not found (id=%s)", proxy_id)
        raise HTTPException(status_code=404, detail="Proxy not found")
    logger.info("Proxy deleted id=%s", proxy_id)
    return None
