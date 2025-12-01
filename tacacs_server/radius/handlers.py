import uuid
from typing import Any

from tacacs_server.utils.logger import bind_context, clear_context, get_logger
from tacacs_server.utils.rate_limiter import get_rate_limiter

from .auth import apply_policy, authenticate_user, get_user_attributes
from .authenticator import verify_message_authenticator, verify_request_authenticator
from .constants import (
    ACCT_STATUS_INTERIM_UPDATE,
    ACCT_STATUS_START,
    ACCT_STATUS_STOP,
    ATTR_ACCT_INPUT_OCTETS,
    ATTR_ACCT_OUTPUT_OCTETS,
    ATTR_ACCT_SESSION_ID,
    ATTR_ACCT_SESSION_TIME,
    ATTR_ACCT_STATUS_TYPE,
    ATTR_CALLED_STATION_ID,
    ATTR_MESSAGE_AUTHENTICATOR,
    ATTR_NAS_IP_ADDRESS,
    ATTR_NAS_PORT,
    ATTR_USER_NAME,
    ATTR_USER_PASSWORD,
    RADIUS_ACCESS_REQUEST,
    RADIUS_ACCOUNTING_REQUEST,
    RADIUS_ACCOUNTING_RESPONSE,
)
from .packet import RADIUSPacket
from .response import send_response

logger = get_logger("tacacs_server.radius.handlers", component="radius")


def handle_auth_request(server, data: bytes, addr: tuple[str, int]):
    """Process an incoming Access-Request packet."""
    client_ip, client_port = addr
    connection_id = str(uuid.uuid4())
    ctx_token = None
    try:
        ctx_token = bind_context(
            correlation_id=str(uuid.uuid4()),
            connection_id=connection_id,
            client_ip=client_ip,
            service="radius",
        )
    except Exception:
        ctx_token = None

    limiter = get_rate_limiter()
    if not limiter.allow_request(client_ip):
        logger.warning(
            "RADIUS rate limit exceeded",
            event="radius.auth.rate_limited",
            client_ip=client_ip,
        )
        if ctx_token is not None:
            clear_context(ctx_token)
        return

    try:
        client_config = server.lookup_client(client_ip)
        if not client_config:
            auto_reg = bool(getattr(server, "device_auto_register", False))
            ds = getattr(server, "device_store", None)
            if auto_reg and ds is not None:
                try:
                    group_name = getattr(server, "default_device_group", "default")
                    ds.ensure_group(group_name)
                    cidr = f"{client_ip}/32"
                    if ":" in client_ip:
                        cidr = f"{client_ip}/128"
                    ds.ensure_device(
                        name=f"auto-{client_ip.replace(':', '_')}",
                        network=cidr,
                        group=group_name,
                    )
                    try:
                        configs = ds.iter_radius_clients()
                        server.refresh_clients(configs)
                    except Exception as refresh_clients_exc:
                        logger.warning(
                            "Failed to refresh RADIUS clients",
                            event="radius.client.refresh_failed",
                            error=str(refresh_clients_exc),
                        )
                    client_config = server.lookup_client(client_ip)
                except Exception as exc:
                    logger.warning(
                        "RADIUS auto-registration failed",
                        event="radius.client.auto_registration_failed",
                        client_ip=client_ip,
                        error=str(exc),
                    )
        if not client_config:
            logger.warning(
                "RADIUS auth request from unknown client",
                event="radius.auth.unknown_client",
                client_ip=client_ip,
            )
            server._inc("invalid_packets")
            return

        client_secret = client_config.secret_bytes

        if not verify_message_authenticator(data, client_secret):
            logger.warning(
                "RADIUS auth request with invalid Message-Authenticator",
                event="radius.auth.bad_message_authenticator",
                client_ip=client_ip,
            )
            server._inc("invalid_packets")
            return

        request = RADIUSPacket.unpack(data, client_secret)

        if request.code != RADIUS_ACCESS_REQUEST:
            logger.warning(
                "Unexpected packet code in auth port",
                event="radius.auth.unexpected_code",
                code=request.code,
            )
            return

        server._inc("auth_requests")

        try:
            nas_ip = request.get_string(ATTR_NAS_IP_ADDRESS)
            nas_port = request.get_integer(ATTR_NAS_PORT)
            logger.debug(
                "RADIUS request",
                event="radius.request",
                service="radius",
                code=request.code,
                client={"ip": client_ip, "port": client_port},
                nas_ip=nas_ip,
                nas_port=nas_port,
                client_group=getattr(client_config, "group", None),
            )
        except Exception as debug_logging_exc:
            logger.debug(
                "Failed to log RADIUS request",
                error=str(debug_logging_exc),
            )

        username = request.get_string(ATTR_USER_NAME)
        password_attr = request.get_attribute(ATTR_USER_PASSWORD)
        password = password_attr.as_string() if password_attr else None

        if not username or not password:
            logger.warning(
                "RADIUS auth request missing username or password from %s",
                client_ip,
            )
            response = server.response_builder.create_access_reject(
                request, "Missing credentials"
            )
            if request.get_attribute(ATTR_MESSAGE_AUTHENTICATOR):
                response.add_attribute(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16)
            send_response(
                server.auth_socket,
                server.acct_socket,
                response,
                addr,
                client_secret,
                request.authenticator,
            )
            return

        logger.debug(
            "RADIUS auth request: user=%s from %s (matched %s)",
            username or "<unknown>",
            client_ip,
            client_config.network,
        )

        authenticated, auth_detail = authenticate_user(
            server.auth_backends, username, password
        )

        device_label = (
            client_config.group or client_config.name or str(client_config.network)
        )

        if authenticated:
            denial_reason: str | None = None
            try:
                svc = getattr(server, "local_user_group_service", None)
                if svc is not None and client_config.allowed_user_groups:
                    okta_backends = [
                        b
                        for b in server.auth_backends
                        if getattr(b, "name", "") == "okta"
                    ]
                    backend = okta_backends[0] if okta_backends else None
                    if backend is not None:
                        allowed_targets: set[str] = set()
                        for gname in client_config.allowed_user_groups:
                            try:
                                rec = svc.get_group(gname)
                            except Exception:
                                continue
                            okg = getattr(rec, "okta_group", None)
                            if okg:
                                try:
                                    allowed_targets.add(str(okg).lower())
                                except Exception:
                                    continue
                        if allowed_targets:
                            try:
                                raw_groups = backend.get_user_groups(username)
                                user_groups = {
                                    str(g).lower() for g in (raw_groups or [])
                                }
                            except Exception as e:
                                logger.debug(
                                    "RADIUS Okta group resolution failed",
                                    event="radius.okta.group_resolution_failed",
                                    username=username,
                                    error=str(e),
                                )
                                user_groups = set()
                            if not (allowed_targets & user_groups):
                                denial_reason = "group_not_allowed"
                                authenticated = False
                                auth_detail = "radius_okta_group_not_allowed"
                                logger.warning(
                                    "RADIUS Okta user not in allowed groups",
                                    event="radius.okta.group_not_allowed",
                                    device=device_label,
                                    username=username,
                                    allowed_targets=sorted(list(allowed_targets)),
                                    user_groups=sorted(list(user_groups)),
                                )
            except Exception:
                logger.debug(
                    "RADIUS Okta device-scoped enforcement failed; falling back to policy engine",
                    exc_info=True,
                )

            user_attrs = get_user_attributes(server.auth_backends, username)
            allowed_ok, denial_message = apply_policy(
                client_config, user_attrs, server.auth_services
            )
            if authenticated and allowed_ok and not denial_reason:
                response = server.response_builder.create_access_accept(
                    request, user_attrs
                )
                if request.vsa_attributes:
                    logger.debug(
                        "RADIUS request contained VSAs",
                        event="radius.vsa.received",
                        vsas=[str(vsa) for vsa in request.vsa_attributes],
                        username=username,
                    )
                server._inc("auth_accepts")
                logger.info(
                    "RADIUS authentication success",
                    event="radius.auth.success",
                    username=username,
                    device=device_label,
                    detail=auth_detail,
                )
                try:
                    from ..web.monitoring import PrometheusIntegration

                    PrometheusIntegration.record_radius_auth("accept")
                except Exception as prometheus_integration_exc:
                    logger.warning(
                        "Failed to record RADIUS authentication accept",
                        event="radius.metrics.record_failed",
                        error=str(prometheus_integration_exc),
                    )
            else:
                response = server.response_builder.create_access_reject(
                    request, denial_reason or denial_message
                )
                server._inc("auth_rejects")
                logger.warning(
                    "RADIUS authentication failed",
                    event="radius.auth.failure",
                    username=username,
                    reason=denial_reason or denial_message,
                    device=device_label,
                )
                try:
                    from ..web.monitoring import PrometheusIntegration

                    PrometheusIntegration.record_radius_auth("reject")
                except Exception as prometheus_integration_exc:
                    logger.warning(
                        "Failed to record RADIUS authentication reject",
                        event="radius.metrics.record_failed",
                        error=str(prometheus_integration_exc),
                    )
        else:
            response = server.response_builder.create_access_reject(
                request, "Authentication failed"
            )
            server._inc("auth_rejects")
            logger.warning(
                "RADIUS authentication failed",
                event="radius.auth.failure",
                username=username,
                reason=auth_detail or "no backend accepted credentials",
                device=device_label,
            )
            try:
                from ..web.monitoring import PrometheusIntegration

                PrometheusIntegration.record_radius_auth("reject")
            except Exception as prometheus_integration_exc:
                logger.warning(
                    "Failed to record RADIUS authentication reject",
                    event="radius.metrics.record_failed",
                    error=str(prometheus_integration_exc),
                )

        if request.get_attribute(ATTR_MESSAGE_AUTHENTICATOR):
            response.add_attribute(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16)

        send_response(
            server.auth_socket,
            server.acct_socket,
            response,
            addr,
            client_secret,
            request.authenticator,
        )

    except Exception as e:
        logger.error(
            "Error handling RADIUS auth request",
            event="radius.auth.unhandled_error",
            client_ip=client_ip,
            error=str(e),
        )
        server._inc("invalid_packets")
    finally:
        if ctx_token is not None:
            try:
                clear_context(ctx_token)
            except Exception as context_cleanup_exc:
                logger.debug(
                    "Failed to cleanup correlation context",
                    error=str(context_cleanup_exc),
                )


def handle_acct_request(server, data: bytes, addr: tuple[str, int]):
    """Process an incoming Accounting-Request packet."""
    client_ip, client_port = addr
    connection_id = str(uuid.uuid4())
    ctx_token = None
    try:
        ctx_token = bind_context(
            correlation_id=str(uuid.uuid4()),
            connection_id=connection_id,
            client_ip=client_ip,
            service="radius",
        )
    except Exception:
        ctx_token = None

    limiter = get_rate_limiter()
    if not limiter.allow_request(client_ip):
        logger.warning(
            "RADIUS acct rate limit exceeded",
            event="radius.acct.rate_limited",
            client_ip=client_ip,
        )
        if ctx_token is not None:
            clear_context(ctx_token)
        return

    try:
        client_config = server.lookup_client(client_ip)
        if not client_config:
            auto_reg = bool(getattr(server, "device_auto_register", False))
            ds = getattr(server, "device_store", None)
            if auto_reg and ds is not None:
                try:
                    group_name = getattr(server, "default_device_group", "default")
                    ds.ensure_group(group_name)
                    cidr = f"{client_ip}/32"
                    if ":" in client_ip:
                        cidr = f"{client_ip}/128"
                    ds.ensure_device(
                        name=f"auto-{client_ip.replace(':', '_')}",
                        network=cidr,
                        group=group_name,
                    )
                    try:
                        configs = ds.iter_radius_clients()
                        server.refresh_clients(configs)
                    except Exception as refresh_clients_exc:
                        logger.warning(
                            "Failed to refresh RADIUS clients",
                            event="radius.client.refresh_failed",
                            error=str(refresh_clients_exc),
                        )
                    client_config = server.lookup_client(client_ip)
                except Exception as exc:
                    logger.warning(
                        "RADIUS auto-registration failed",
                        event="radius.client.auto_registration_failed",
                        client_ip=client_ip,
                        error=str(exc),
                    )
        if not client_config:
            logger.warning(
                "RADIUS acct request from unknown client",
                event="radius.acct.unknown_client",
                client_ip=client_ip,
            )
            server._inc("invalid_packets")
            return

        client_secret = client_config.secret_bytes

        if not verify_request_authenticator(data, client_secret):
            logger.warning(
                "RADIUS acct request with invalid Request Authenticator",
                event="radius.acct.invalid_authenticator",
                client_ip=client_ip,
            )
            server._inc("invalid_packets")
            return

        try:
            request = RADIUSPacket.unpack(data, client_secret)
        except ValueError as e:
            logger.warning(
                "Invalid RADIUS packet",
                event="radius.packet.invalid",
                client_ip=client_ip,
                error=str(e),
            )
            server._inc("invalid_packets")
            return

        if request.code != RADIUS_ACCOUNTING_REQUEST:
            logger.warning(
                "Unexpected packet code in acct port",
                event="radius.acct.unexpected_code",
                code=request.code,
            )
            server._inc("invalid_packets")
            return

        server._inc("acct_requests")

        username = request.get_string(ATTR_USER_NAME)
        session_id = request.get_string(ATTR_ACCT_SESSION_ID)
        status_type = request.get_integer(ATTR_ACCT_STATUS_TYPE)

        status_names = {
            1: "START",
            2: "STOP",
            3: "UPDATE",
            7: "ACCOUNTING-ON",
            8: "ACCOUNTING-OFF",
        }
        status_name = status_names.get(status_type or -1, f"UNKNOWN({status_type})")

        logger.info(
            "RADIUS accounting received",
            event="radius.acct.received",
            username=username,
            session=session_id,
            status=status_name,
            client_ip=client_ip,
            client_network=str(client_config.network),
        )

        try:
            logger.debug(
                "RADIUS accounting request",
                event="radius.request",
                code=RADIUS_ACCOUNTING_REQUEST,
                client={"ip": client_ip, "port": client_port},
                username=username,
                session=session_id,
                status=status_name,
                client_group=getattr(client_config, "group", None),
            )
        except Exception as debug_logging_exc:
            logger.warning(
                "Failed to log RADIUS accounting request",
                event="radius.acct.log_failed",
                error=str(debug_logging_exc),
            )

        if server.accounting_logger:
            log_accounting_record(request, client_ip, server.accounting_logger)

        response = RADIUSPacket(
            code=RADIUS_ACCOUNTING_RESPONSE,
            identifier=request.identifier,
            authenticator=bytes(16),
        )

        send_response(
            server.auth_socket,
            server.acct_socket,
            response,
            addr,
            client_secret,
            request.authenticator,
        )
        server._inc("acct_responses")
        try:
            logger.debug(
                "RADIUS accounting response",
                event="radius.reply",
                code=RADIUS_ACCOUNTING_RESPONSE,
                client={"ip": client_ip, "port": client_port},
                username=username,
                session=session_id,
                status=status_name,
            )
        except Exception as debug_logging_exc:
            logger.warning(
                "Failed to log RADIUS accounting response",
                event="radius.acct.response_log_failed",
                error=str(debug_logging_exc),
            )

    except Exception as e:
        logger.error(
            "Error handling RADIUS acct request",
            event="radius.acct.unhandled_error",
            client_ip=client_ip,
            error=str(e),
        )
    finally:
        if ctx_token is not None:
            try:
                clear_context(ctx_token)
            except Exception as context_cleanup_exc:
                logger.debug(
                    "Failed to cleanup correlation context",
                    error=str(context_cleanup_exc),
                )


def log_accounting_record(
    request: RADIUSPacket, client_ip: str, accounting_logger: Any
):
    """Log accounting information to database."""
    try:
        from ..accounting.models import AccountingRecord

        username = request.get_string(ATTR_USER_NAME) or "unknown"
        session_id_str = request.get_string(ATTR_ACCT_SESSION_ID) or "0"
        status_type = request.get_integer(ATTR_ACCT_STATUS_TYPE)

        status_map = {
            ACCT_STATUS_START: "START",
            ACCT_STATUS_STOP: "STOP",
            ACCT_STATUS_INTERIM_UPDATE: "UPDATE",
        }
        status = status_map.get(int(status_type or -1), "UNKNOWN")

        try:
            session_id = (
                int(session_id_str)
                if session_id_str.isdigit()
                else hash(session_id_str) & 0xFFFFFFFF
            )
        except Exception:
            session_id = hash(session_id_str) & 0xFFFFFFFF

        record = AccountingRecord(
            username=username,
            session_id=session_id,
            status=status,
            service="radius",
            command=f"RADIUS {status}",
            client_ip=client_ip,
            port=request.get_string(ATTR_CALLED_STATION_ID),
            bytes_in=request.get_integer(ATTR_ACCT_INPUT_OCTETS) or 0,
            bytes_out=request.get_integer(ATTR_ACCT_OUTPUT_OCTETS) or 0,
            elapsed_time=request.get_integer(ATTR_ACCT_SESSION_TIME) or 0,
        )
        accounting_logger.log_accounting(record)

    except Exception as e:
        logger.error(
            "Error logging RADIUS accounting",
            event="radius.accounting.log_error",
            error=str(e),
        )


__all__ = [
    "handle_auth_request",
    "handle_acct_request",
    "log_accounting_record",
]
