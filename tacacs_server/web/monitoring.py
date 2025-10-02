"""
Web Monitoring Interface for TACACS+ Server
Provides both HTML dashboard and Prometheus metrics endpoint
"""

import asyncio
import threading
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

from tacacs_server.utils.logger import get_logger
from tacacs_server.utils.metrics_history import get_metrics_history

logger = get_logger(__name__)

_device_service: Optional["DeviceService"] = None
_local_user_service: Optional["LocalUserService"] = None
_local_user_group_service: Optional["LocalUserGroupService"] = None
_config: Optional["TacacsConfig"] = None
_tacacs_server_ref = None
_radius_server_ref = None
_admin_auth_dependency: Callable[[Request], Awaitable[None]] | None = None
_admin_session_manager: Optional["AdminSessionManager"] = None


def get_device_service() -> Optional["DeviceService"]:
    return _device_service


def set_device_service(service: Optional["DeviceService"]) -> None:
    global _device_service
    _device_service = service


def get_local_user_service() -> Optional["LocalUserService"]:
    return _local_user_service


def set_local_user_service(service: Optional["LocalUserService"]) -> None:
    global _local_user_service
    _local_user_service = service


def get_local_user_group_service() -> Optional["LocalUserGroupService"]:
    return _local_user_group_service


def set_local_user_group_service(service: Optional["LocalUserGroupService"]) -> None:
    global _local_user_group_service
    _local_user_group_service = service


def set_config(config: Optional["TacacsConfig"]) -> None:
    global _config
    _config = config


def get_config() -> Optional["TacacsConfig"]:
    return _config


def set_tacacs_server(server) -> None:
    global _tacacs_server_ref
    _tacacs_server_ref = server


def get_tacacs_server():
    return _tacacs_server_ref


def set_radius_server(server) -> None:
    global _radius_server_ref
    _radius_server_ref = server


def get_radius_server():
    return _radius_server_ref


def set_admin_auth_dependency(
    dependency: Callable[[Request], Awaitable[None]] | None
) -> None:
    global _admin_auth_dependency
    _admin_auth_dependency = dependency


def get_admin_auth_dependency_func() -> (
    Callable[[Request], Awaitable[None]] | None
):
    return _admin_auth_dependency


def set_admin_session_manager(manager: Optional["AdminSessionManager"]) -> None:
    global _admin_session_manager
    _admin_session_manager = manager


def get_admin_session_manager() -> Optional["AdminSessionManager"]:
    return _admin_session_manager


if TYPE_CHECKING:
    from tacacs_server.auth.local_user_group_service import LocalUserGroupService
    from tacacs_server.auth.local_user_service import LocalUserService
    from tacacs_server.config.config import TacacsConfig
    from tacacs_server.devices.service import DeviceService

    from .admin.auth import AdminSessionManager

# Prometheus Metrics
auth_requests_total = Counter(
    'tacacs_auth_requests_total', 
    'Total authentication requests', 
    ['status', 'backend']
)
auth_duration = Histogram(
    'tacacs_auth_duration_seconds', 'Authentication request duration'
)
active_connections = Gauge('tacacs_active_connections', 'Number of active connections')
server_uptime = Gauge('tacacs_server_uptime_seconds', 'Server uptime in seconds')
accounting_records = Counter(
    'tacacs_accounting_records_total', 'Total accounting records', ['status']
)
radius_auth_requests = Counter(
    'radius_auth_requests_total', 'RADIUS authentication requests', ['status']
)
radius_acct_requests = Counter(
    'radius_acct_requests_total', 'RADIUS accounting requests', ['type']
)
radius_active_clients = Gauge(
    'radius_active_clients', 'Number of configured RADIUS clients'
)


class TacacsMonitoringAPI:
    """Web monitoring interface for TACACS+ server"""
    
    def __init__(self, tacacs_server, host="127.0.0.1", port=8080, radius_server=None):
        self.tacacs_server = tacacs_server
        self.radius_server = radius_server
        set_tacacs_server(tacacs_server)
        set_radius_server(radius_server)
        self.host = host
        self.port = port
        self.app = FastAPI(title="TACACS+ Server Monitor", version="1.0.0")

        # Use package-relative paths for templates/static so it works regardless of CWD
        pkg_root = Path(__file__).resolve().parent.parent
        templates_dir = pkg_root / "templates"
        static_dir = pkg_root / "static"

        self.templates = Jinja2Templates(directory=str(templates_dir))
        # mount static files using package-relative path only once
        self.app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

        self.setup_routes()
        self.server = None
        self.server_thread = None
    
    def setup_routes(self):
        """Setup API routes"""
        
        # static already mounted in __init__ with package-relative path
        
        # WebSocket endpoint for real-time updates
        @self.app.websocket("/ws/metrics")
        async def websocket_metrics(websocket: WebSocket):
            """WebSocket endpoint for real-time metrics"""
            await websocket.accept()
            try:
                while True:
                    stats = self.get_server_stats()
                    await websocket.send_json({
                        "type": "metrics_update",
                        "data": stats,
                        "timestamp": datetime.now().isoformat()
                    })
                    await asyncio.sleep(2)  # Update every 2 seconds
            except WebSocketDisconnect:
                logger.debug("WebSocket client disconnected")
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                await websocket.close()
        
        # HTML Dashboard
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard(request: Request):
            """Main monitoring dashboard"""
            try:
                stats = self.get_server_stats()
                return self.templates.TemplateResponse("dashboard.html", {
                    "request": request,
                    "stats": stats,
                    "timestamp": datetime.now().isoformat(),
                    "websocket_enabled": True
                })
            except Exception as e:
                logger.error(f"Dashboard error: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        # API Endpoints
        @self.app.get("/api/status")
        async def api_status():
            """Server status API"""
            return self.get_server_stats()
        
        @self.app.get("/api/metrics/history")
        async def api_metrics_history(hours: int = 24):
            """Historical metrics data"""
            try:
                history = get_metrics_history()
                data = history.get_historical_data(hours)
                summary = history.get_summary_stats(hours)
                return {
                    "data": data,
                    "summary": summary,
                    "period_hours": hours
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/health")
        async def api_health():
            """Health check endpoint"""
            try:
                health = self.tacacs_server.get_health_status()
                return health
            except Exception as e:
                raise HTTPException(status_code=503, detail=f"Health check failed: {e}")
        
        @self.app.get("/api/stats")
        async def api_stats():
            """Detailed server statistics"""
            return {
                "server": self.get_server_stats(),
                "backends": self.get_backend_stats(),
                "database": self.get_database_stats(),
                "sessions": self.get_session_stats()
            }
        
        @self.app.get("/api/backends")
        async def api_backends():
            """Authentication backends status"""
            return self.get_backend_stats()
        
        @self.app.get("/api/sessions")
        async def api_sessions():
            """Active sessions"""
            return self.get_session_stats()
        
        @self.app.get("/api/accounting")
        async def api_accounting(hours: int = 24, limit: int = 100):
            """Recent accounting records"""
            try:
                since = datetime.now() - timedelta(hours=hours)
                # This would need to be implemented in your database logger
                records = self.tacacs_server.db_logger.get_recent_records(since, limit)
                return {
                    "records": records,
                    "count": len(records),
                    "period_hours": hours
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        # Prometheus Metrics Endpoint
        @self.app.get("/metrics", response_class=PlainTextResponse)
        async def metrics():
            """Prometheus metrics endpoint"""
            try:
                # Update metrics before serving
                self.update_prometheus_metrics()
                # generate_latest() returns bytes — ensure proper media type
                data = generate_latest()
                return PlainTextResponse(content=data, media_type=CONTENT_TYPE_LATEST)
            except Exception as e:
                logger.error(f"Metrics generation error: {e}")
                raise HTTPException(status_code=500, detail="Metrics unavailable")
        
        # Control Endpoints (Admin)
        @self.app.post("/api/admin/reload-config")
        async def reload_config():
            """Reload server configuration"""
            try:
                success = self.tacacs_server.reload_configuration()
                message = "Configuration reloaded" if success else "Reload failed"
                return {"success": success, "message": message}
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/admin/reset-stats")
        async def reset_stats():
            """Reset server statistics"""
            try:
                self.tacacs_server.reset_stats()
                return {"success": True, "message": "Statistics reset"}
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/admin/logs")
        async def get_logs(lines: int = 100):
            """Get recent log entries"""
            try:
                # This would read from your log file
                logs = self.get_recent_logs(lines)
                return {"logs": logs, "count": len(logs)}
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        # Admin API router
        try:
            from .admin import admin_router

            self.app.include_router(admin_router)
        except Exception as exc:
            logger.warning("Failed to include admin router: %s", exc)

        if self.radius_server:
            @self.app.get("/api/radius/status")
            async def radius_status():
                """RADIUS server status"""
                return self.get_radius_stats()
            
            @self.app.get("/api/radius/clients")
            async def radius_clients():
                """RADIUS clients """
                clients = []
                try:
                    clients = [
                        {
                            'network': str(client.network),
                            'name': client.name,
                            'group': client.group,
                            'secret_length': len(client.secret),
                            'attributes': client.attributes,
                        }
                        for client in getattr(self.radius_server, 'clients', [])
                    ]
                except Exception as exc:
                    logger.warning("Failed to enumerate RADIUS clients: %s", exc)
                return {
                    'clients': clients
                }
    
    def get_server_stats(self) -> dict[str, Any]:
        """Get current server statistics"""
        try:
            stats = self.tacacs_server.get_stats()
            health = self.tacacs_server.get_health_status()

            data = {
                "status": "running" if self.tacacs_server.running else "stopped",
                "uptime": health.get('uptime_seconds', 0),
                "connections": {
                    "active": stats.get('connections_active', 0),
                    "total": stats.get('connections_total', 0)
                },
                "authentication": {
                    "requests": stats.get('auth_requests', 0),
                    "successes": stats.get('auth_success', 0),
                    "failures": stats.get('auth_failures', 0),
                    "success_rate": self.calculate_success_rate(
                        stats.get('auth_success', 0), 
                        stats.get('auth_requests', 0)
                    )
                },
                "authorization": {
                    "requests": stats.get('author_requests', 0),
                    "successes": stats.get('author_success', 0),
                    "failures": stats.get('author_failures', 0),
                    "success_rate": self.calculate_success_rate(
                        stats.get('author_success', 0), 
                        stats.get('author_requests', 0)
                    )
                },
                "accounting": {
                    "requests": stats.get('acct_requests', 0),
                    "successes": stats.get('acct_success', 0),
                    "failures": stats.get('acct_failures', 0)
                },
                "memory": health.get('memory_usage', {}),
                "timestamp": datetime.now().isoformat()
            }

            if self.radius_server:
                data['radius'] = self.get_radius_stats()

            return data
        except Exception as e:
            logger.error(f"Error getting server stats: {e}")
            return {"error": str(e)}
    
    def get_backend_stats(self) -> list[dict[str, Any]]:
        """Get authentication backend statistics"""
        backends = []
        try:
            for backend in self.tacacs_server.auth_backends:
                backend_info = {
                    "name": backend.name,
                    "type": backend.__class__.__name__,
                    "available": backend.is_available(),
                    "stats": getattr(backend, 'get_stats', lambda: {})()
                }
                backends.append(backend_info)
        except Exception as e:
            logger.error(f"Error getting backend stats: {e}")
        
        return backends
    
    def get_database_stats(self) -> dict[str, Any]:
        """Get database statistics"""
        try:
            return self.tacacs_server.db_logger.get_statistics(days=30)
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            return {"error": str(e)}
    
    def get_session_stats(self) -> dict[str, Any]:
        """Get active session statistics"""
        try:
            active_sessions = self.tacacs_server.get_active_sessions()
            return {
                "active_count": len(active_sessions),
                "sessions": active_sessions[:20],  # Limit to recent 20
                "total_shown": min(len(active_sessions), 20)
            }
        except Exception as e:
            logger.error(f"Error getting session stats: {e}")
            return {"error": str(e)}
    
    def get_recent_logs(self, lines: int = 100) -> list[str]:
        """Get recent log entries"""
        try:
            # Read from log file - this is a simple implementation
            log_file = "logs/tacacs.log"
            with open(log_file) as f:
                all_lines = f.readlines()
                return [line.strip() for line in all_lines[-lines:]]
        except Exception as e:
            logger.warning(f"Could not read logs: {e}")
            return ["Log file not available"]
    
    def calculate_success_rate(self, successes: int, total: int) -> float:
        """Calculate success rate percentage"""
        return round((successes / total * 100) if total > 0 else 0, 2)
    
    def update_prometheus_metrics(self):
        """
        Collect runtime stats from the running TACACS server and update 
        Prometheus metrics. Also record historical data.
        """
        try:
            if not self.tacacs_server:
                logger.debug(
                    "Monitoring: no tacacs_server bound, skipping metrics update"
                )
                return

            stats = None
            if hasattr(self.tacacs_server, "get_stats"):
                stats = self.tacacs_server.get_stats()
            elif (hasattr(self.tacacs_server, "server") and 
                  hasattr(self.tacacs_server.server, "get_stats")):
                stats = self.tacacs_server.server.get_stats()
            else:
                logger.debug(
                    "Monitoring: tacacs_server has no get_stats(), "
                    "skipping metrics update"
                )
                return

            if not stats:
                logger.debug(
                    "Monitoring: stats object empty/None, skipping metrics update"
                )
                return

            # Record historical metrics
            try:
                import psutil
                memory_info = psutil.virtual_memory()
                cpu_percent = psutil.cpu_percent(interval=0.0)
                
                metrics_data = {
                    **stats,
                    'memory_usage_mb': memory_info.used / 1024 / 1024,
                    'cpu_percent': cpu_percent
                }
                
                history = get_metrics_history()
                history.record_snapshot(metrics_data)
            except Exception as e:
                logger.debug(f"Failed to record historical metrics: {e}")

        except Exception as exc:
            logger.exception("Error updating Prometheus metrics: %s", exc)
    
    def start(self):
        """Start the monitoring web server"""
        if self.server_thread and self.server_thread.is_alive():
            logger.warning("Monitoring server is already running")
            return True

        def run_server():
            """Run the FastAPI server in a separate thread"""
            try:
                logger.info(
                    "Starting uvicorn for monitoring on %s:%s", self.host, self.port
                )
                config = uvicorn.Config(
                    self.app, host=self.host, port=self.port, 
                    log_level="warning", access_log=False
                )
                server = uvicorn.Server(config)
                # keep reference so we can signal shutdown later
                self.server = server
                # create and set a fresh event loop for this thread
                asyncio.set_event_loop(asyncio.new_event_loop())
                server.run()
                logger.info("uvicorn monitoring exited")
            except Exception as e:
                logger.exception("Monitoring server error: %s", e)

        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        # short wait to allow uvicorn to bind
        time.sleep(0.2)
        if self.server_thread.is_alive():
            logger.info(
                "Monitoring interface started at http://%s:%s", self.host, self.port
            )
            return True
        else:
            logger.error("Monitoring thread did not start")
            return False

    def stop(self):
        """Stop the monitoring web server"""
        if self.server:
            try:
                logger.info("Signalling uvicorn monitoring to stop")
                self.server.should_exit = True
            except Exception:
                logger.exception("Failed to signal uvicorn to stop")
        # join thread briefly
        try:
            if self.server_thread:
                self.server_thread.join(timeout=1.0)
        except Exception:
            pass
        logger.info("Monitoring interface stopped")

    def get_radius_stats(self) -> dict[str, Any]:
        """Get RADIUS server statistics"""
        if not self.radius_server:
            return {'enabled': False}
        
        stats = self.radius_server.get_stats()
        return {
            'enabled': True,
            'running': stats['running'],
            'authentication': {
                'requests': stats['auth_requests'],
                'accepts': stats['auth_accepts'],
                'rejects': stats['auth_rejects'],
                'success_rate': stats['auth_success_rate']
            },
            'accounting': {
                'requests': stats['acct_requests'],
                'responses': stats['acct_responses']
            },
            'clients': stats['configured_clients'],
            'invalid_packets': stats['invalid_packets']
        }
    
# Metrics Integration for TACACS+ Server
class PrometheusIntegration:
    """Integration helper for Prometheus metrics"""
    
    @staticmethod
    def record_auth_request(status: str, backend: str, duration: float):
        """Record authentication request metrics"""
        auth_requests_total.labels(status=status, backend=backend).inc()
        auth_duration.observe(duration)
    
    @staticmethod
    def record_accounting_record(status: str):
        """Record accounting metrics"""
        accounting_records.labels(status=status).inc()
    
    @staticmethod
    def update_active_connections(count: int):
        """Update active connections gauge"""
        active_connections.set(count)

    @staticmethod
    def record_radius_auth(status: str):
        """Record RADIUS authentication"""
        radius_auth_requests.labels(status=status).inc()
    
    @staticmethod
    def record_radius_accounting(acct_type: str):
        """Record RADIUS accounting"""
        radius_acct_requests.labels(type=acct_type).inc()
    
    @staticmethod
    def update_radius_clients(count: int):
        """Update RADIUS clients count"""
        radius_active_clients.set(count)


# HTML Template for Dashboard
DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TACACS+ Server Monitor</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background-color: #f5f5f5; 
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 30px; }
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .stat-card { 
            background: white; 
            padding: 20px; 
            border-radius: 8px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
        }
        .stat-title { font-size: 14px; color: #666; margin-bottom: 8px; }
        .stat-value { font-size: 24px; font-weight: bold; color: #333; }
        .stat-success { color: #28a745; }
        .stat-error { color: #dc3545; }
        .stat-warning { color: #ffc107; }
        .chart-container { 
            background: white; 
            padding: 20px; 
            border-radius: 8px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
            margin-bottom: 20px; 
        }
        .status-online { color: #28a745; }
        .status-offline { color: #dc3545; }
        .backend-list { list-style: none; padding: 0; }
        .backend-item { padding: 8px; border-left: 4px solid #ddd; margin-bottom: 8px; }
        .backend-available { border-left-color: #28a745; }
        .backend-unavailable { border-left-color: #dc3545; }
        .refresh-btn { 
            background: #007bff; 
            color: white; 
            padding: 10px 20px; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer; 
        }
        .refresh-btn:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>TACACS+ Server Monitor</h1>
            <p class="status-{{
                'online' if stats.status == 'running' else 'offline' 
            }}">
                Server Status: {{ stats.status.upper() }}
            </p>
            <button class="refresh-btn" onclick="location.reload()">Refresh</button>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-title">Uptime</div>
                <div class="stat-value">
                    {{ (stats.uptime // 3600) }}h {{ ((stats.uptime % 3600) // 60) }}m
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-title">Active Connections</div>
                <div class="stat-value">{{ stats.connections.active }}</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-title">Auth Success Rate</div>
                <div class="stat-value stat-{{
                    'success' if stats.authentication.success_rate > 90 
                    else 'warning' if stats.authentication.success_rate > 70 
                    else 'error' 
                }}">
                    {{ stats.authentication.success_rate }}%
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-title">Memory Usage</div>
                <div class="stat-value">{{ stats.memory.rss_mb }}MB</div>
            </div>
        </div>

        <div class="chart-container">
            <h3>Authentication Statistics</h3>
            <canvas id="authChart" width="400" height="200"></canvas>
        </div>

        <div class="chart-container">
            <h3>Authentication Backends</h3>
            <ul class="backend-list" id="backendList">
                <!-- Populated by JavaScript -->
            </ul>
        </div>
    </div>

    <script>
        // Chart.js setup
        const ctx = document.getElementById('authChart').getContext('2d');
        const authChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Success', 'Failed'],
                datasets: [{
                    data: [
                        {{ stats.authentication.successes }}, 
                        {{ stats.authentication.failures }}
                    ],
                    backgroundColor: ['#28a745', '#dc3545']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });

        // WebSocket connection for real-time updates
        let ws = null;
        let reconnectAttempts = 0;
        const maxReconnectAttempts = 5;
        
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws/metrics`;
            
            ws = new WebSocket(wsUrl);
            
            ws.onopen = function() {
                console.log('WebSocket connected');
                reconnectAttempts = 0;
            };
            
            ws.onmessage = function(event) {
                const message = JSON.parse(event.data);
                if (message.type === 'metrics_update') {
                    updateDashboard(message.data);
                }
            };
            
            ws.onclose = function() {
                console.log('WebSocket disconnected');
                if (reconnectAttempts < maxReconnectAttempts) {
                    setTimeout(() => {
                        reconnectAttempts++;
                        connectWebSocket();
                    }, 2000 * reconnectAttempts);
                } else {
                    // Fallback to page refresh
                    setInterval(() => location.reload(), 30000);
                }
            };
        }
        
        function updateDashboard(stats) {
            // Update connection count
            const activeConnEl = document.querySelector('.stat-value');
            if (activeConnEl) {
                activeConnEl.textContent = stats.connections.active;
            }
            
            // Update success rate
            const successRateEl = document.querySelectorAll('.stat-value')[2];
            if (successRateEl) {
                successRateEl.textContent = stats.authentication.success_rate + '%';
            }
            
            // Update chart data
            authChart.data.datasets[0].data = [
                stats.authentication.successes,
                stats.authentication.failures
            ];
            authChart.update('none'); // No animation for real-time updates
        }
        
        // Initialize WebSocket connection
        connectWebSocket();

        // Load backend information
        fetch('/api/backends')
            .then(response => response.json())
            .then(backends => {
                const backendList = document.getElementById('backendList');
                backendList.innerHTML = '';
                backends.forEach(backend => {
                    const li = document.createElement('li');
                    li.className = `backend-item ${
                        backend.available ? 'backend-available' : 'backend-unavailable'
                    }`;
                    // Sanitize backend data to prevent XSS
                    const safeName = document.createTextNode(backend.name).textContent;
                    const safeType = document.createTextNode(backend.type).textContent;
                    const statusText = backend.available ? 'Available' : 'Unavailable';
                    
                    const nameEl = document.createElement('strong');
                    nameEl.textContent = safeName;
                    
                    li.appendChild(nameEl);
                    li.appendChild(
                        document.createTextNode(` (${safeType}) - ${statusText}`)
                    );
                    backendList.appendChild(li);
                });
            });
    </script>
</body>
</html>
'''
