from .auth import router as auth_router
from .frontend import router as frontend_router
from .backend import router as backend_router
from .cluster import router as cluster_router
from .dashboard import router as dashboard_router
from .agent import router as agent_router
from .waf import router as waf_router
from .ssl import router as ssl_router
from .user import router as user_router

__all__ = [
    "auth_router",
    "frontend_router",
    "backend_router", 
    "cluster_router",
    "dashboard_router",
    "agent_router",
    "waf_router",
    "ssl_router",
    "user_router"
]
