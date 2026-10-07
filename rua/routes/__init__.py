"""HTTP routers."""

from rua.routes.auth import router as auth_router
from rua.routes.pages import router as pages_router
from rua.routes.setup import router as setup_router

__all__ = ["auth_router", "pages_router", "setup_router"]
