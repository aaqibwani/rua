"""HTTP routers."""

from rua.routes.pages import router as pages_router
from rua.routes.setup import router as setup_router

__all__ = ["pages_router", "setup_router"]
