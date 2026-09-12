"""Single-process, single-port transport: FastAPI PIP routes + MCP at /mcp.

For PaaS deployments (e.g. Fly.io) that expose one port and terminate TLS at
the platform. The FastAPI routes (`/healthz`, `/.well-known/pip`,
`/pip/v1/inbox`, `/metrics`) win; everything else falls through to the mounted
MCP app (`/mcp`). The MCP app's own `/healthz` is shadowed — the FastAPI one
answers instead.
"""

from fastapi import FastAPI

from ..config import Settings
from ..mcp_server import build_mcp_http_app, create_mcp_server
from ..node import Node
from .http import create_app


def create_combined_app(node: Node, settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    mcp_app = build_mcp_http_app(create_mcp_server(node, settings), settings.http_bearer_token)
    app = create_app(node, settings, lifespan=mcp_app.router.lifespan_context)
    app.mount("/", mcp_app)
    return app
