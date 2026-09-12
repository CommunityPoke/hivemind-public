"""PaaS entrypoint (Fly.io et al.): single-port combined app.

Usage: ``uvicorn main:app`` (the platform sets PORT and, on Fly.io,
FLY_APP_NAME; TLS is terminated by the platform).
"""

import os
from pathlib import Path

from pip_protocol.bootstrap import build_node_from_settings
from pip_protocol.config import Settings
from pip_protocol.observability import configure_logging
from pip_protocol.transport.combined import create_combined_app

settings = Settings()

# PaaS conveniences — env vars set by the platform, not by the operator.
if settings.public_http_url is None and os.environ.get("FLY_APP_NAME"):
    base = f"https://{os.environ['FLY_APP_NAME']}.fly.dev"
    settings.public_http_url = base
    settings.public_mcp_url = f"{base}/mcp"
if os.environ.get("PORT"):
    settings.http_port = int(os.environ["PORT"])
_default_key = Settings.model_fields["private_key_file"].default
if settings.private_key_file == _default_key and Path("/data").is_dir():
    if os.access("/data", os.W_OK):
        settings.private_key_file = "/data/instance.key"
        if settings.store_url == "memory://":
            settings.store_url = "sqlite:////data/pip.db"

configure_logging(settings.log_level)
node = build_node_from_settings(settings)
app = create_combined_app(node, settings)
