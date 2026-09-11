"""Build a Node from Settings (spec §12)."""

import logging
from pathlib import Path

from .config import Settings
from .identity import KeyPair
from .node import Node
from .policy import Policy
from .store import open_store

logger = logging.getLogger("pip_protocol.bootstrap")


def build_node_from_settings(settings: Settings) -> Node:
    key_path = Path(settings.private_key_file)
    if not key_path.exists():
        keypair = KeyPair.generate()
        keypair.save(key_path)
        logger.info("generated new instance key at %s", key_path)
    else:
        keypair = KeyPair.load(key_path, allow_insecure=settings.allow_insecure_key_perms)

    policy_path = Path(settings.policy_file)
    if policy_path.exists():
        policy = Policy.load(policy_path)
    else:
        logger.warning("policy file %s not found; starting with empty policy", policy_path)
        policy = Policy(
            max_clock_skew_seconds=settings.max_clock_skew_seconds,
            idempotency_ttl_seconds=settings.idempotency_ttl_seconds,
        )

    endpoints: dict[str, str | None] = {}
    if settings.public_http_url:
        endpoints["http"] = settings.public_http_url
    if settings.public_mcp_url:
        endpoints["mcp"] = settings.public_mcp_url

    return Node(
        keypair,
        policy,
        store=open_store(settings.store_url),
        display_name=settings.display_name,
        endpoints=endpoints,
    )
