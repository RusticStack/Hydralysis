"""Semantic trace store (package T0: M0 of hydra-semantic-trace.md). Store, import, bounded query, aligned diff and
three-valued checks over imported or appended evidence. No capture, no engine protocol, no MCP tools yet."""

from .schema import TraceError
from .store import CorrelationKeyring, Producer, TraceStore, connect_ro, create_session, health

__all__ = ["CorrelationKeyring", "Producer", "TraceError", "TraceStore", "connect_ro", "create_session", "health"]
