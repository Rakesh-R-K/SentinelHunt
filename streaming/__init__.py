"""
SentinelHunt Streaming Module

Real-time data pipeline using Redis Streams.

Exports:
    RedisBroker      — Message broker for flow/alert pub-sub
    RealtimeScorer   — Flow scoring engine (ML + rules + MITRE)
    get_config       — Centralized configuration loader
    setup_logging    — Structured logging initializer
"""

from streaming.config import get_config, setup_logging
from streaming.redis_broker import RedisBroker
from streaming.realtime_scorer import RealtimeScorer

__all__ = [
    "RedisBroker",
    "RealtimeScorer",
    "get_config",
    "setup_logging",
]
