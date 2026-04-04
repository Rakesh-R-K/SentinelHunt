"""
SentinelHunt — Redis Streams Message Broker

Provides a pub/sub messaging layer using Redis Streams for real-time
flow processing. Connects the collector, ML engine, rule engine,
and dashboard with sub-second latency.

Architecture:
    Collector → Redis Stream (flows) → Consumer Groups → Alerts Stream → Dashboard
"""

import json
import time
import logging
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime

logger = logging.getLogger("sentinelhunt.streaming.broker")

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("redis-py not installed — streaming disabled (pip install redis)")


class RedisBroker:
    """
    Redis Streams-based message broker for SentinelHunt.

    Supports:
        - Publishing flow data to streams
        - Consumer groups for parallel processing
        - Alert publishing with automatic ID generation
        - Connection pooling and retry logic
        - Graceful degradation when Redis is unavailable
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        flow_stream: str = "sentinelhunt:flows",
        alert_stream: str = "sentinelhunt:alerts",
        consumer_group: str = "sentinelhunt-workers",
        max_stream_length: int = 100_000,
    ):
        self.flow_stream = flow_stream
        self.alert_stream = alert_stream
        self.consumer_group = consumer_group
        self.max_stream_length = max_stream_length
        self._connected = False
        self._client: Optional[Any] = None

        if not REDIS_AVAILABLE:
            logger.warning("Redis not available — broker running in offline mode")
            return

        try:
            self._pool = redis.ConnectionPool(
                host=host,
                port=port,
                db=db,
                password=password,
                decode_responses=True,
                max_connections=10,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True,
            )
            self._client = redis.Redis(connection_pool=self._pool)
            self._client.ping()
            self._connected = True
            logger.info("Connected to Redis at %s:%d", host, port)

            # Create consumer groups
            self._ensure_consumer_groups()

        except Exception as e:
            logger.warning("Redis connection failed: %s — running offline", e)
            self._connected = False

    def _ensure_consumer_groups(self) -> None:
        """Create consumer groups if they don't exist."""
        for stream in [self.flow_stream, self.alert_stream]:
            try:
                self._client.xgroup_create(
                    stream, self.consumer_group, id="0", mkstream=True
                )
                logger.info("Created consumer group '%s' on '%s'", self.consumer_group, stream)
            except redis.ResponseError as e:
                if "BUSYGROUP" not in str(e):
                    logger.warning("Consumer group error: %s", e)

    @property
    def is_connected(self) -> bool:
        """Check if Redis connection is active."""
        if not self._connected or not self._client:
            return False
        try:
            self._client.ping()
            return True
        except Exception:
            self._connected = False
            return False

    def publish_flow(self, flow_data: Dict[str, Any]) -> Optional[str]:
        """
        Publish a flow to the flows stream.

        Returns the stream entry ID, or None if offline.
        """
        if not self.is_connected:
            return None

        try:
            # Flatten nested dicts and convert values to strings
            flat_data = {
                k: json.dumps(v) if isinstance(v, (dict, list)) else str(v)
                for k, v in flow_data.items()
            }
            flat_data["_published_at"] = datetime.utcnow().isoformat() + "Z"

            entry_id = self._client.xadd(
                self.flow_stream,
                flat_data,
                maxlen=self.max_stream_length,
                approximate=True,
            )
            return entry_id
        except Exception as e:
            logger.error("Failed to publish flow: %s", e)
            return None

    def publish_alert(self, alert_data: Dict[str, Any]) -> Optional[str]:
        """Publish an alert to the alerts stream."""
        if not self.is_connected:
            return None

        try:
            flat_data = {
                k: json.dumps(v) if isinstance(v, (dict, list)) else str(v)
                for k, v in alert_data.items()
            }
            flat_data["_published_at"] = datetime.utcnow().isoformat() + "Z"

            entry_id = self._client.xadd(
                self.alert_stream,
                flat_data,
                maxlen=self.max_stream_length,
                approximate=True,
            )
            return entry_id
        except Exception as e:
            logger.error("Failed to publish alert: %s", e)
            return None

    def consume_flows(
        self,
        consumer_name: str,
        batch_size: int = 10,
        block_ms: int = 1000,
    ) -> List[Dict[str, Any]]:
        """
        Consume flows from the stream as part of a consumer group.

        Returns a list of flow dictionaries with stream IDs.
        """
        if not self.is_connected:
            return []

        try:
            results = self._client.xreadgroup(
                self.consumer_group,
                consumer_name,
                {self.flow_stream: ">"},
                count=batch_size,
                block=block_ms,
            )

            flows = []
            if results:
                for stream_name, entries in results:
                    for entry_id, data in entries:
                        flow = {"_stream_id": entry_id}
                        for k, v in data.items():
                            try:
                                flow[k] = json.loads(v)
                            except (json.JSONDecodeError, TypeError):
                                flow[k] = v
                        flows.append(flow)

            return flows
        except Exception as e:
            logger.error("Failed to consume flows: %s", e)
            return []

    def consume_alerts(
        self,
        consumer_name: str,
        batch_size: int = 10,
        block_ms: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Consume alerts from the alerts stream."""
        if not self.is_connected:
            return []

        try:
            results = self._client.xreadgroup(
                self.consumer_group,
                consumer_name,
                {self.alert_stream: ">"},
                count=batch_size,
                block=block_ms,
            )

            alerts = []
            if results:
                for stream_name, entries in results:
                    for entry_id, data in entries:
                        alert = {"_stream_id": entry_id}
                        for k, v in data.items():
                            try:
                                alert[k] = json.loads(v)
                            except (json.JSONDecodeError, TypeError):
                                alert[k] = v
                        alerts.append(alert)

            return alerts
        except Exception as e:
            logger.error("Failed to consume alerts: %s", e)
            return []

    def acknowledge(self, stream: str, entry_id: str) -> bool:
        """Acknowledge a processed message."""
        if not self.is_connected:
            return False

        try:
            self._client.xack(stream, self.consumer_group, entry_id)
            return True
        except Exception as e:
            logger.error("Failed to acknowledge %s: %s", entry_id, e)
            return False

    def get_stream_info(self) -> Dict[str, Any]:
        """Get information about the streams."""
        if not self.is_connected:
            return {"status": "disconnected"}

        try:
            flow_info = self._client.xinfo_stream(self.flow_stream)
            alert_info = self._client.xinfo_stream(self.alert_stream)
            return {
                "status": "connected",
                "flows": {
                    "length": flow_info["length"],
                    "first_entry": flow_info.get("first-entry"),
                    "last_entry": flow_info.get("last-entry"),
                },
                "alerts": {
                    "length": alert_info["length"],
                    "first_entry": alert_info.get("first-entry"),
                    "last_entry": alert_info.get("last-entry"),
                },
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def get_recent_alerts(self, count: int = 50) -> List[Dict[str, Any]]:
        """Get the most recent alerts from the stream (for dashboard)."""
        if not self.is_connected:
            return []

        try:
            results = self._client.xrevrange(
                self.alert_stream, count=count
            )
            alerts = []
            for entry_id, data in results:
                alert = {"_stream_id": entry_id}
                for k, v in data.items():
                    try:
                        alert[k] = json.loads(v)
                    except (json.JSONDecodeError, TypeError):
                        alert[k] = v
                alerts.append(alert)
            return alerts
        except Exception as e:
            logger.error("Failed to get recent alerts: %s", e)
            return []

    def close(self) -> None:
        """Close the Redis connection."""
        if self._client:
            self._client.close()
            self._connected = False
            logger.info("Redis connection closed")
