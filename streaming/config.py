"""
SentinelHunt — Centralized Configuration Management

Provides a single source of truth for all system configuration.
Supports environment variables, YAML config files, and sensible defaults.
"""

import os
import yaml
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

logger = logging.getLogger("sentinelhunt.config")

# ==========================================
# Project paths
# ==========================================
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "feature_engineering" / "outputs"
ML_MODEL_DIR = PROJECT_ROOT / "ml" / "models"
THREAT_INTEL_DIR = PROJECT_ROOT / "threat_intel" / "data"
LOGS_DIR = PROJECT_ROOT / "logs"


@dataclass
class RedisConfig:
    """Redis connection settings."""
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None
    flow_stream: str = "sentinelhunt:flows"
    alert_stream: str = "sentinelhunt:alerts"
    consumer_group: str = "sentinelhunt-workers"
    max_stream_length: int = 100_000


@dataclass
class MLConfig:
    """Machine learning pipeline settings."""
    # Feature columns used by all models
    feature_columns: List[str] = field(default_factory=lambda: [
        "packet_count", "duration", "total_bytes", "avg_packet_size",
        "min_iat", "max_iat", "mean_iat", "std_iat",
        "bytes_per_second", "packets_per_second", "avg_bytes_per_packet",
        "dns_query_length", "dns_subdomain_depth", "dns_entropy",
    ])

    # Isolation Forest
    iforest_n_estimators: int = 200
    iforest_contamination: float = 0.05
    iforest_random_state: int = 42

    # Autoencoder
    autoencoder_epochs: int = 100
    autoencoder_batch_size: int = 64
    autoencoder_learning_rate: float = 1e-3
    autoencoder_latent_dim: int = 8
    autoencoder_threshold_percentile: float = 95.0

    # LSTM
    lstm_sequence_length: int = 10
    lstm_hidden_dim: int = 64
    lstm_num_layers: int = 2
    lstm_epochs: int = 50
    lstm_batch_size: int = 32
    lstm_learning_rate: float = 1e-3

    # Ensemble
    ensemble_weights: Dict[str, float] = field(default_factory=lambda: {
        "isolation_forest": 0.25,
        "autoencoder": 0.30,
        "lof": 0.20,
        "ocsvm": 0.25,
    })
    ensemble_threshold: float = 0.5

    # Training
    validation_split: float = 0.2
    cross_validation_folds: int = 5
    model_dir: str = str(ML_MODEL_DIR)


@dataclass
class DetectionConfig:
    """Detection engine settings."""
    # Rule-based detection thresholds
    port_scan_threshold: int = 20
    dns_entropy_threshold: float = 3.5
    dns_subdomain_depth_threshold: int = 3
    brute_force_connection_threshold: int = 30
    brute_force_duration_threshold: float = 1.0
    exfil_bytes_threshold: int = 5_000_000
    lateral_movement_new_connection_threshold: int = 3
    dga_entropy_threshold: float = 3.8
    credential_failure_window_seconds: int = 300
    credential_failure_threshold: int = 10

    # Score fusion weights
    rule_weight: float = 0.6
    ml_weight: float = 0.4

    # Severity bands
    severity_low: float = 0.3
    severity_medium: float = 0.6
    severity_high: float = 0.8


@dataclass
class ThreatIntelConfig:
    """Threat intelligence settings."""
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    maxmind_db_path: Optional[str] = None

    # Cache settings
    cache_ttl_seconds: int = 3600
    max_cache_size: int = 10_000

    # IOC settings
    ioc_db_path: str = str(THREAT_INTEL_DIR / "ioc_database.db")
    ioc_confidence_decay_days: int = 90

    # Feed URLs
    otx_feed_url: str = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    abusech_feed_url: str = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


@dataclass
class APIConfig:
    """API server settings."""
    host: str = "0.0.0.0"
    port: int = 5000
    cors_origins: List[str] = field(default_factory=lambda: [
        "http://localhost:3000",
        "http://localhost:3001",
    ])
    jwt_secret: str = "sentinelhunt-secret-change-in-production"
    jwt_expiry_hours: int = 24
    rate_limit_per_minute: int = 100
    enable_websocket: bool = True


@dataclass
class CollectorConfig:
    """Collector settings."""
    interface: str = "eth0"
    snapshot_length: int = 1600
    promiscuous_mode: bool = True
    timeout_ms: int = 1000
    bpf_filter: str = "tcp or udp"
    flow_timeout_seconds: int = 60
    max_flows_in_memory: int = 10_000
    output_directory: str = str(DATA_DIR)
    export_interval_seconds: int = 30
    enable_redis: bool = True


@dataclass
class SentinelHuntConfig:
    """Root configuration for the entire platform."""
    redis: RedisConfig = field(default_factory=RedisConfig)
    ml: MLConfig = field(default_factory=MLConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    api: APIConfig = field(default_factory=APIConfig)
    collector: CollectorConfig = field(default_factory=CollectorConfig)

    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = str(LOGS_DIR / "sentinelhunt.log")


def _apply_env_overrides(config: SentinelHuntConfig) -> None:
    """Override config values from environment variables."""
    env_map = {
        "SENTINELHUNT_REDIS_HOST": ("redis", "host"),
        "SENTINELHUNT_REDIS_PORT": ("redis", "port", int),
        "SENTINELHUNT_REDIS_PASSWORD": ("redis", "password"),
        "SENTINELHUNT_VT_API_KEY": ("threat_intel", "virustotal_api_key"),
        "SENTINELHUNT_ABUSEIPDB_KEY": ("threat_intel", "abuseipdb_api_key"),
        "SENTINELHUNT_SHODAN_KEY": ("threat_intel", "shodan_api_key"),
        "SENTINELHUNT_JWT_SECRET": ("api", "jwt_secret"),
        "SENTINELHUNT_LOG_LEVEL": (None, "log_level"),
        "SENTINELHUNT_API_PORT": ("api", "port", int),
    }

    for env_var, mapping in env_map.items():
        value = os.environ.get(env_var)
        if value is None:
            continue

        if len(mapping) == 3:
            section, key, cast = mapping
            value = cast(value)
        elif len(mapping) == 2:
            section, key = mapping
        else:
            continue

        if section is None:
            setattr(config, key, value)
        else:
            sub_config = getattr(config, section)
            setattr(sub_config, key, value)

        logger.debug("Config override from env: %s → %s.%s", env_var, section, key)


def load_config(config_path: Optional[str] = None) -> SentinelHuntConfig:
    """
    Load configuration from YAML file with environment variable overrides.

    Priority: Environment Variables > YAML File > Defaults
    """
    config = SentinelHuntConfig()

    # Try to load YAML config
    if config_path is None:
        config_path = os.environ.get(
            "SENTINELHUNT_CONFIG",
            str(PROJECT_ROOT / "config.yaml"),
        )

    config_file = Path(config_path)
    if config_file.exists():
        try:
            with open(config_file, "r") as f:
                raw = yaml.safe_load(f) or {}

            # Apply YAML values to config sections
            for section_name in ("redis", "ml", "detection", "threat_intel", "api", "collector"):
                if section_name in raw:
                    sub_config = getattr(config, section_name)
                    for key, value in raw[section_name].items():
                        if hasattr(sub_config, key):
                            setattr(sub_config, key, value)

            # Top-level keys
            for key in ("log_level", "log_file"):
                if key in raw:
                    setattr(config, key, raw[key])

            logger.info("Loaded configuration from %s", config_file)
        except Exception as e:
            logger.warning("Failed to load config file %s: %s", config_file, e)

    # Apply environment variable overrides (highest priority)
    _apply_env_overrides(config)

    # Ensure directories exist
    for directory in (DATA_DIR, ML_MODEL_DIR, THREAT_INTEL_DIR, LOGS_DIR):
        directory.mkdir(parents=True, exist_ok=True)

    return config


# Module-level singleton for easy access
_config: Optional[SentinelHuntConfig] = None


def get_config() -> SentinelHuntConfig:
    """Get or create the global configuration singleton."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def setup_logging(config: Optional[SentinelHuntConfig] = None) -> None:
    """Configure structured logging for the platform."""
    if config is None:
        config = get_config()

    log_format = (
        "%(asctime)s | %(levelname)-8s | %(name)-30s | %(message)s"
    )
    date_format = "%Y-%m-%d %H:%M:%S"

    handlers: list = [logging.StreamHandler()]

    if config.log_file:
        log_path = Path(config.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(str(log_path)))

    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format=log_format,
        datefmt=date_format,
        handlers=handlers,
        force=True,
    )

    # Suppress noisy third-party loggers
    for noisy in ("urllib3", "requests", "redis", "matplotlib"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
