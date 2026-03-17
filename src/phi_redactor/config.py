"""Application configuration and structured logging setup.

Configuration is loaded from (highest priority first):

1. Environment variables with ``PHI_REDACTOR_`` prefix.
2. ``.env`` file in the working directory.
3. Built-in defaults defined on the model fields.

**Security invariant**: The logging subsystem NEVER emits PHI values.
``PhiSafeFormatter`` actively scrubs known PHI patterns from every log
record before it reaches any handler.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------

_DEFAULT_BASE_DIR = Path.home() / ".phi-redactor"
_DEFAULT_VAULT_PATH = _DEFAULT_BASE_DIR / "vault.db"
_DEFAULT_AUDIT_PATH = _DEFAULT_BASE_DIR / "audit"
_DEFAULT_PLUGINS_DIR = _DEFAULT_BASE_DIR / "plugins"


# ---------------------------------------------------------------------------
# Configuration Model
# ---------------------------------------------------------------------------


class PhiRedactorConfig(BaseSettings):
    """Central configuration for the phi-redactor application.

    All fields can be overridden via environment variables prefixed with
    ``PHI_REDACTOR_`` (e.g. ``PHI_REDACTOR_PORT=9090``).

    Attributes:
        port: HTTP port for the proxy server.
        host: Bind address for the proxy server.
        default_provider: Default upstream LLM provider identifier.
        sensitivity: Detection sensitivity threshold.  ``0.0`` = aggressive
            (more redaction), ``1.0`` = permissive (less redaction).
        vault_path: Filesystem path for the encrypted SQLite vault database.
        audit_path: Directory for append-only audit trail files.
        plugins_dir: Directory scanned for custom plugin modules.
        session_idle_timeout: Seconds of inactivity before a session expires.
        session_max_lifetime: Maximum session duration in seconds regardless
            of activity.
        log_level: Python logging level name (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        vault_passphrase: Optional passphrase for vault encryption key
            derivation.  When ``None``, a machine-specific key is generated
            automatically.
        dashboard_enabled: Whether the monitoring dashboard routes are mounted.
    """

    model_config = SettingsConfigDict(
        env_prefix="PHI_REDACTOR_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    port: int = Field(
        default=8080,
        ge=1,
        le=65535,
        description="HTTP port for the proxy server",
    )
    host: str = Field(
        default="0.0.0.0",
        description="Bind address for the proxy server",
    )
    default_provider: str = Field(
        default="openai",
        description="Default upstream LLM provider (openai, anthropic, google, azure)",
    )
    sensitivity: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description=(
            "Detection sensitivity: 0.0 = aggressive (more redaction), "
            "1.0 = permissive (less redaction)"
        ),
    )
    vault_path: Path = Field(
        default=_DEFAULT_VAULT_PATH,
        description="Path to the encrypted SQLite vault database",
    )
    audit_path: Path = Field(
        default=_DEFAULT_AUDIT_PATH,
        description="Directory for append-only audit trail files",
    )
    plugins_dir: Path = Field(
        default=_DEFAULT_PLUGINS_DIR,
        description="Directory scanned for custom plugin modules",
    )
    session_idle_timeout: int = Field(
        default=1800,
        ge=60,
        description="Seconds of inactivity before a session expires",
    )
    session_max_lifetime: int = Field(
        default=86400,
        ge=300,
        description="Maximum session duration in seconds",
    )
    log_level: str = Field(
        default="INFO",
        description="Python logging level name",
    )
    vault_passphrase: str | None = Field(
        default=None,
        description="Passphrase for vault key derivation (auto-generated if None)",
    )
    dashboard_enabled: bool = Field(
        default=False,
        description="Enable the monitoring web dashboard",
    )

    # -- Validators ----------------------------------------------------------

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        """Ensure the log level is a recognized Python logging level name."""
        canonical = value.upper().strip()
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if canonical not in valid_levels:
            msg = f"Invalid log_level '{value}'. Must be one of: {', '.join(sorted(valid_levels))}"
            raise ValueError(msg)
        return canonical

    @field_validator("default_provider")
    @classmethod
    def _validate_provider(cls, value: str) -> str:
        """Normalise provider name to lowercase."""
        return value.strip().lower()


# ---------------------------------------------------------------------------
# PHI-Safe Logging
# ---------------------------------------------------------------------------

# Patterns that may indicate PHI leaking into log messages.  These are applied
# defensively -- any match is replaced with a redaction placeholder.
_PHI_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # SSN: 123-45-6789 or 123456789
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED-SSN]"),
    (re.compile(r"\b\d{9}\b"), "[REDACTED-POSSIBLE-SSN]"),
    # Phone numbers: (555) 123-4567, 555-123-4567, 555.123.4567
    (re.compile(r"\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}"), "[REDACTED-PHONE]"),
    # Email addresses
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[REDACTED-EMAIL]"),
    # IP addresses
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "[REDACTED-IP]"),
    # MRN-like patterns (6-10 digit numbers preceded by MRN context)
    (re.compile(r"(?i)\bMRN[:\s#]*\d{6,10}\b"), "[REDACTED-MRN]"),
]


def _scrub_phi(message: str) -> str:
    """Remove known PHI patterns from a log message string.

    This is a defense-in-depth measure.  Application code should never
    intentionally log PHI, but this formatter catches accidental leaks.
    """
    for pattern, replacement in _PHI_PATTERNS:
        message = pattern.sub(replacement, message)
    return message


class PhiSafeFormatter(logging.Formatter):
    """JSON log formatter that scrubs PHI patterns from every record.

    Produces one JSON object per line with the following keys:

    - ``timestamp``: ISO-8601 UTC timestamp.
    - ``level``: Log level name.
    - ``logger``: Logger name.
    - ``message``: PHI-scrubbed log message.
    - ``module``: Source module name.
    - ``function``: Source function name.
    - ``line``: Source line number.

    If the record contains an exception, an ``exception`` key is added
    (also PHI-scrubbed).
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as a single-line JSON object with PHI scrubbed."""
        # Build the message (may include args formatting)
        message = record.getMessage()
        message = _scrub_phi(message)

        log_entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": message,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if record.exc_info and record.exc_info[1] is not None:
            exc_text = self.formatException(record.exc_info)
            log_entry["exception"] = _scrub_phi(exc_text)

        return json.dumps(log_entry, default=str)


# ---------------------------------------------------------------------------
# Public setup helper
# ---------------------------------------------------------------------------


def setup_logging(config: PhiRedactorConfig) -> None:
    """Configure the root logger with structured JSON output and PHI scrubbing.

    This function:

    1. Creates a :class:`PhiSafeFormatter` that emits single-line JSON.
    2. Attaches it to a ``StreamHandler`` writing to *stderr*.
    3. Sets the root log level from ``config.log_level``.
    4. Suppresses noisy third-party loggers (uvicorn access, httpx, httpcore).

    Call this once at application startup -- typically in the CLI ``serve``
    command or the ``ProxyApp`` factory.

    Args:
        config: Application configuration supplying the desired log level.
    """
    root_logger = logging.getLogger()

    # Remove any pre-existing handlers to avoid duplicate output when
    # setup_logging is called more than once (e.g., in tests).
    root_logger.handlers.clear()

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(PhiSafeFormatter())
    root_logger.addHandler(handler)
    root_logger.setLevel(getattr(logging, config.log_level))

    # Quiet noisy third-party loggers
    for noisy in ("uvicorn.access", "httpx", "httpcore", "faker"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
