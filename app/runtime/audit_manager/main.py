import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import structlog

_configured = False


def configure_audit_logging(log_dir: str = "logs", max_bytes: int = 10 * 1024 * 1024, backup_count: int = 5) -> None:
    global _configured
    if _configured:
        return
    _configured = True

    Path(log_dir).mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        Path(log_dir) / "audit.jsonl", maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8",
    )
    file_handler.setFormatter(logging.Formatter("%(message)s"))  # structlog fournit déjà le JSON complet

    root = logging.getLogger()
    root.addHandler(file_handler)
    root.setLevel(logging.INFO)

    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_audit_logger(name: str = "audit"):
    return structlog.get_logger(name)

