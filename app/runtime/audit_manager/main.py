import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import structlog

_configured = False

# Tous les événements d'audit vivent sous ce namespace. Le fichier audit.jsonl
# est branché UNIQUEMENT sur ce logger — jamais sur le logger racine, sinon
# chaque bibliothèque tierce (httpx, google-genai, transformers, chromadb...)
# y écrirait du texte non structuré.
AUDIT_NAMESPACE = "audit"


def configure_audit_logging(log_dir: str = "logs", max_bytes: int = 10 * 1024 * 1024, backup_count: int = 5) -> None:
    global _configured
    if _configured:
        return
    _configured = True

    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    file_handler = RotatingFileHandler(
        log_path / "audit.jsonl", maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8",
    )
    file_handler.setFormatter(logging.Formatter("%(message)s"))  # structlog fournit déjà le JSON complet

    audit_root = logging.getLogger(AUDIT_NAMESPACE)
    audit_root.addHandler(file_handler)
    audit_root.setLevel(logging.INFO)
    # propagate reste True : la console (uvicorn / basicConfig) et caplog (tests) voient aussi les événements.

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
    return structlog.get_logger(f"{AUDIT_NAMESPACE}.{name}")
