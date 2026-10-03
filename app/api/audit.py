"""Endpoint de consultation du journal d'audit, destiné au panneau de
démonstration. Réservé au rôle admin : le journal contient l'historique
des décisions de sécurité de tous les utilisateurs."""
import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from app.dependancies import get_current_user
from app.auth.schemas import TokenPayload

router = APIRouter()

AUDIT_LOG_PATH = Path("logs/audit.jsonl")


@router.get("/audit")
async def get_audit_log(limit: int = 50, current_user: TokenPayload = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Consultation du journal d'audit réservée au rôle admin")

    if not AUDIT_LOG_PATH.exists():
        return {"entries": []}

    lines = AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines()
    entries = []
    for line in lines[-limit:]:
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            # Ligne non structurée (logging standard résiduel) — conservée brute
            # plutôt qu'ignorée silencieusement.
            entries.append({"event": "unparsed", "raw": line[:200]})

    return {"entries": list(reversed(entries))}