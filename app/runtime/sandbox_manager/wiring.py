import asyncio
import json
import logging
import sys

from app.runtime.sandbox_manager.authorization_receipt import AuthorizationReceipt

logger = logging.getLogger("sandbox_manager")  # nom distinct de "policy_engine" — utile pour filtrer les logs

SANDBOX_WORKER = "app/runtime/sandbox_manager/landlock_worker.py"


_OPERATION_TO_RECEIPT = {
    "file_read": ("file", "read"),
    "file_write": ("file", "write"),
    "tool_exec": ("tool", "execute"),
    "network_call": ("network", "connect"),
}#able de correspondance entre deux vocabulaires: du policu engine et du landlock worker


async def _run_sandboxed(receipt: AuthorizationReceipt, operation: str, identifier: str, worker_kwargs: dict) -> str:
    expected_type, expected_action = _OPERATION_TO_RECEIPT.get(operation, (None, None))
    if receipt.resource_type != expected_type or receipt.action != expected_action:
        logger.error("sandbox_receipt_mismatch: operation=%s receipt_type=%s receipt_action=%s",
                     operation, receipt.resource_type, receipt.action)
        raise PermissionError("Reçu d'autorisation invalide pour cette opération")
    if receipt.identifier != identifier:
        logger.error("sandbox_receipt_mismatch: attendu=%s reçu=%s", identifier, receipt.identifier)
        raise PermissionError("Reçu d'autorisation invalide : cible différente de celle autorisée")

    request = {"operation": operation, **worker_kwargs}
    proc = await asyncio.create_subprocess_exec(
        sys.executable, SANDBOX_WORKER, json.dumps(request),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        close_fds=True,
    )
    stdout, stderr = await proc.communicate()
        #create_subprocess_exec() lance le worker Landlock, et communicate() attend sa fin pour récupérer son résultat et ses erreurs.

    if proc.returncode != 0:
        logger.warning(
            "sandbox_failed: operation=%s returncode=%s stderr=%r",
            operation,
            proc.returncode,
            stderr,
        )
        raise PermissionError(
            f"Sandbox failed: operation={operation}, "
            f"returncode={proc.returncode}, "
            f"stderr={stderr.decode(errors='replace')}"
        )

    if not stdout:
        raise RuntimeError(
            f"Sandbox worker returned no output. stderr={stderr.decode(errors='replace')!r}"
        )

    return stdout.decode()