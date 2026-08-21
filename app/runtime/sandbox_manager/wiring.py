import asyncio
import json
import logging
import sys
import os
from pathlib import Path
import importlib.util

CGROUP_BASE = Path(f"/sys/fs/cgroup/user.slice/user-{os.getuid()}.slice/user@{os.getuid()}.service")
#for me for ex: /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/ , this is the path to the cgroup of the current user, where we can find the cgroup of the current process and its children


from app.runtime.sandbox_manager.authorization_receipt import AuthorizationReceipt

logger = logging.getLogger("sandbox_manager")  # nom distinct de "policy_engine" — utile pour filtrer les logs

SANDBOX_WORKER = "app/runtime/sandbox_manager/landlock_worker.py"


_OPERATION_TO_RECEIPT = {
    "file_read": ("file", "read"),
    "file_write": ("file", "write"),
    "tool_exec": ("tool", "execute"),
    "network_call": ("network", "connect"),
}#able de correspondance entre deux vocabulaires: du policu engine et du landlock worker


async def _run_sandboxed(receipt: AuthorizationReceipt,operation: str,identifier: str,worker_kwargs: dict,timeout=10.0) -> str:
    expected_type, expected_action = _OPERATION_TO_RECEIPT.get(operation, (None, None))

    if receipt.resource_type != expected_type or receipt.action != expected_action:
        logger.error(
            "sandbox_receipt_mismatch: operation=%s receipt_type=%s receipt_action=%s",
            operation,
            receipt.resource_type,
            receipt.action,
        )
        raise PermissionError("Reçu d'autorisation invalide pour cette opération")

    if receipt.identifier != identifier:
        logger.error(
            "sandbox_receipt_mismatch: attendu=%s reçu=%s",
            identifier,
            receipt.identifier,
        )
        raise PermissionError("Reçu d'autorisation invalide : cible différente de celle autorisée")

    # Crée un cgroup dédié à cette opération.
    # Les limites mémoire, CPU et nombre de processus sont configurées ici.
    cg_path = _setup_cgroup(operation)

    request = {"operation": operation, **worker_kwargs}

    proc = await asyncio.create_subprocess_exec(
        sys.executable, #lance dasn l interpreteur python actuel
        SANDBOX_WORKER,
        json.dumps(request),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        close_fds=True #ensures that stdout and stderr are closed in the child process, preventing file descriptor leaks and ensuring that the child process does not inherit unnecessary file descriptors
    )

    # Ajoute le worker au cgroup après sa création.
    # create_subprocess_exec() nous donne son PID, que nous écrivons
    # dans cgroup.procs afin que le worker soit soumis aux limites du cgroup.
    if cg_path is not None:
        try:
            (cg_path / "cgroup.procs").write_text(str(proc.pid))
        except OSError as e:
            logger.warning("échec d'ajout au cgroup: %s", e)

    try:
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
    # create_subprocess_exec() lance le worker Landlock,
    # et communicate() attend sa fin pour récupérer son résultat et ses erreurs.
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()

            raise PermissionError(
                f"Opération {operation} annulée : "
                f"délai de {timeout}s dépassé"
            )

    finally:
        # Supprime le cgroup après la fin du worker afin de nettoyer
        # les ressources et le répertoire associé à cette opération.
        _cleanup_cgroup(cg_path)
    stderr_text = stderr.decode(errors="replace").strip()

    if stderr_text:
        level = (logging.WARNING if proc.returncode != 0 else logging.INFO)

        logger.log(
            level,
            "sandbox_stderr: operation=%s returncode=%s stderr=%s",
            operation,
            proc.returncode,
            stderr_text,
        )

    if proc.returncode != 0:
        raise PermissionError(
            f"Accès refusé par le sandbox: {operation}"
        )

    if not stdout:
        raise RuntimeError(
            "Sandbox worker returned no output. "
            f"stderr={stderr_text!r}"
        )
    return stdout.decode()


def _setup_cgroup(name: str, memory_max_mb: int = 256, pids_max: int = 32, cpu_percent: int = 50) -> Path :
    """Crée un sous-cgroup dédié à une opération. Retourne son chemin, ou None
    si la délégation n'est pas disponible — dégradation gracieuse, même principe
    que seccomp sous WSL2 : on continue sans, on ne bloque pas l'opération. ==> fail-open"""
    try:
        cg_path = CGROUP_BASE / f"sandbox-{name}-{os.getpid()}"
        cg_path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.warning("cgroups indisponibles (%s) — limites de ressources non appliquées", e)
        return None

    for filename, value in [
        ("memory.max", str(memory_max_mb * 1024 * 1024)),
        ("pids.max", str(pids_max)),
        ("cpu.max", f"{cpu_percent * 1000} 100000"),
    ]:
        (cg_path / filename).write_text(value)
    return cg_path


def _cleanup_cgroup(cg_path: Path | None) -> None:
    if cg_path is None:
        return
    try:
        cg_path.rmdir()
    except OSError:
        pass