import asyncio
import json
import sys
import os
from pathlib import Path
import importlib.util
from app.runtime.sandbox_manager.config import load_sandbox_config
import signal as signal_module
from app.runtime.audit_manager.main import get_audit_logger

audit = get_audit_logger("sandbox_manager")


_SANDBOX_CONFIG = load_sandbox_config()

def _current_cgroup_path() -> Path:
    line = Path("/proc/self/cgroup").read_text().strip()
    rel_path = line.split(":")[-1].lstrip("/")
    return Path("/sys/fs/cgroup") / rel_path

CGROUP_BASE = _current_cgroup_path()
#for me for ex: /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/ , this is the path to the cgroup of the current user, where we can find the cgroup of the current process and its children


from app.runtime.sandbox_manager.authorization_receipt import AuthorizationReceipt


SANDBOX_WORKER = "app/runtime/sandbox_manager/landlock_worker.py"


_OPERATION_TO_RECEIPT = {
    "file_read": ("file", "read"),
    "file_write": ("file", "write"),
    "tool_exec": ("tool", "execute"),
    "network_call": ("network", "connect"),
}#able de correspondance entre deux vocabulaires: du policu engine et du landlock worker


async def _run_sandboxed(receipt: AuthorizationReceipt,operation: str,identifier: str,worker_kwargs: dict, timeout: float = 10.0) -> str:
    expected_type, expected_action = _OPERATION_TO_RECEIPT.get(operation, (None, None))

    # Vérifie que le reçu correspond à l'opération demandée.
    if (
        receipt.resource_type != expected_type
        or receipt.action != expected_action
    ):
        audit.warning(
            "policy_denial",
            operation=operation,
            reason="invalid_receipt",
        )
        raise PermissionError(
            "Reçu d'autorisation invalide pour cette opération"

        )

    # Vérifie que la cible correspond à celle autorisée.
    if receipt.identifier != identifier:
        audit.warning(
            "policy_denial",
            operation=operation,
            reason="unauthorized_target",
        )
        raise PermissionError(
            "Reçu d'autorisation invalide : "
            "cible différente de celle autorisée"
        )

    # Crée un cgroup dédié à cette opération.
    cg_path = _setup_cgroup(
        operation,
        **_SANDBOX_CONFIG["cgroup_defaults"],
    )

    request = {
        "operation": operation,
        "dangerous_syscalls": _SANDBOX_CONFIG["dangerous_syscalls"],
        **worker_kwargs,
    }

    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        SANDBOX_WORKER,
        json.dumps(request),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        close_fds=True,
    )

    # Ajoute le worker au cgroup.
    if cg_path is not None:
        try:
            (cg_path / "cgroup.procs").write_text(str(proc.pid))
        except OSError as e:
            proc.kill()
            await proc.communicate()
            _cleanup_cgroup(cg_path)
            audit.warning("infra_failure", operation=operation, component="cgroup", detail=f"attach_failed: {e}")
            raise RuntimeError("Sandbox indisponible : impossible d'appliquer les limites cgroup")

    try:
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )

        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()

            audit.warning(
                "cgroup_exceeded",
                operation=operation,
                limit_type="timeout",
                limit_s=timeout,
            )

            raise PermissionError(
                f"Opération {operation} annulée : "
                f"délai de {timeout}s dépassé"
            )

    finally:
        # Nettoyage unique du cgroup.
        _cleanup_cgroup(cg_path)

    stderr_text = stderr.decode(errors="replace").strip()

    # stderr est conservé comme information de diagnostic.
    if stderr_text:
        if proc.returncode == 0:
            audit.info(
                "sandbox_stderr",
                operation=operation,
                returncode=proc.returncode,
                stderr=stderr_text,
            )
        else:
            audit.warning(
                "sandbox_stderr",
                operation=operation,
                returncode=proc.returncode,
                stderr=stderr_text,
            )

    # Worker terminé correctement.
    if proc.returncode == 0:
        return stdout.decode()

    # Worker terminé par un signal.
    if proc.returncode < 0:
        sig = -proc.returncode

        if sig == getattr(signal_module, "SIGSYS", 31):
            audit.warning(
                "seccomp_violation",
                operation=operation,
                signal=sig,
            )
            raise PermissionError(
                f"Appel système bloqué: {operation}"
            )

        if sig == getattr(signal_module, "SIGKILL", 9):
            audit.warning(
                "cgroup_exceeded",
                operation=operation,
                signal=sig,
                detail="probable OOM kill",
            )
            raise PermissionError(
                f"Limite de ressources dépassée: {operation}"
            )

        audit.warning(
            "infra_failure",
            operation=operation,
            signal=sig,
        )
        raise RuntimeError(
            f"Sandbox interrompu (signal {sig}): {operation}"
        )

    # Le worker a éventuellement fourni une erreur structurée sur stderr.
    try:
        info = json.loads(stderr_text)
        category = info.get("category", "infra_failure")
        detail = info.get("detail", stderr_text)

    except (json.JSONDecodeError, ValueError):
        category = "infra_failure"
        detail = stderr_text

    audit.warning(
        "sandbox_failure",
        operation=operation,
        category=category,
        detail=detail,
    )

    if category == "landlock_denial":
        audit.warning(
            "landlock_denial",
            operation=operation,
            detail=detail,
        )
        raise PermissionError(
            f"Accès refusé par le sandbox: {operation}"
        )

    raise RuntimeError(
        f"Sandbox indisponible pour {operation}: {detail}"
    )


def _setup_cgroup(name: str,memory_max_mb: int = 256,pids_max: int = 32,cpu_percent: int = 50,) -> Path | None:
"""Crée un cgroup dédié à une opération.
Lève PermissionError si les limites cgroup ne peuvent pas
être configurées, afin de garantir un comportement fail-closed.
"""
    try:
        cg_path = CGROUP_BASE / f"sandbox-{name}-{os.getpid()}"
        cg_path.mkdir(parents=True, exist_ok=True)

    except OSError as e:
        audit.warning(
            "infra_failure",
            component="cgroup",
            operation=name,
            detail=f"cgroups_unavailable: {e}",
        )
        raise PermissionError(
            "Sandbox indisponible : cgroups non disponibles"
        ) from e

    try:
        for filename, value in [
            ("memory.max", str(memory_max_mb * 1024 * 1024)),
            ("pids.max", str(pids_max)),
            ("cpu.max", f"{cpu_percent * 1000} 100000"),
        ]:
            (cg_path / filename).write_text(value)

    except OSError as e:
        audit.warning(
            "infra_failure",
            component="cgroup",
            operation=name,
            detail=f"configuration_failed: {e}",
        )
        _cleanup_cgroup(cg_path)

        raise PermissionError(
            f"Sandbox indisponible : impossible de configurer les limites cgroup"
        ) from e

    return cg_path


def _cleanup_cgroup(cg_path: Path | None) -> None:
    if cg_path is None:
        return

    try:
        cg_path.rmdir()
    except OSError as e:
        audit.warning(
            "infra_failure",
            component="cgroup",
            detail=f"cleanup_failed: {e}",
        )
