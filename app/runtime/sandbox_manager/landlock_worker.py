"""Exécuté exclusivement en sous-processus, jamais importé. Un seul point
d'entrée pour fichiers, outils et appels réseau. TOUS les imports sont en haut
du fichier — Landlock/seccomp ne sont appliqués qu'à l'intérieur des handlers, #pour ne pas tomber dans le piege ou landlock bloque l import
donc tout ce dont le process a besoin doit déjà être chargé avant."""
import sys
import json
import importlib.util
import ast       # pré-chargé pour les outils qui en ont besoin (calculator)
import operator  # idem
from pathlib import Path

from py_landlock import Landlock
import pyseccomp as seccomp
import httpx
import sysconfig 

STDLIB_DIR = sysconfig.get_path("stdlib") #demande à l'installation Python actuelle où se trouve sa standard library sur le disque. 

# Syscalls nécessaires au fonctionnement de base de CPython + I/O simple.
# Obtenu par observation empirique (mode LOG) — à revalider si ça casse.
#a l/aide de: strace -f python3 syscalls.py 2>&1   | grep -oP '^[a-zA-Z_][a-zA-Z0-9_]*\('   | sed 's/($//'   | sort -u
BASELINE_SYSCALLS = [
    # Observed
    "access",
    "arch_prctl",
    "bind",
    "brk",
    "close",
    "connect",
    "epoll_create1",
    "execve",
    "exit_group",
    "fcntl",
    "fstat",
    "futex",
    "getcwd",
    "getdents64",
    "getpeername",
    "getrandom",
    "getsockname",
    "gettid",
    "ioctl",
    "lseek",
    "mmap",
    "mprotect",
    "munmap",
    "newfstatat",
    "openat",
    "pipe2",
    "poll",
    "pread64",
    "prctl",
    "prlimit64",
    "read",
    "readlink",
    "recvfrom",
    "recvmsg",
    "rseq",
    "rt_sigaction",
    "rt_sigprocmask",
    "seccomp",
    "sendto",
    "set_robust_list",
    "set_tid_address",
    "setsockopt",
    "socket",
    "uname",
    "vfork",
    "wait4",
    "write",

    # Important baseline
    "sigaltstack",
    "clock_gettime",
    "exit",
]

def _apply_seccomp(extra_syscalls: list[str]) -> None:
    f = seccomp.SyscallFilter(defaction=seccomp.KILL)
    for name in BASELINE_SYSCALLS + extra_syscalls:
        f.add_rule(seccomp.ALLOW, name)
    f.load()


def _handle_file_read(path: str) -> str:
    Landlock().allow_read(str(Path(path).parent)).apply()  #definit la zone autorisee
    _apply_seccomp([])
    return Path(path).read_text()


def _handle_file_write(path: str, content: str) -> str:
    Landlock().allow_read_write(str(Path(path).parent)).apply()
    _apply_seccomp([])
    Path(path).write_text(content)
    return ""


def _handle_tool_exec(script_path: str, kwargs: dict) -> str:
    script_dir = str(Path(script_path).resolve().parent)
    Landlock().allow_read(script_dir, STDLIB_DIR).apply()
    _apply_seccomp([])
    spec = importlib.util.spec_from_file_location("tool_module", script_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.run(**kwargs)
    return json.dumps(result)


def _handle_network_call(method: str, url: str, port: int, body: dict | None) -> str:
    Landlock().allow_network(port, bind=False, connect=True).apply()
    _apply_seccomp(["socket", "connect", "sendto", "recvfrom", "getsockopt", "setsockopt"])
    resp = httpx.request(method, url, json=body, timeout=5.0)
    resp.raise_for_status()
    return resp.text


def main() -> None:
    request = json.loads(sys.argv[1])
    op = request["operation"]
    if op == "file_read":
        result = _handle_file_read(request["path"])
    elif op == "file_write":
        result = _handle_file_write(request["path"], request["content"])
    elif op == "tool_exec":
        result = _handle_tool_exec(request["script_path"], request.get("kwargs", {}))
    elif op == "network_call":
        result = _handle_network_call(request["method"], request["url"], request["port"], request.get("body"))
    else:
        raise ValueError(f"Opération inconnue: {op}")
    sys.stdout.write(result)


if __name__ == "__main__":
    main()