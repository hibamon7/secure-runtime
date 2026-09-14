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
import certifi #cette biblio cntient les certifs, c est a dire les clés publiques des autorités de certification, pour vérifier l'identité des serveurs lors des connexions HTTPS
import pyseccomp as seccomp
import httpx
import encodings.idna
_ = httpx.Client()

# Force l'initialisation de py_landlock (chargement de libc via ctypes.util.find_library,
# qui lance un sous-processus — impossible une fois execve bloqué par seccomp).
from py_landlock import AccessFs, Landlock, get_abi_version
_ = get_abi_version()




def _apply_seccomp(dangerous_syscalls: list[str]) -> None:
    try:
        f = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
        for name in dangerous_syscalls:
            f.add_rule(seccomp.KILL, name)
        f.load()
    except PermissionError as e:
        # Connu sous WSL2 : un filtre seccomp est parfois déjà attaché à PID 1
        # et hérité par tous les processus enfants (microsoft/WSL#9548, #9993).
        # Pas un bug applicatif — Landlock reste actif et constitue la protection
        # principale ; seccomp se dégrade plutôt que de bloquer l'opération.
        print(f"seccomp indisponible ({e}) — Landlock reste actif.", file=sys.stderr)


def _handle_file_read(path: str, dangerous_syscalls: list[str]) -> str:
    Landlock().allow_read(str(Path(path).parent)).apply()
    _apply_seccomp(dangerous_syscalls)
    return Path(path).read_text()


def _handle_file_write(path: str, content: str, dangerous_syscalls: list[str]) -> str:
    Landlock().allow_read_write(str(Path(path).parent)).apply()
    _apply_seccomp(dangerous_syscalls)
    Path(path).write_text(content)
    return ""


def _handle_tool_exec(script_path: str, kwargs: dict, dangerous_syscalls: list[str]) -> str:
    resolved_script = str(Path(script_path).resolve())
    Landlock().add_path_rule(resolved_script, access=AccessFs.READ_FILE).apply()
    _apply_seccomp(dangerous_syscalls)
    spec = importlib.util.spec_from_file_location("tool_module", resolved_script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return json.dumps(module.run(**kwargs))


def _handle_network_call(method: str, url: str, port: int, body: dict | None, dangerous_syscalls: list[str]) -> str:
    (Landlock()
        .add_path_rule(certifi.where(), access=AccessFs.READ_FILE)
        .add_path_rule("/etc/resolv.conf", access=AccessFs.READ_FILE)
        .add_path_rule("/etc/hosts", access=AccessFs.READ_FILE)
        .add_path_rule("/etc/nsswitch.conf", access=AccessFs.READ_FILE)
        .allow_network(port, bind=False, connect=True)
        .apply()
    )
    _apply_seccomp(dangerous_syscalls)
    resp = httpx.request(method, url, json=body, timeout=5.0)
    resp.raise_for_status()
    return resp.text



def main() -> None:
    try:
        request = json.loads(sys.argv[1])
        dangerous_syscalls = request["dangerous_syscalls"]
        op = request["operation"]
        if op == "file_read":
            result = _handle_file_read(request["path"], dangerous_syscalls)
        elif op == "file_write":
            result = _handle_file_write(request["path"], request["content"], dangerous_syscalls)
        elif op == "tool_exec":
            result = _handle_tool_exec(request["script_path"], request.get("kwargs", {}), dangerous_syscalls)
        elif op == "network_call":
            result = _handle_network_call(request["method"], request["url"], request["port"], request.get("body"), dangerous_syscalls)
        else:
            raise ValueError(f"Opération inconnue: {op}")
        sys.stdout.write(result)
    except PermissionError as e:
        print(json.dumps({"category": "landlock_denial", "detail": str(e)}), file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(json.dumps({"category": "infra_failure", "detail": f"{type(e).__name__}: {e}"}), file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()