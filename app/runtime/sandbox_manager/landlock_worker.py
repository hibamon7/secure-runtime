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
import certifi  # à ajouter en haut de landlock_worker.py, avec les autres imports

from py_landlock import AccessFs

from py_landlock import Landlock
import pyseccomp as seccomp
import sysconfig 
import httpx
import encodings.idna
_ = httpx.Client()



STDLIB_DIR = sysconfig.get_path("stdlib") #demande à l'installation Python actuelle où se trouve sa standard library sur le disque. 

# Syscalls nécessaires au fonctionnement de base de CPython + I/O simple.
# Obtenu par observation empirique (mode LOG) — à revalider si ça casse.
DANGEROUS_SYSCALLS = [
    "execve", "execveat",              # empêche de lancer un autre programme
    "fork", "vfork", "clone", "clone3", # empêche de créer d'autres processus
    "ptrace",                           # empêche d'espionner/manipuler un autre process
    "mount", "umount2",                 # empêche de modifier le système de fichiers monté
    "reboot", "kexec_load",             # empêche d'agir sur la machine elle-même
    "init_module", "delete_module",     # empêche de charger du code dans le noyau
    "setuid", "setgid", "setreuid", "setregid",  # empêche de changer d'identité
]

def _apply_seccomp() -> None:
    f = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
    try:
        for name in DANGEROUS_SYSCALLS:
            f.add_rule(seccomp.KILL, name)
        f.load()
    except PermissionError as e:
        # Connu sous WSL2 : un filtre seccomp est parfois déjà attaché à PID 1
        # et hérité par tous les processus enfants (microsoft/WSL#9548, #9993).
        # Pas un bug applicatif — Landlock reste actif et constitue la protection
        # principale ; seccomp se dégrade plutôt que de bloquer l'opération.
        print(f"seccomp indisponible ({e}) — Landlock reste actif.", file=sys.stderr)


def _handle_file_read(path: str) -> str:
    _apply_seccomp()
    Landlock().allow_read(str(Path(path).parent)).apply()
    return Path(path).read_text()

def _handle_file_write(path: str, content: str) -> str:
    _apply_seccomp()
    Landlock().allow_read_write(str(Path(path).parent)).apply()
    Path(path).write_text(content)
    return ""

def _handle_tool_exec(script_path: str, kwargs: dict) -> str:
    resolved_script = str(Path(script_path).resolve())
    _apply_seccomp()
    Landlock().add_path_rule(resolved_script, access=AccessFs.READ_FILE).apply()
    spec = importlib.util.spec_from_file_location("tool_module", resolved_script) #this is to load the code of the tool
    module = importlib.util.module_from_spec(spec) #the module is a representation of the code in memory, it is not executed yet
    spec.loader.exec_module(module) #this line executes the code of the tool
    return json.dumps(module.run(**kwargs)) #this line returns the result of the run as a json object

def _handle_network_call(method: str, url: str, port: int, body: dict | None) -> str:
    _apply_seccomp()
    (
        Landlock()
        .add_path_rule(certifi.where(), access=AccessFs.READ_FILE)
        .add_path_rule("/etc/resolv.conf", access=AccessFs.READ_FILE)
        .add_path_rule("/etc/hosts", access=AccessFs.READ_FILE)
        .add_path_rule("/etc/nsswitch.conf", access=AccessFs.READ_FILE)
        .allow_network(port, bind=False, connect=True) #bind means the process only listens to the port
        .apply()
    )
    resp = httpx.request(method, url, json=body, timeout=5.0)

    print(
        f"HTTP status={resp.status_code}, "
        f"content_length={len(resp.content)}",
        file=sys.stderr,
    )


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