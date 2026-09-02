import json
from pathlib import Path

_KNOWN_KEYS = {"version", "dangerous_syscalls", "cgroup_defaults", "subprocess_timeout_seconds"}
_KNOWN_CGROUP_KEYS = {"memory_max_mb", "pids_max", "cpu_percent"}

# Syscalls nécessaires au fonctionnement de base de CPython + I/O simple.
# Obtenu par observation empirique (mode strace).
#DANGEROUS_SYSCALLS =
#  "execve", "execveat",              # empêche de lancer un autre programme
#   "fork", "vfork", "clone", "clone3", # empêche de créer d'autres processus
#   "ptrace",                           # empêche d'espionner/manipuler un autre process
#   "mount", "umount2",                 # empêche de modifier le système de fichiers monté
#   "reboot", "kexec_load",             # empêche d'agir sur la machine elle-même
#   "init_module", "delete_module",     # empêche de charger du code dans le noyau
#   "setuid", "setgid", "setreuid", "setregid",  # empêche de changer d'identité

def load_sandbox_config(path: str = "app/runtime/policy_engine/sandbox.json") -> dict:
    data = json.loads(Path(path).read_text())
    unknown = set(data.keys()) - _KNOWN_KEYS
    if unknown:
        raise ValueError(f"sandbox.json: clé(s) inconnue(s) {unknown}")
    bad = set(data.get("cgroup_defaults", {}).keys()) - _KNOWN_CGROUP_KEYS
    if bad:
        raise ValueError(f"sandbox.json: cgroup_defaults: clé(s) inconnue(s) {bad}")
    return data