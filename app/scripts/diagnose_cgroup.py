"""Diagnostic cgroup v2 pour le mode natif (WSL / dual-boot / Linux).

Reproduit, étape par étape et sans rien masquer, ce que fait le Runtime pour
préparer le sandbox, puis teste la disposition « feuille + parent » utilisée par
l'entrypoint Docker. Aucune écriture hors de l'arbre cgroup du processus courant.

Usage :
    python app/scripts/diagnose_cgroup.py
    systemd-run --user --scope -p Delegate=yes -- python app/scripts/diagnose_cgroup.py
"""
import os
import stat
import sys
from pathlib import Path

LIMITS = [("memory.max", "268435456"), ("pids.max", "32"), ("cpu.max", "50000 100000")]


def info(label, value):
    print(f"{label:<38} {value}")


def read(p):
    try:
        return Path(p).read_text().strip()
    except OSError as e:
        return f"<illisible: {e}>"


def owner(p):
    try:
        st = Path(p).stat()
        return f"uid={st.st_uid} mode={stat.filemode(st.st_mode)}"
    except OSError as e:
        return f"<{e}>"


if not Path("/sys/fs/cgroup/cgroup.controllers").exists():
    sys.exit("cgroup v2 (unifié) absent sur cette machine : /sys/fs/cgroup/cgroup.controllers introuvable. Le sandbox cgroup ne peut pas fonctionner ici.")

rel = Path("/proc/self/cgroup").read_text().strip().split(":")[-1].lstrip("/")
base = Path("/sys/fs/cgroup") / rel
info("uid courant", os.getuid())
info("cgroup du processus", f"/{rel}")
info("propriétaire du cgroup", owner(base))
info("cgroup.controllers (disponibles)", read(base / "cgroup.controllers"))
info("cgroup.subtree_control (activés)", read(base / "cgroup.subtree_control"))
info("parent: cgroup.subtree_control", read(base.parent / "cgroup.subtree_control"))
print()

print("== Étape A : disposition actuelle du Runtime (enfant directement sous le cgroup courant) ==")
child = base / f"diag-A-{os.getpid()}"
try:
    child.mkdir()
    info("mkdir enfant", "OK")
    info("fichiers de l'enfant", sorted(p.name for p in child.iterdir() if p.name.split('.')[0] in ('memory', 'pids', 'cpu')))
    for name, value in LIMITS:
        target = child / name
        info(f"{name} propriétaire", owner(target))
        try:
            target.write_text(value)
            info(f"écriture {name}", "OK")
        except OSError as e:
            info(f"écriture {name}", f"ÉCHEC -> {e}")
except OSError as e:
    info("mkdir enfant", f"ÉCHEC -> {e}")
finally:
    try:
        child.rmdir()
    except OSError:
        pass
print()

print("== Étape B : disposition feuille/parent (celle de l'entrypoint Docker) ==")
leaf = base / f"diag-leaf-{os.getpid()}"
try:
    leaf.mkdir()
    (leaf / "cgroup.procs").write_text(str(os.getpid()))
    info("déplacement du processus dans la feuille", "OK")
    (base / "cgroup.subtree_control").write_text("+memory +pids +cpu")
    info("activation +memory +pids +cpu sur le parent", "OK")
    work = base / f"diag-B-{os.getpid()}"
    work.mkdir()
    for name, value in LIMITS:
        (work / name).write_text(value)
        info(f"écriture {name}", "OK")
    work.rmdir()
    print("\n=> Étape B réussit : la préparation feuille/parent au démarrage de l'application suffit.")
except OSError as e:
    info("ÉCHEC", e)
    print("\n=> Étape B échoue : le cgroup n'est pas délégué avec ces contrôleurs ; envoyer cette sortie complète.")
finally:
    try:
        (base / "cgroup.procs").write_text(str(os.getpid()))  # best-effort : retour ; sinon le processus meurt avec le script
    except OSError:
        pass
    try:
        leaf.rmdir()
    except OSError:
        pass
