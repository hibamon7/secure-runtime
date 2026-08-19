import os
from py_landlock import Landlock, get_abi_version, LandlockNotAvailableError

def main():
    try:
        version = get_abi_version() #gets the ABI version of the Landlock kernel module
        print(f"Landlock ABI v{version} disponible")
    except LandlockNotAvailableError as e:
        raise SystemExit(f"Landlock indisponible sur ce noyau: {e}")  # fail-closed, pas de fallback silencieux

    os.makedirs("/tmp/landlock_test/allowed", exist_ok=True)
    with open("/tmp/landlock_test/allowed/ok.txt", "w") as f:
        f.write("visible")
    with open("/tmp/landlock_test/forbidden.txt", "w") as f:
        f.write("invisible")

    Landlock().allow_read("/tmp/landlock_test/allowed").apply()  # si on veut lire dans un autre path il faut ajouter un allow_read() pour ce path

    with open("/tmp/landlock_test/allowed/ok.txt") as f:
        print("Lecture autorisée OK:", f.read())

    try:
        open("/tmp/landlock_test/forbidden.txt").read()
        print("ERREUR: lecture hors périmètre non bloquée")
    except PermissionError:
        print("Lecture hors périmètre bloquée comme attendu")

if __name__ == "__main__":
    main()