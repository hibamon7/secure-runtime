#!/bin/bash
set -euo pipefail #cette ligne permet d'arreter le cript si une commande echoue ou une variable non definie est utilisee
#sert a creer un cgroup pour l'application et a deleguer les droits d'ecriture sur ce cgroup a l'utilisateur runtime_user

CONTAINER_CG="/sys/fs/cgroup"
APP_CG="$CONTAINER_CG/runtime-app"
MAIN_CG="$APP_CG/main"

mkdir -p "$MAIN_CG" || {
    echo "ERROR: cannot create $MAIN_CG"
    exit 1
}




# Donne à runtime_user les droits nécessaires pour manipuler
# les processus dans le cgroup, mais laisse la configuration
# des contrôleurs au processus root.
chown runtime_user:runtime_user \
    "$APP_CG" \
    "$APP_CG/cgroup.procs"

chown runtime_user:runtime_user \
    "$MAIN_CG/cgroup.procs"


# Place le futur processus applicatif dans la feuille main/, pas dans
# runtime-app/ lui-même — c'est ce qui rend la délégation possible.
echo $$ > "$MAIN_CG/cgroup.procs"

# Vérifie que le processus a bien été déplacé avant d'activer les contrôleurs.

# Les contrôleurs doivent d'abord être activés au niveau du parent
# afin d'être disponibles pour runtime-app/.
echo "+memory +pids +cpu" > "$CONTAINER_CG/cgroup.subtree_control"

# Active ensuite les contrôleurs pour les enfants de runtime-app/ — licite ici
# puisque runtime-app/ lui-même ne contiendra jamais de processus.
echo "+memory +pids +cpu" > "$APP_CG/cgroup.subtree_control"

export SANDBOX_CGROUP_BASE="$APP_CG"

#Maintenant que la préparation privilégiée est terminée
#exécute l'application en tant que runtime_user.
exec gosu runtime_user "$@"
