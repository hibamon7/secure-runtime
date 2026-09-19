#!/bin/bash
set -euo pipefail #cette ligne permet d'arreter le cript si une commande echoue ou une variable non definie est utilisee
#sert a creer un cgroup pour l'application et a deleguer les droits d'ecriture sur ce cgroup a l'utilisateur runtime_user

CONTAINER_CG="/sys/fs/cgroup$(cat /proc/self/cgroup | cut -d: -f3)"
APP_CG="$CONTAINER_CG/runtime-app"
MAIN_CG="$APP_CG/main"

mkdir -p "$MAIN_CG"


# Délègue runtime-app/ (jamais son parent) — seul nœud où runtime_user doit
# pouvoir créer de nouveaux sous-cgroups.
chown runtime_user:runtime_user \
    "$APP_CG" \
    "$APP_CG/cgroup.procs" \
    "$APP_CG/cgroup.subtree_control"

chown runtime_user:runtime_user \
    "$MAIN_CG/cgroup.procs"

# Active les contrôleurs pour les enfants de runtime-app/ — licite ici
# puisque runtime-app/ lui-même ne contiendra jamais de processus.
echo "+memory +pids +cpu" > "$APP_CG/cgroup.subtree_control"

# Place le futur processus applicatif dans la feuille main/, pas dans
# runtime-app/ lui-même — c'est ce qui rend la délégation possible.
echo $$ > "$MAIN_CG/cgroup.procs"

export SANDBOX_CGROUP_BASE="$APP_CG"

#Maintenant que la préparation privilégiée est terminée
#exécute l'application en tant que runtime_user.
exec gosu runtime_user "$@"