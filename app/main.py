from fastapi import FastAPI
from app.api.routes.routes import router
from app.api.routes import auth as auth_router
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.rate_limiting import limiter
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s") #pour enregistrer les événements liés au moteur de politique, les erreurs et d'autres informations pertinentes pour le débogage et l'audit. Cela permet de suivre les décisions de politique, les erreurs et d'autres informations pertinentes pour le débogage et l'audit.
from py_landlock import Landlock


#Ce bloc crée un plafond de permissions filesystem pour ton serveur avant toute requête :
# data, policies, logs et /tmp restent accessibles, le reste est bloqué, et si Landlock ne peut pas être appliqué, le serveur s'arrête.
def apply_static_baseline_restriction() -> None:
    """Restriction PERMANENTE du process principal, appliquée UNE FOIS avant que
    uvicorn n'accepte la moindre requête. C'est un plafond : chaque sous-processus
    en hérite et ne peut que le restreindre davantage, jamais l'élargir — doit
    donc rester un sur-ensemble généreux des besoins présents et futurs
    (ex. futur répertoire RAG du Jour 14)."""
    try:
        Landlock().allow_read_write("data", "policies", "logs", "/tmp").apply()
    except Exception as e:
        raise SystemExit(f"Landlock indisponible — arrêt fail-closed: {e}")

apply_static_baseline_restriction()  # avant app = FastAPI(...)

app = FastAPI()

app.include_router(router)
app.include_router(auth_router.router, prefix="/auth", tags=["auth"]) #auth_router est le module qui contient les routes d'authentification, et on les inclut dans l'application FastAPI avec le préfixe /auth pour que toutes les routes d'authentification soient accessibles via /auth/...
#les tags=["auth"] sont utilisés pour regrouper les routes d'authentification dans la documentation générée par FastAPI (Swagger UI). Cela permet de mieux organiser et présenter les différentes parties de l'API.

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)