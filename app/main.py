from fastapi import FastAPI
from app.api.routes.routes import router
from app.api.routes import auth as auth_router
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.rate_limiting import limiter


app = FastAPI()

app.include_router(router)
app.include_router(auth_router.router, prefix="/auth", tags=["auth"]) #auth_router est le module qui contient les routes d'authentification, et on les inclut dans l'application FastAPI avec le préfixe /auth pour que toutes les routes d'authentification soient accessibles via /auth/...
#les tags=["auth"] sont utilisés pour regrouper les routes d'authentification dans la documentation générée par FastAPI (Swagger UI). Cela permet de mieux organiser et présenter les différentes parties de l'API.

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)