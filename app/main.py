from fastapi import FastAPI
from app.api.routes.routes import router
from app.api.routes import auth as auth_router
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.rate_limiting import limiter
import logging
from app.runtime.audit_manager.main import configure_audit_logging
from py_landlock import Landlock
from fastapi.responses import FileResponse
from app.api import audit as audit_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")

configure_audit_logging()

app = FastAPI()


app.include_router(router)
app.include_router(auth_router.router, prefix="/auth", tags=["auth"])
app.include_router(audit_router.router, tags=["audit"])

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)



@app.get("/", include_in_schema=False)
async def demo_console():
    """Console de démonstration — interface web exerçant chaque méthode
    du Runtime et affichant le journal d'audit en direct."""
    return FileResponse("app/index.html")



