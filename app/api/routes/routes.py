from fastapi import APIRouter, Request, Depends, HTTPException
from app.dependancies import get_runtime
from app.runtime.main import Runtime
from app.models.schemas import AskRequest
from app.rate_limiting import limiter
from app.runtime.input_guardrails.input_guardrails import GuardrailViolation
from app.dependancies import get_current_user
from app.auth.schemas import TokenPayload


router = APIRouter()

@router.post("/ask")
@limiter.limit("10/minute")
async def ask_endpoint(request: Request,payload: AskRequest, runtime: Runtime = Depends(get_runtime),current_user: TokenPayload = Depends(get_current_user)):
    try:
        response = await runtime.ask(payload.prompt, current_user=current_user)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except GuardrailViolation as e:
        raise HTTPException(status_code=400, detail=f"Requête bloquée: {e.reason}")
    return {"response": response}


