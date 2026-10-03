from fastapi import APIRouter, Request, Depends, HTTPException
from app.dependancies import get_runtime, get_current_user
from app.runtime.main import Runtime
from app.rate_limiting import limiter
from app.runtime.input_guardrails.input_guardrails import GuardrailViolation
from app.auth.schemas import TokenPayload
from app.models.schemas import (
    AskRequest, ReadFileRequest, WriteFileRequest,
    ExecuteToolRequest, CallApiRequest, QueryRagRequest,
)


router = APIRouter()


def _to_http_error(e: Exception) -> HTTPException:
    """Traduit les exceptions du Runtime en codes HTTP distincts :
    403 = refus de sécurité légitime, 500 = panne du mécanisme lui-même,
    400 = requête bloquée par les guardrails d'entrée."""
    if isinstance(e, GuardrailViolation):
        return HTTPException(status_code=400, detail=f"Requête bloquée: {e.reason}")
    if isinstance(e, PermissionError):
        return HTTPException(status_code=403, detail=str(e))
    if isinstance(e, RuntimeError):
        return HTTPException(status_code=500, detail=f"Sandbox indisponible: {e}")
    return HTTPException(status_code=500, detail=str(e))


@router.post("/ask")
@limiter.limit("10/minute")
async def ask_endpoint(
    request: Request,
    payload: AskRequest,
    runtime: Runtime = Depends(get_runtime),
    current_user: TokenPayload = Depends(get_current_user),
):
    try:
        response = await runtime.ask(payload.prompt, current_user=current_user)
    except Exception as e:
        raise _to_http_error(e)
    return {"response": response}


@router.post("/ask-with-context")
@limiter.limit("10/minute")
async def ask_with_context_endpoint(
    request: Request,
    payload: AskRequest,
    runtime: Runtime = Depends(get_runtime),
    current_user: TokenPayload = Depends(get_current_user),
):
    try:
        response = await runtime.ask_with_context(payload.prompt, current_user=current_user)
    except Exception as e:
        raise _to_http_error(e)
    return {"response": response}


@router.post("/read-file")
@limiter.limit("20/minute")
async def read_file_endpoint(
    request: Request,
    payload: ReadFileRequest,
    runtime: Runtime = Depends(get_runtime),
    current_user: TokenPayload = Depends(get_current_user),
):
    try:
        content = await runtime.read_file(payload.path, current_user=current_user)
    except Exception as e:
        raise _to_http_error(e)
    return {"content": content}


@router.post("/write-file")
@limiter.limit("20/minute")
async def write_file_endpoint(
    request: Request,
    payload: WriteFileRequest,
    runtime: Runtime = Depends(get_runtime),
    current_user: TokenPayload = Depends(get_current_user),
):
    try:
        await runtime.write_file(payload.path, payload.content, current_user=current_user)
    except Exception as e:
        raise _to_http_error(e)
    return {"status": "written", "path": payload.path}


@router.post("/execute-tool")
@limiter.limit("20/minute")
async def execute_tool_endpoint(
    request: Request,
    payload: ExecuteToolRequest,
    runtime: Runtime = Depends(get_runtime),
    current_user: TokenPayload = Depends(get_current_user),
):
    kwargs = {}
    if payload.expression is not None:
        kwargs["expression"] = payload.expression
    try:
        result = await runtime.execute_tool(payload.name, current_user=current_user, **kwargs)
    except Exception as e:
        raise _to_http_error(e)
    return {"result": result}


@router.post("/call-api")
@limiter.limit("20/minute")
async def call_api_endpoint(
    request: Request,
    payload: CallApiRequest,
    runtime: Runtime = Depends(get_runtime),
    current_user: TokenPayload = Depends(get_current_user),
):
    try:
        result = await runtime.call_api(payload.url, current_user=current_user, method=payload.method)
    except Exception as e:
        raise _to_http_error(e)
    return {"result": result}


@router.post("/query-rag")
@limiter.limit("20/minute")
async def query_rag_endpoint(
    request: Request,
    payload: QueryRagRequest,
    runtime: Runtime = Depends(get_runtime),
    current_user: TokenPayload = Depends(get_current_user),
):
    try:
        documents = await runtime.query_rag(payload.query, current_user=current_user, n_results=payload.n_results)
    except Exception as e:
        raise _to_http_error(e)
    return {"documents": documents}




