from fastapi import APIRouter, Depends, HTTPException, status 
from fastapi.security import OAuth2PasswordRequestForm

from app.auth.security import verify_password, create_access_token, create_refresh_token, decode_token
from app.auth.users_db import get_user
from app.auth.schemas import Token, RefreshRequest
from app.auth.users_db import create_user
from app.auth.schemas import RegisterRequest


router = APIRouter()


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest):
    try:
        create_user(payload.username, payload.password)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Nom d'utilisateur déjà pris")
    return {"message": f"Utilisateur '{payload.username}' créé"}


@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Identifiants invalides")

    access = create_access_token(user["username"], user["role"], user["scopes"])
    refresh = create_refresh_token(user["username"], user["role"], user["scopes"])
    return Token(access_token=access, refresh_token=refresh)


@router.post("/refresh", response_model=Token)
async def refresh(payload: RefreshRequest):
    try:
        data = decode_token(payload.refresh_token)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token invalide")

    if data.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Ce n'est pas un refresh token")

    new_access = create_access_token(data["sub"], data["role"], data["scopes"])
    new_refresh = create_refresh_token(data["sub"], data["role"], data["scopes"])
    return Token(access_token=new_access, refresh_token=new_refresh)