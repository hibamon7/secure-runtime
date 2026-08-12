from app.runtime.main import Runtime
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.auth.security import decode_token
from app.auth.schemas import TokenPayload

_runtime_instance = Runtime()
#c'est important de garder une seule instance de Runtime pour l'application, pour éviter de recréer des objets inutiles et pour partager l'état si nécessaire., et si on desire modifier le runtime ou par exemple ajouter plusieurs routes on a pas besoin de recreer l instance a chaque fois

def get_runtime() -> Runtime:
    return _runtime_instance

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login") #sert à extraire le token d'accès de l'en-tête Authorization de la requête HTTP. Il est utilisé pour sécuriser les routes qui nécessitent une authentification.


def get_current_user(token: str = Depends(oauth2_scheme)) -> TokenPayload:
    try:
        data = decode_token(token)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalide")
    if data.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Ce n'est pas un access token")
    return TokenPayload(sub=data["sub"], role=data["role"], scopes=data["scopes"])

