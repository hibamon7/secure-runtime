import os
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError #jose est une bibliothèque qui permet de créer et de vérifier des JSON Web Tokens (JWT) en Python. Elle fournit des fonctionnalités pour encoder et décoder des JWT, ainsi que pour gérer les algorithmes de signature et de chiffrement.
import bcrypt



SECRET_KEY = os.environ["JWT_SECRET_KEY"]
ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
ACCESS_EXPIRE_MIN = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
REFRESH_EXPIRE_DAYS = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", 7))

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def create_token(subject: str, role: str, scopes: list[str], expires_delta: timedelta, token_type: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "role": role,
        "scopes": scopes,      # <- ce que le Policy Engine lira plus tard
        "type": token_type,    # "access" ou "refresh"
        "iat": now,
        "exp": now + expires_delta,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM) 

def create_access_token(subject: str, role: str, scopes: list[str]) -> str:
    return create_token(subject, role, scopes, timedelta(minutes=ACCESS_EXPIRE_MIN), "access")

def create_refresh_token(subject: str, role: str, scopes: list[str]) -> str:
    return create_token(subject, role, scopes, timedelta(days=REFRESH_EXPIRE_DAYS), "refresh")

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]) 
    except JWTError:
        raise ValueError("Token invalide ou expiré")