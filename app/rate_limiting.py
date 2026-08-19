from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address #remote_address est une fonction utilitaire fournie par la bibliothèque slowapi. Elle est utilisée pour obtenir l'adresse IP du client à partir de la requête HTTP entrante. Cette adresse IP est ensuite utilisée comme clé pour appliquer les limites de débit (rate limiting) sur les requêtes provenant de ce client spécifique.
from app.auth.security import decode_token

def key_func(request: Request) -> str: 
    """Identifie par sub du JWT si présent, sinon fallback IP."""
    auth_header = request.headers.get("Authorization", "") 
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        try:
            return decode_token(token).get("sub", get_remote_address(request))
        except ValueError: #value error est levée si le token est invalide ou expiré, dans ce cas on retourne l'adresse IP du client comme fallback pour l'identification
            pass
    return get_remote_address(request)

limiter = Limiter(key_func=key_func) #here the limiter applies the limiting rate on the ip/user id that the key_func returns
