from app.auth.security import hash_password

FAKE_USERS_DB = {
    "alice": {
        "username": "alice",
        "hashed_password": hash_password("alice_pwd"),
        "role": "admin",
        "scopes": ["file:read", "file:write", "tool:execute", "api:call"],
    },
    "bob": {
        "username": "bob",
        "hashed_password": hash_password("bob_pwd"),
        "role": "user",
        "scopes": ["file:read"],
    },
}

def get_user(username: str) -> dict | None:
    return FAKE_USERS_DB.get(username)

def user_exists(username: str) -> bool:
    return username in FAKE_USERS_DB

def create_user(username: str, password: str) -> dict:
    if user_exists(username):
        raise ValueError("Username already taken")
    user = {
        "username": username,
        "hashed_password": hash_password(password),
        "role": "user",           # toujours "user" par défaut, jamais fourni par le client
        "scopes": ["file:read"],  # scope minimal par défaut
    }
    FAKE_USERS_DB[username] = user
    return user