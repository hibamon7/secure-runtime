import os
from pathlib import Path
from urllib.parse import urlparse
from app.llm import ask_llm
from app.runtime.input_guardrails.input_guardrails import check_prompt
from app.runtime.policy_engine.main import PolicyEngine
import logging
from app.auth.schemas import TokenPayload
from app.runtime.tool_manager.main import get_tool_script
from app.runtime.sandbox_manager.wiring import _run_sandboxed
from app.runtime.sandbox_manager.authorization_receipt import AuthorizationReceipt


logger = logging.getLogger("policy_engine") #sert à créer un objet logger pour enregistrer les événements liés au moteur de politique. Cela permet de suivre les décisions de politique, les erreurs et d'autres informations pertinentes pour le débogage et l'audit.

def _to_subject(user: TokenPayload) -> dict:
    return {"role": user.role, "scopes": user.scopes, "sub": user.sub}

def _identifier_from_resource(resource: dict) -> str:
    rtype = resource.get("type")
    if rtype == "file":
        return resource["path"]
    if rtype == "tool":
        return resource["tool_name"]
    if rtype == "network":
        return f"{resource.get('domain')}:{resource.get('port')}"
    if rtype in ("llm", "api"):
        return rtype  # pas de sandbox associé — le reçu est construit puis simplement ignoré par l'appelant
    raise ValueError(f"Type de ressource inconnu pour reçu: {rtype}")


class Runtime:

    def __init__(self, policy_rules_path: str = "app/runtime/policy_engine/rules.json"):
        self.policy_engine = PolicyEngine(policy_rules_path)
        self.audit = None


    async def _authorize(self, current_user: TokenPayload, resource: dict, action: str) -> AuthorizationReceipt:
        decision = self.policy_engine.evaluate(_to_subject(current_user), resource, action)
        logger.info(
            "policy_decision: version=%s sub=%s resource=%s action=%s allowed=%s rule=%s",
            self.policy_engine.version, current_user.sub, resource.get("type"),
            action, decision.allowed, decision.matched_rule_id,
        )
        if not decision.allowed:
            raise PermissionError(decision.reason)
        return AuthorizationReceipt(
            resource_type=resource.get("type"), action=action,
            identifier=_identifier_from_resource(resource),
        )   
        
    async def ask(self, prompt: str, current_user: TokenPayload) -> str:
        check_prompt(prompt)
        await self._authorize(current_user, resource={"type": "llm"}, action="ask")
        return await self._call_llm(prompt)

    async def read_file(self, path: str, current_user: TokenPayload | None = None) -> str:
        resolved = str(Path(path).resolve())
        try:
            size_mb = os.path.getsize(resolved) / (1024 * 1024)
        except OSError:
            size_mb = 0
        resource = {"type": "file", "path": resolved, "file_size_mb": size_mb}
        receipt = await self._authorize(current_user, resource, "read")
        return await _run_sandboxed(receipt, "file_read", identifier=resolved, worker_kwargs={"path": resolved})


    async def write_file(self, path: str, content: str, current_user: TokenPayload | None = None) -> None:
        resolved = str(Path(path).resolve())
        resource = {"type": "file", "path": resolved, "file_size_mb": len(content.encode()) / 1_048_576}
        receipt = await self._authorize(current_user, resource, "write")
        await _run_sandboxed(receipt, "file_write", identifier=resolved, worker_kwargs={"path": resolved, "content": content})
    #Policy Engine vérifié avant Landlock — le check le moins cher (comparaison de strings en mémoire) élimine les cas évidents avant de payer le coût d'un fork/exec

    async def _http_request(self, method: str, url: str, **kwargs) -> dict:
        import httpx
        # follow_redirects reste False (défaut httpx) : une redirection ne contourne pas l'allowlist
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.request(method, url, **kwargs)
            resp.raise_for_status() #this line checks if the HTTP response status code indicates an error (4xx or 5xx). If it does, it raises an exception, which can be caught and handled by the caller. This is important for ensuring that the application can gracefully handle failed HTTP requests and provide appropriate feedback or error messages to the user.
            return resp.json()
    
    async def call_api(self, url: str, current_user: TokenPayload, method: str = "GET", **kwargs) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        # Deux vérifications distinctes, deux lignes différentes du modèle de menaces :
        await self._authorize(current_user, resource={"type": "api"}, action="call")
        net_resource = {"type": "network", "domain": domain, "port": port}
        receipt = await self._authorize(current_user, net_resource, "connect")

        result = await _run_sandboxed(
            receipt, "network_call", identifier=f"{domain}:{port}",
            worker_kwargs={"method": method, "url": url, "port": port, "body": kwargs.get("json")},
        )
        return json.loads(result)

    async def execute_tool(self, name: str, current_user: TokenPayload, **kwargs):
        resource = {"type": "tool", "tool_name": name}
        receipt = await self._authorize(current_user, resource, "execute")
        script_path = get_tool_script(name)
        if script_path is None:
            raise ValueError(f"Outil '{name}' non implémenté")
        result = await _run_sandboxed(
            receipt, "tool_exec", identifier=name,
            worker_kwargs={"script_path": script_path, "kwargs": kwargs},
        )
        return json.loads(result)

    async def query_rag(self, query: str) -> list[str]:
        # TODO (Jour 14-15) : pipeline RAG + RAG Security Layer
        raise NotImplementedError("RAG pas encore câblé")

    async def _call_llm(self, prompt: str) -> str:
         return await ask_llm(prompt)

    