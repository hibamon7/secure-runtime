from app.llm import ask_llm
from app.runtime.input_guardrails.input_guardrails import check_prompt

class Runtime:

    def __init__(self):
        self.policy_engine = None 
        self.audit = None     

    async def ask(self, prompt: str, user: str | None = None) -> str:
        # TODO (Jour 8) : policy_engine.evaluate() avant l'appel LLM
        check_prompt(prompt)
        return await self._call_llm(prompt)

    async def read_file(self, path: str, user: str | None = None) -> str:
        # TODO (Jour 11) : policy check + exécution sous Landlock
        with open(path, "r") as f:
            return f.read()

    async def write_file(self, path: str, content: str, user: str | None = None) -> None:
        # TODO (Jour 11) : policy check + Landlock
        with open(path, "w") as f:
            f.write(content)

    async def call_api(self, url: str, method: str = "GET", **kwargs) -> dict:
        # TODO (Jour 9) : policy check + Network Manager (allowlist)
        import httpx
        async with httpx.AsyncClient() as client: #outil pour communiquer en HTTP de manière asynchrone
            resp = await client.request(method, url, **kwargs)
            return resp.json()

    async def execute_tool(self, name: str, **kwargs):
        # TODO (Jour 9 + 12) : policy check + seccomp-bpf
        raise NotImplementedError(f"Outil '{name}' pas encore câblé")

    async def query_rag(self, query: str) -> list[str]:
        # TODO (Jour 14-15) : pipeline RAG + RAG Security Layer
        raise NotImplementedError("RAG pas encore câblé")

    async def _call_llm(self, prompt: str) -> str:
         return await ask_llm(prompt)