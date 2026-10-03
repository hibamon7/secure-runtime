from pydantic import BaseModel, Field


class AskRequest(BaseModel):
    prompt: str = Field(min_length=1, description="The prompt to send to the model for generating a response.")


class AskResponse(BaseModel):
    response: str


class ReadFileRequest(BaseModel):
    path: str = Field(min_length=1, description="Chemin du fichier à lire via le Runtime.")


class WriteFileRequest(BaseModel):
    path: str = Field(min_length=1)
    content: str = Field(description="Contenu à écrire.")


class ExecuteToolRequest(BaseModel):
    name: str = Field(min_length=1, description="Nom de l'outil à exécuter.")
    expression: str | None = Field(default=None, description="Expression pour l'outil calculator.")


class CallApiRequest(BaseModel):
    url: str = Field(min_length=1, description="URL de l'API externe à appeler.")
    method: str = Field(default="GET")


class QueryRagRequest(BaseModel):
    query: str = Field(min_length=1)
    n_results: int = Field(default=3, ge=1, le=10)