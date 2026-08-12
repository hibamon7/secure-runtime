from pydantic import BaseModel, Field


class AskRequest(BaseModel):
    prompt: str = Field(min_length=1, description="The prompt to send to the model for generating a response.")


class AskResponse(BaseModel):
    response: str

    