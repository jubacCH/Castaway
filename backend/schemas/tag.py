from pydantic import BaseModel, Field


class TagCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    color: str | None = Field(default=None, pattern="^#[0-9a-fA-F]{6}$")


class TagOut(BaseModel):
    id: int
    name: str
    color: str | None

    model_config = {"from_attributes": True}
