from pydantic import BaseModel, Field


class FolderCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    parent_id: int | None = None
    color: str | None = Field(default=None, pattern="^#[0-9a-fA-F]{6}$")
    sort_order: int = 0


class FolderUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    parent_id: int | None = None
    color: str | None = None
    sort_order: int | None = None


class FolderOut(BaseModel):
    id: int
    name: str
    parent_id: int | None
    color: str | None
    sort_order: int
    connection_count: int = 0

    model_config = {"from_attributes": True}
