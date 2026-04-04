from pydantic import BaseModel, Field


class ConnectionCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    host: str = Field(..., min_length=1, max_length=256)
    port: int = Field(default=22, ge=1, le=65535)
    protocol: str = Field(default="ssh", pattern="^(ssh|rdp)$")
    username: str | None = None
    auth_method: str = Field(default="password", pattern="^(password|key|agent)$")
    password: str | None = None  # plaintext, will be encrypted
    private_key: str | None = None  # plaintext, will be encrypted
    key_passphrase: str | None = None
    folder_id: int | None = None
    notes: str | None = None
    jump_host_id: int | None = None
    web_url: str | None = None
    tag_ids: list[int] = []


class ConnectionUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    host: str | None = Field(default=None, min_length=1, max_length=256)
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = Field(default=None, pattern="^(ssh|rdp)$")
    username: str | None = None
    auth_method: str | None = Field(default=None, pattern="^(password|key|agent)$")
    password: str | None = None
    private_key: str | None = None
    key_passphrase: str | None = None
    folder_id: int | None = None
    notes: str | None = None
    jump_host_id: int | None = None
    web_url: str | None = None
    tag_ids: list[int] | None = None


class ConnectionOut(BaseModel):
    id: int
    name: str
    host: str
    port: int
    protocol: str
    username: str | None
    auth_method: str
    folder_id: int | None
    notes: str | None
    jump_host_id: int | None
    web_url: str | None
    source: str
    source_id: str | None
    created_at: str | None
    updated_at: str | None
    tags: list[dict] = []

    model_config = {"from_attributes": True}
