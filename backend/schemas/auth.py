from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: str | None = None


class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str | None = None
