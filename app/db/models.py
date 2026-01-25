from sqlmodel import SQLModel
from sqlmodel import Field


class User(SQLModel, table=True):
    __tablename__: str = "users"

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(default=None)
    email: str = Field(default=None)
    password: str = Field(default=None)
    token_version: int = Field(default=1)
