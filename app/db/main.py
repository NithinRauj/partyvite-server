from fastapi import Depends
from typing import Annotated
from sqlmodel import create_engine, SQLModel, Session
from ..config import get_config

config = get_config()
engine = create_engine(url=config.DATABASE_URL, echo=True)


async def init_db():
    SQLModel.metadata.create_all(engine)


async def get_session():
    with Session(engine) as session:
        yield session

dbSession = Annotated[Session, Depends(get_session)]
