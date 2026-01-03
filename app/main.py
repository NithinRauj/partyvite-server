from fastapi import FastAPI
from contextlib import asynccontextmanager
from .api import users
from .config import get_config
from .db.main import init_db

app = FastAPI()

app.include_router(users.router)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()


@app.get('/')
async def root():
    db_url = get_config().DATABASE_URL
    return {"success": True, "msg": db_url}
