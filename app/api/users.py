from fastapi import APIRouter, Response, status
from ..db.main import dbSession
from ..db.models import User
from sqlalchemy.exc import IntegrityError
from psycopg2.errors import UniqueViolation

router = APIRouter(
    prefix="/users",
    tags=["users"]
)


@router.post("/signin", description="authenticates and signs in user")
async def signin():
    return {"success": True, "msg": "user signed in"}


@router.post("/signout", description="signs out user")
async def signout():
    return {"success": True, "msg": "user signed out"}


@router.post("/create_user", description="create a user", status_code=status.HTTP_201_CREATED)
async def create_user(user: User, session: dbSession, response: Response):
    try:
        session.add(user)
        session.commit()
        session.refresh(user)
        return {"success": True, "msg": "user created", "data": user.model_dump()}
    except IntegrityError as e:
        session.rollback()
        orig = getattr(e, "orig", None)
        response.status_code = status.HTTP_400_BAD_REQUEST
        if isinstance(orig, UniqueViolation) or getattr(orig, "pgcode", None) == "23505":
            return {"success": False, "msg": "user with this email address exists", "context": ""}
        return {"success": False, "msg": "error creating user", "context": str(e)}
    except Exception as e:
        session.rollback()
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"success": False, "msg": "error creating user", "context": str(e)}
