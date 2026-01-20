import jwt
import datetime
from typing import Annotated
from sqlalchemy.exc import IntegrityError
from sqlmodel import select, Session
from pydantic import BaseModel
from pwdlib import PasswordHash
from psycopg2.errors import UniqueViolation
from jwt.exceptions import InvalidTokenError
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import APIRouter, Response, status, Depends, HTTPException
from ..db.models import User
from ..db.main import dbSession
from ..config import get_config

JWT_SECRET_KEY = get_config().JWT_SECRET_KEY

router = APIRouter(
    prefix="/users",
    tags=["users"]
)


class Token(BaseModel):
    access_token: str
    token_type: str


mock_users = {
    "johndoe@example.com": {
        "id": 2,
        "name": "johndoe",
        "email": "johndoe@example.com",
        "password": "$argon2id$v=19$m=65536,t=3,p=4$wagCPXjifgvUFBzq4hqe3w$CYaIb8sB+wtD+Vu/P4uod1+Qof8h+1g7bbDlBID48Rc",
    }
}

# Password utils
password_hash = PasswordHash.recommended()


def get_hashed_password(password):
    return password_hash.hash(password)


def verify_password(plain_password, hashed_password):
    return password_hash.verify(plain_password, hashed_password)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='users/signin')


def generate_access_token(data: dict, expires_delta: datetime.timedelta | None = None):
    to_encode = data.copy()
    expires_at = datetime.datetime.now(datetime.timezone.utc)
    if expires_delta:
        expires_at += expires_delta
    else:
        expires_at += datetime.timedelta(hours=12)
    to_encode.update({'exp': expires_at})
    return jwt.encode(to_encode, JWT_SECRET_KEY, 'HS256')


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    unauthorized_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"})
    try:
        jwt_payload = jwt.decode(token, JWT_SECRET_KEY, 'HS256')
        email = jwt_payload.get('sub')
        if not email:
            raise unauthorized_exception
    except InvalidTokenError:
        raise unauthorized_exception
    user_dict = mock_users.get(email)
    if not user_dict:
        raise unauthorized_exception
    return User(**user_dict)


@router.get('/me', description='get current logged in user')
async def get_logged_user(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user


def authenticate_user(email: str, plain_password: str, db_session: Session) -> User | None:
    query = select(User).where(User.email == email)
    user = db_session.exec(query).one()
    if not user:
        return False
    hashed_password = user.password
    if not verify_password(plain_password, hashed_password):
        return False
    return user


@router.post("/signin", summary="sign in user", description="signs in an existing user")
async def signin(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db_session: dbSession):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"})
    try:
        user = authenticate_user(
            form_data.username, form_data.password, db_session)
        if not user:
            raise credentials_exception
        data = {"sub": user.id}
        token = generate_access_token(data=data)
        return Token(access_token=token, token_type='bearer')
    except Exception as e:
        raise credentials_exception


@router.post("/signout", description="signs out user")
async def signout():
    return {"success": True, "msg": "user signed out"}


@router.post("/signup", summary="signup user", description="signup a new user", status_code=status.HTTP_201_CREATED)
async def create_user(user: User, session: dbSession, response: Response):
    try:
        hashed_password = get_hashed_password(user.password)
        user.password = hashed_password
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
