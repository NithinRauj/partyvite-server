from fastapi import APIRouter

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
