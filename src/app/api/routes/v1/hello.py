from fastapi import APIRouter

router = APIRouter(prefix="/api/v1", tags=["hello"])

@router.get("/hello")
async def hello(name: str = "world"):
    return {"message": f"hello, {name}!"}
