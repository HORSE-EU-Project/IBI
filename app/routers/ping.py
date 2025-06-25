from fastapi import APIRouter

router = APIRouter()

@router.get("/ping")
async def get_ping():
    return {"ping": "pong"}