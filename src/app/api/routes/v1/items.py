from fastapi import APIRouter, Depends
from typing import List

from app.api.deps import get_current_user, require_roles

router = APIRouter(prefix="/api/v1/items", tags=["items"])

FAKE_DB: dict[int, dict] = {
    1: {"id": 1, "name": "widget"},
    2: {"id": 2, "name": "gadget"},
}

@router.get("/", dependencies=[Depends(get_current_user)])
async def list_items() -> List[dict]:
    return list(FAKE_DB.values())

@router.get("/{item_id}", dependencies=[Depends(get_current_user)])
async def get_item(item_id: int) -> dict:
    return FAKE_DB.get(item_id, {"error": "not found"})

@router.post("/", dependencies=[Depends(require_roles("admin"))])
async def create_item(item: dict) -> dict:
    new_id = max(FAKE_DB) + 1 if FAKE_DB else 1
    FAKE_DB[new_id] = {"id": new_id, **item}
    return FAKE_DB[new_id]
