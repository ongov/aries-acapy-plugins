"""API for token introspection."""

from fastapi import APIRouter, Depends, Form, Path
from fastapi.responses import ORJSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from tenant.deps import get_db_session
from tenant.services.introspect_service import introspect_access_token
from tenant.security.bearer import require_bearer

router = APIRouter(prefix="/tenants/{uid}")


@router.post(
    "/introspect",
    tags=["protected"],
    dependencies=[Depends(require_bearer)],
    response_class=ORJSONResponse,
)
async def introspect(
    uid: str = Path(...),
    token: str = Form(...),
    db: AsyncSession = Depends(get_db_session),
):
    """Return RFC 7662-style token introspection payload."""
    data = await introspect_access_token(db, uid, token)
    return ORJSONResponse(data, status_code=200)
