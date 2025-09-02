"""Token endpoint (per-tenant)."""

from fastapi import APIRouter, Depends, Form, Path, Request, Response
from fastapi.responses import ORJSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from tenant.deps import get_db_session
from tenant.services.token_service import TokenService

router = APIRouter(prefix="/tenants/{uid}")


@router.post("/token", tags=["public"], response_class=ORJSONResponse)
async def token_endpoint(
    request: Request,
    response: Response,
    uid: str = Path(...),
    grant_type: str = Form(...),
    pre_authorized_code: str | None = Form(None, alias="pre-authorized_code"),
    user_pin: str | None = Form(None),
    refresh_token: str | None = Form(None),
    db: AsyncSession = Depends(get_db_session),
):
    """Exchange a pre-auth code or refresh token for an access and refresh token."""
    if grant_type == "urn:ietf:params:oauth:grant-type:pre-authorized_code":
        code = pre_authorized_code
        if code is None:
            form = await request.form()
            code = form.get("pre-authorized_code") or form.get("pre_authorized_code")
        if not code:
            return ORJSONResponse({"error": "invalid_request"}, status_code=400)
        access_token, refresh_token = await TokenService.issue_by_pre_auth_code(
            db,
            uid=uid,
            code=code,
            realm=uid,
            user_pin=user_pin,
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return {
            "access_token": access_token.token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_at": access_token.expires_at.isoformat(),
        }
    elif grant_type == "refresh_token":
        if not refresh_token:
            return ORJSONResponse({"error": "invalid_request"}, status_code=400)
        access_token, refresh_token = await TokenService.rotate_by_refresh_token(
            db=db,
            uid=uid,
            refresh_token_value=refresh_token,
            realm=uid,
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return {
            "access_token": access_token.token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_at": access_token.expires_at.isoformat(),
        }
    else:
        return ORJSONResponse({"error": "unsupported_grant_type"}, status_code=400)
