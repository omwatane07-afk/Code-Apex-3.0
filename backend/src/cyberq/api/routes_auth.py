"""Authentication endpoints for session creation, inspection, and termination."""

import re
import threading
import time
import unicodedata
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberq.api.deps import get_audit_service, get_current_session, get_current_user, require_csrf
from cyberq.audit.chain import AuditService
from cyberq.core.config import get_settings
from cyberq.core.database import get_db
from cyberq.iam.models import RoleGrant, User, UserSession
from cyberq.iam.policy import Role
from cyberq.iam.session import SessionManager

router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=64)
    role: Role
    full_name: str | None = None
    email: str | None = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not v:
            raise ValueError("Username cannot be empty")
        if unicodedata.normalize("NFKC", v) != v:
            raise ValueError("Username contains non-NFKC or compatibility characters")
        for ch in v:
            cat = unicodedata.category(ch)
            if cat in {"Cf", "Cc", "Cs", "Cn"}:
                raise ValueError("Username contains invisible, control, or formatting characters")
        if not re.match(r"^[a-zA-Z0-9._-]+$", v):
            raise ValueError(
                "Username must contain only ASCII alphanumeric characters, '.', '_', or '-'"
            )
        return v


class UserProfileResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: str
    active_role: str
    csrf_token: str
    session_id: str


_login_attempts: dict[str, list[float]] = defaultdict(list)
_rate_lock = threading.Lock()
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 60.0


def check_login_rate_limit(key: str) -> None:
    now = time.monotonic()
    with _rate_lock:
        attempts = [t for t in _login_attempts[key] if now - t < LOGIN_WINDOW_SECONDS]
        _login_attempts[key] = attempts
        if len(attempts) >= MAX_LOGIN_ATTEMPTS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many login attempts. Account/client locked. Please wait {int(LOGIN_WINDOW_SECONDS)} seconds.",
            )
        _login_attempts[key].append(now)


def clear_login_rate_limits() -> None:
    with _rate_lock:
        _login_attempts.clear()


@router.post("/login", response_model=UserProfileResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> UserProfileResponse:
    """Dev/Pilot OIDC login simulator.

    Authenticates user, creates server-side session, and logs audit event.
    """
    if not settings.is_demo():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Development login simulator disabled in production. Authentication must be performed via bank OIDC IdP.",
        )

    peer_ip = request.client.host if request.client else "127.0.0.1"
    if peer_ip in settings.TRUSTED_PROXIES:
        xff = request.headers.get("x-forwarded-for")
        client_ip = xff.split(",")[0].strip() if xff else peer_ip
    else:
        client_ip = peer_ip

    check_login_rate_limit(f"{client_ip}:{payload.username}")

    user = db.execute(select(User).where(User.username == payload.username)).scalar_one_or_none()

    if not user:
        user = User(
            username=payload.username,
            email=payload.email or f"{payload.username}@bank.internal",
            full_name=payload.full_name or payload.username.title(),
            is_active=True,
        )
        db.add(user)
        db.flush()

        grant = RoleGrant(
            user_id=user.id,
            role=payload.role.value,
            granted_by="system_idp",
        )
        db.add(grant)
        db.flush()

    session = SessionManager.create_session(db, user, payload.role)

    audit.record_event(
        session=db,
        actor_id=user.id,
        actor_role=payload.role.value,
        action="auth:login",
        entity_type="session",
        entity_id=session.id,
        client_ip=client_ip,
        after_state={"role": payload.role.value, "expires_at": session.expires_at.isoformat()},
    )
    db.commit()

    # Set secure httpOnly session cookie
    response.set_cookie(
        key="cyberq_session",
        value=session.id,
        httponly=True,
        secure=settings.should_secure_cookie(),
        samesite="strict",
        max_age=settings.SESSION_ABSOLUTE_TIMEOUT_HOURS * 3600,
        path="/",
    )

    return UserProfileResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        active_role=session.active_role,
        csrf_token=session.csrf_token,
        session_id=session.id,
    )


@router.get("/me", response_model=UserProfileResponse)
def get_me(
    user: User = Depends(get_current_user),
    session: UserSession = Depends(get_current_session),
) -> UserProfileResponse:
    return UserProfileResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        active_role=session.active_role,
        csrf_token=session.csrf_token,
        session_id=session.id,
    )


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    session: UserSession = Depends(get_current_session),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    _: None = Depends(require_csrf),
) -> dict[str, str]:
    client_ip = request.client.host if request.client else "127.0.0.1"
    audit.record_event(
        session=db,
        actor_id=user.id,
        actor_role=session.active_role,
        action="auth:logout",
        entity_type="session",
        entity_id=session.id,
        client_ip=client_ip,
    )
    SessionManager.destroy_session(db, session.id)
    response.delete_cookie(
        "cyberq_session",
        path="/",
        httponly=True,
        secure=settings.should_secure_cookie(),
        samesite="lax",
    )
    return {"status": "logged_out"}
