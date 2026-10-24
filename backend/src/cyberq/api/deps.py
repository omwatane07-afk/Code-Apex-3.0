"""FastAPI dependencies for authentication, role authorization, and audit recording."""

from collections.abc import Callable

from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from cyberq.audit.chain import AuditService
from cyberq.core.config import get_settings
from cyberq.core.database import get_db
from cyberq.iam.models import User, UserSession
from cyberq.iam.policy import Action, AuthContext, PolicyEngine, Role
from cyberq.iam.session import CSRFValidationError, SessionError, SessionManager

settings = get_settings()
audit_service = AuditService(settings.AUDIT_SIGNING_SEED)


def get_current_session(
    request: Request,
    cyberq_session: str | None = Cookie(None),
    authorization: str | None = Header(None),
    x_session_id: str | None = Header(None),
    db: Session = Depends(get_db),
) -> UserSession:
    """Extracts and validates the server-side session from cookie, Bearer header, or X-Session-ID header."""
    is_prod = settings.is_production()

    # In production, header-based session tokens are forbidden (HttpOnly cookie strictly required)
    if is_prod and (authorization or x_session_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Header-based authentication tokens are strictly forbidden in production mode: HttpOnly cookie required",
        )

    # In production, insecure transport is rejected
    if is_prod:
        client_host = request.client.host if request.client else ""
        if client_host in settings.TRUSTED_PROXIES:
            proto = request.headers.get("x-forwarded-proto", request.url.scheme).lower()
        else:
            proto = request.url.scheme.lower()

        if proto != "https":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insecure transport: HTTPS required in production mode",
            )

    for token in (cyberq_session, x_session_id, authorization):
        if token and len(token) > 128:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Session identifier malformed or excessive length",
            )

    provided_tokens: set[str] = set()
    if cyberq_session:
        provided_tokens.add(cyberq_session)
    if x_session_id:
        provided_tokens.add(x_session_id)
    if authorization and authorization.startswith("Bearer "):
        provided_tokens.add(authorization.removeprefix("Bearer ").strip())

    if len(provided_tokens) > 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Conflicting/ambiguous session identifiers provided in request",
        )

    session_id = next(iter(provided_tokens), None)

    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    try:
        session = SessionManager.validate_session(db, session_id)
    except SessionError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        ) from e

    return session


def get_current_user(
    session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> User:
    user = db.get(User, session.user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User inactive or not found",
        )
    return user


def get_auth_context(
    session: UserSession = Depends(get_current_session),
) -> AuthContext:
    role_val = session.active_role.removeprefix("Role.").lower()
    return AuthContext(
        user_id=session.user_id,
        role=Role(role_val),
    )


def require_permission(action: Action) -> Callable[[AuthContext], AuthContext]:
    """Dependency factory enforcing deny-by-default role permission evaluation."""

    def dependency(auth_ctx: AuthContext = Depends(get_auth_context)) -> AuthContext:
        if not PolicyEngine.is_allowed(auth_ctx.role, action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{auth_ctx.role.value}' is not permitted to perform '{action.value}'",
            )
        return auth_ctx

    return dependency


def require_csrf(
    request: Request,
    session: UserSession = Depends(get_current_session),
    x_csrf_token: str | None = Header(None),
) -> None:
    """Dependency verifying the CSRF token on state-changing requests."""
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        try:
            SessionManager.validate_csrf(session, x_csrf_token)
        except CSRFValidationError as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(e),
            ) from e


def get_audit_service() -> AuditService:
    return audit_service
