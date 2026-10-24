"""Server-side session management and CSRF token verification."""

import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberq.core.config import get_settings
from cyberq.iam.models import User, UserSession
from cyberq.iam.policy import Role

settings = get_settings()


class SessionError(Exception):
    pass


class SessionExpiredError(SessionError):
    pass


class SessionNotFoundError(SessionError):
    pass


class CSRFValidationError(SessionError):
    pass


class SessionManager:
    """Manages secure server-side sessions stored in the database."""

    @staticmethod
    def create_session(
        db: Session,
        user: User,
        role: Role | str,
    ) -> UserSession:
        now = datetime.now(UTC)
        session_id = secrets.token_urlsafe(48)
        csrf_token = secrets.token_urlsafe(32)

        expires_at = now + timedelta(hours=settings.SESSION_ABSOLUTE_TIMEOUT_HOURS)

        role_str = role.value if isinstance(role, Role) else str(role)
        session = UserSession(
            id=session_id,
            user_id=user.id,
            active_role=role_str,
            csrf_token=csrf_token,
            created_at=now,
            last_active_at=now,
            expires_at=expires_at,
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        return session

    @staticmethod
    def validate_session(
        db: Session,
        session_id: str,
    ) -> UserSession:
        if not session_id or len(session_id) > 128:
            raise SessionNotFoundError("Session ID missing or malformed")

        session = db.execute(
            select(UserSession).where(UserSession.id == session_id)
        ).scalar_one_or_none()

        if not session:
            raise SessionNotFoundError("Session not found")

        now = datetime.now(UTC)

        # Ensure tz-aware comparisons
        expires_at = (
            session.expires_at.replace(tzinfo=UTC)
            if session.expires_at.tzinfo is None
            else session.expires_at
        )
        last_active = (
            session.last_active_at.replace(tzinfo=UTC)
            if session.last_active_at.tzinfo is None
            else session.last_active_at
        )

        # Check absolute expiration
        if now > expires_at:
            db.delete(session)
            db.commit()
            raise SessionExpiredError("Session has exceeded maximum duration")

        # Check idle timeout (15 minutes) - Wallboard display role is exempt from idle timeout
        if session.active_role != Role.WALLBOARD.value:
            idle_limit = timedelta(minutes=settings.SESSION_IDLE_TIMEOUT_MINUTES)
            if now - last_active > idle_limit:
                db.delete(session)
                db.commit()
                raise SessionExpiredError("Session timed out due to inactivity")

        # Slide last active timestamp
        session.last_active_at = now
        db.commit()
        return session

    @staticmethod
    def rotate_session(db: Session, session: UserSession) -> UserSession:
        """Rotates session token and CSRF token to mitigate fixation while preserving expiry bounds."""
        new_id = secrets.token_urlsafe(48)
        new_csrf = secrets.token_urlsafe(32)
        now = datetime.now(UTC)

        rotated = UserSession(
            id=new_id,
            user_id=session.user_id,
            active_role=session.active_role,
            csrf_token=new_csrf,
            created_at=session.created_at,
            last_active_at=now,
            expires_at=session.expires_at,
        )
        db.delete(session)
        db.add(rotated)
        db.commit()
        db.refresh(rotated)
        return rotated

    @staticmethod
    def validate_csrf(session: UserSession, submitted_csrf: str | None) -> None:
        """Validates the CSRF token on state-changing requests."""
        if not submitted_csrf or not secrets.compare_digest(session.csrf_token, submitted_csrf):
            raise CSRFValidationError("Invalid or missing CSRF token")

    @staticmethod
    def destroy_session(db: Session, session_id: str) -> None:
        session = db.execute(
            select(UserSession).where(UserSession.id == session_id)
        ).scalar_one_or_none()
        if session:
            db.delete(session)
            db.commit()
