"""Owner-confirmed local account recovery with strict target guards."""


from sqlalchemy import select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.models.auth import User
from app.services import auth_service

TARGET_USERNAME = "liveadmin"
TARGET_ROLE = "ADMIN"
AUDIT_EVENT = "USER_UPDATED"


def rotate_local_admin_password(
    db: Session,
    username: str,
    new_password: str,
    *,
    environment: str,
    database_url: str,
    test_only: bool = False,
) -> None:
    """Rotate only the designated admin password and append an audit event.

    Test mode is accepted only for the isolated SQLite test database.
    Production use is deliberately restricted to the known development
    PostgreSQL target. This function never changes roles or account status.
    """
    if username != TARGET_USERNAME:
        raise ValueError("Recovery is restricted to the designated local admin.")

    try:
        url = make_url(database_url)
    except Exception as exc:
        raise ValueError("Database target could not be validated.") from exc

    if test_only:
        if environment != "test" or url.get_backend_name() != "sqlite":
            raise ValueError("Test mode requires the test environment and SQLite.")
    else:
        if (
            environment != "development"
            or url.drivername != "postgresql+psycopg"
            or url.host != "db"
            or url.database != "security_platform"
        ):
            raise ValueError("Refusing recovery: development database target mismatch.")

    bound_url = db.get_bind().url
    if (
        bound_url.get_backend_name() != url.get_backend_name()
        or (
            not test_only
            and (
                bound_url.host != url.host
                or bound_url.database != url.database
                or bound_url.drivername != url.drivername
            )
        )
        or (test_only and bound_url.get_backend_name() != "sqlite")
    ):
        raise ValueError("Session database does not match the validated target.")

    try:
        user = db.scalar(
            select(User).where(User.username == TARGET_USERNAME)
        )
        if user is None:
            raise ValueError("The designated admin account was not found.")
        if not user.is_active:
            raise ValueError("The designated admin account is inactive.")

        try:
            roles = auth_service.parse_roles(user.roles)
        except Exception as exc:
            raise ValueError("The account roles could not be validated.") from exc

        if TARGET_ROLE not in roles:
            raise ValueError("The designated account does not have the ADMIN role.")

        # Existing password policy and Argon2 hashing are reused.
        password_hash = auth_service.hash_password(new_password)
        if not auth_service.verify_password(password_hash, new_password):
            raise RuntimeError("New password hash verification failed.")

        user.password_hash = password_hash
        auth_service.record_auth_audit(
            db,
            AUDIT_EVENT,
            user.id,
            user.username,
            "Password rotated by owner-confirmed local recovery procedure.",
        )
        db.commit()
    except BaseException:
        db.rollback()
        raise
