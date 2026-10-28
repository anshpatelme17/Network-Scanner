"""Interactive, owner-confirmed local recovery for liveadmin."""

from getpass import getpass

from sqlalchemy import select
from sqlalchemy.engine import make_url

from app.core.config import get_settings
from app.database.session import get_session_factory, init_engine
from app.models.auth import User
from app.services.auth_service import parse_roles
from app.services.local_recovery import rotate_local_admin_password


def main() -> int:
    settings = get_settings()

    # Validate the configured target before requesting a password.
    try:
        url = make_url(settings.database_url)
    except Exception:
        print("STOP: configured database target could not be validated.")
        return 1

    if (
        settings.environment != "development"
        or url.drivername != "postgresql+psycopg"
        or url.host != "db"
        or url.database != "security_platform"
    ):
        print("STOP: recovery is restricted to the expected development database.")
        return 1

    print("Target: designated local administrator (liveadmin)")
    print("Environment: development")
    print("Database target: validated; credentials are not displayed.")

    try:
        init_engine(settings.database_url)
        session = get_session_factory()()
    except Exception:
        print("STOP: database session could not be initialized.")
        return 1

    try:
        user = session.scalar(
            select(User).where(User.username == "liveadmin")
        )
        if user is None:
            print("STOP: liveadmin was not found.")
            return 1
        if not user.is_active:
            print("STOP: liveadmin is inactive.")
            return 1

        try:
            roles = parse_roles(user.roles)
        except Exception:
            print("STOP: account roles could not be validated.")
            return 1

        if "ADMIN" not in roles:
            print("STOP: liveadmin does not have the ADMIN role.")
            return 1

        print("Account check: active administrator.")
        print("Enter a new password of at least 12 characters.")

        password = getpass("New password (input hidden): ")
        confirmation = getpass("Repeat new password (input hidden): ")

        if password != confirmation:
            print("STOP: passwords do not match; nothing was changed.")
            return 1

        if not password or len(password) < 12:
            print("STOP: password does not meet the minimum length policy.")
            return 1

        print("This will rotate only liveadmin's password and append an audit event.")
        approval = input("Type ROTATE liveadmin to proceed: ")
        if approval != "ROTATE liveadmin":
            print("Cancelled; nothing was changed.")
            return 1

        rotate_local_admin_password(
            session,
            "liveadmin",
            password,
            environment=settings.environment,
            database_url=settings.database_url,
        )

        print("Password rotation completed and audit event committed.")
        print("Roles and account active status were not changed.")
        return 0
    except Exception:
        session.rollback()
        print("STOP: recovery failed; the database transaction was rolled back.")
        return 1
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
