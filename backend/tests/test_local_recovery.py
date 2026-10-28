import pytest
from sqlalchemy import select

from app.models.auth import AuthAudit, User
from app.services import auth_service
from app.services.local_recovery import rotate_local_admin_password

TEST_DB_URL = "sqlite://"


@pytest.fixture
def db(clean_db):
    session = __import__(
        "app.database.session", fromlist=["get_session_factory"]
    ).get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def seed_admin(db, *, active=True, roles='["ADMIN"]'):
    user = User(
        username="liveadmin",
        password_hash=auth_service.hash_password("Original-Test-Pass-123"),
        display_name="Local Admin",
        is_active=active,
        roles=roles,
    )
    db.add(user)
    db.commit()
    return user


def rotate(db, password="New-Test-Password-456"):
    return rotate_local_admin_password(
        db,
        "liveadmin",
        password,
        environment="test",
        database_url=TEST_DB_URL,
        test_only=True,
    )


def test_rotation_updates_hash_preserves_roles_and_audits(db):
    user = seed_admin(db)
    original_roles = user.roles
    original_id = user.id

    rotate(db)

    db.refresh(user)
    assert user.id == original_id
    assert user.is_active is True
    assert user.roles == original_roles
    assert auth_service.verify_password(user.password_hash, "New-Test-Password-456")
    assert not auth_service.verify_password(user.password_hash, "Original-Test-Pass-123")

    audit = db.scalar(
        select(AuthAudit).where(
            AuthAudit.username == "liveadmin",
            AuthAudit.event == "USER_UPDATED",
        )
    )
    assert audit is not None
    assert "Password rotated" in audit.detail
    assert "New-Test-Password-456" not in audit.detail


def test_refuses_wrong_username_without_changes(db):
    seed_admin(db)
    with pytest.raises(ValueError, match="restricted"):
        rotate_local_admin_password(
            db, "another-user", "New-Test-Password-456",
            environment="test", database_url=TEST_DB_URL, test_only=True,
        )
    assert db.scalar(select(User).where(User.username == "liveadmin")) is not None
    assert db.scalar(select(AuthAudit)) is None


def test_refuses_non_test_environment_in_test_mode(db):
    seed_admin(db)
    with pytest.raises(ValueError, match="Test mode"):
        rotate_local_admin_password(
            db, "liveadmin", "New-Test-Password-456",
            environment="development", database_url=TEST_DB_URL, test_only=True,
        )
    assert db.scalar(select(AuthAudit)) is None


def test_refuses_non_sqlite_test_target(db):
    seed_admin(db)
    with pytest.raises(ValueError, match="Test mode"):
        rotate_local_admin_password(
            db, "liveadmin", "New-Test-Password-456",
            environment="test",
            database_url="postgresql+psycopg://user:pass@db/security_platform",
            test_only=True,
        )
    assert db.scalar(select(AuthAudit)) is None


def test_refuses_inactive_admin(db):
    seed_admin(db, active=False)
    with pytest.raises(ValueError, match="inactive"):
        rotate(db)
    assert db.scalar(select(AuthAudit)) is None


def test_refuses_account_without_admin_role(db):
    seed_admin(db, roles='["VIEWER"]')
    with pytest.raises(ValueError, match="ADMIN role"):
        rotate(db)
    assert db.scalar(select(AuthAudit)) is None


def test_weak_password_is_rejected_without_audit(db):
    seed_admin(db)
    with pytest.raises(Exception, match="at least 12 characters"):
        rotate(db, "short")
    assert db.scalar(select(AuthAudit)) is None
