"""SQLAlchemy declarative base.

Step 1 intentionally defines NO domain tables (assets, events, incidents,
...). Future stages will add versioned Alembic migrations one bounded
context at a time. Keeping the base in one place makes that extension safe.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base for all future ORM models."""
