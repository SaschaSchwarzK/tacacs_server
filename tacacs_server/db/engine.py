"""Shared SQLAlchemy engine/session helpers for local SQLite usage."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

Base = declarative_base()


def _sqlite_engine(db_path: str, *, echo: bool = False) -> Engine:
    """Create a SQLite engine with WAL, tuned pooling, and busy timeout defaults."""
    path = Path(db_path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    url = f"sqlite:///{path}"
    engine = create_engine(
        url,
        future=True,
        echo=echo,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        pool_timeout=30,
        pool_recycle=3600,
    )
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):  # noqa: ANN001
        cursor = dbapi_conn.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
        finally:
            cursor.close()

    return engine


def get_session_factory(db_path: str, *, echo: bool = False) -> sessionmaker[Session]:
    """Return a sessionmaker bound to the shared SQLite engine (with preconfigured pooling)."""
    engine = _sqlite_engine(db_path, echo=echo)
    factory = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
        future=True,
    )
    # Expose the engine for compatibility with legacy code/tests expecting .bind
    try:
        factory.bind = engine  # type: ignore[attr-defined]
    except Exception:
        pass
    try:
        factory.engine = engine  # type: ignore[attr-defined]
    except Exception:
        pass
    return factory


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Provide a transactional scope around a series of operations."""
    session: Session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
