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
    path = Path(db_path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    url = f"sqlite:///{path}"
    return create_engine(
        url,
        future=True,
        echo=echo,
        pool_pre_ping=True,
    )


def get_session_factory(db_path: str, *, echo: bool = False) -> sessionmaker[Session]:
    engine = _sqlite_engine(db_path, echo=echo)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
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
