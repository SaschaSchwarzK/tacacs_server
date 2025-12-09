"""SQL security utilities using SQLAlchemy Core for safe queries."""

import re
from typing import Any

from sqlalchemy import (
    Column,
    MetaData,
    String,
    Table,
    and_,
    bindparam,
    delete,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Engine, create_engine
from sqlalchemy.exc import SQLAlchemyError

from .exceptions import ValidationError
from .logger import get_logger

logger = get_logger("tacacs_server.utils.sql_security", component="sql_security")


class SQLSecurityError(Exception):
    """SQL security related error."""

    pass


class ParameterizedQuery:
    """Helper for building secure parameterized SQL queries."""

    # SQL keywords that should never appear in user input
    DANGEROUS_KEYWORDS = {
        "DROP",
        "DELETE",
        "INSERT",
        "UPDATE",
        "CREATE",
        "ALTER",
        "EXEC",
        "EXECUTE",
        "UNION",
        "TRUNCATE",
        "REPLACE",
        "MERGE",
        "CALL",
    }

    # SQL injection patterns
    INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
        r"(--|#|/\*|\*/)",
        r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
        r"(\'\s*(OR|AND)\s+\'\w+\'\s*=\s*\'\w+\')",
        r"(\bUNION\s+SELECT\b)",
        r"(\bINTO\s+OUTFILE\b)",
        r"(\bLOAD_FILE\b)",
    ]

    @classmethod
    def validate_identifier(cls, identifier: str, context: str = "identifier") -> str:
        """
        Validate SQL identifier (table name, column name, etc.).

        Args:
            identifier: The identifier to validate
            context: Context for error messages

        Returns:
            Validated identifier

        Raises:
            ValidationError: If identifier is invalid or dangerous
        """
        if not identifier:
            raise ValidationError(f"{context} cannot be empty")

        # Check length
        if len(identifier) > 64:
            raise ValidationError(f"{context} too long (max 64 characters)")

        # Check for valid characters (alphanumeric, underscore, dot)
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", identifier):
            raise ValidationError(f"{context} contains invalid characters")

        # Check for dangerous keywords
        if identifier.upper() in cls.DANGEROUS_KEYWORDS:
            raise ValidationError(f"{context} contains reserved keyword")

        return identifier

    @classmethod
    def validate_value(cls, value: Any, context: str = "value") -> Any:
        """
        Validate user input value for SQL queries.

        Args:
            value: The value to validate
            context: Context for error messages

        Returns:
            Validated value

        Raises:
            ValidationError: If value contains SQL injection patterns
        """
        if value is None:
            return None

        # Convert to string for pattern checking
        str_value = str(value)

        # Check for SQL injection patterns
        for pattern in cls.INJECTION_PATTERNS:
            if re.search(pattern, str_value, re.IGNORECASE):
                raise ValidationError(
                    f"{context} contains potentially unsafe SQL patterns"
                )

        return value

    @classmethod
    def _build_table(cls, table: str, columns: set[str]) -> Table:
        """Create an in-memory SQLAlchemy table with validated identifiers."""
        table = cls.validate_identifier(table, "table name")
        metadata = MetaData()
        cols = []
        for col in sorted(columns):
            cols.append(Column(cls.validate_identifier(col, "column name"), String))
        return Table(table, metadata, *cols)

    @classmethod
    def build_select(
        cls,
        table: str,
        columns: list[str],
        where_conditions: dict[str, Any] | None = None,
        order_by: str | None = None,
        limit: int | None = None,
    ):
        """
        Build a secure SELECT statement with bound parameters.

        Returns:
            Tuple of (SQLAlchemy selectable, params dict)
        """
        if limit is not None and (not isinstance(limit, int) or limit < 0):
            raise ValidationError("LIMIT must be a non-negative integer")

        where_conditions = where_conditions or {}
        all_columns: set[str] = set(columns) | set(where_conditions.keys())
        if order_by:
            all_columns.add(order_by)

        table_obj = cls._build_table(table, all_columns)
        params: dict[str, Any] = {}

        for val in columns:
            cls.validate_identifier(val, "column name")
        selectable_cols = [table_obj.c[col] for col in columns]
        stmt = select(*selectable_cols)

        if where_conditions:
            clauses = []
            for idx, (col, value) in enumerate(where_conditions.items()):
                col = cls.validate_identifier(col, "where column")
                cls.validate_value(value, f"where value for {col}")
                bind_key = f"w_{idx}"
                clauses.append(table_obj.c[col] == bindparam(bind_key))
                params[bind_key] = value
            stmt = stmt.where(and_(*clauses))

        if order_by:
            order_by = cls.validate_identifier(order_by, "order by column")
            stmt = stmt.order_by(table_obj.c[order_by])

        if limit is not None:
            stmt = stmt.limit(limit)

        return stmt, params

    @classmethod
    def build_insert(cls, table: str, data: dict[str, Any]):
        """
        Build a secure INSERT statement with bound parameters.

        Returns:
            Tuple of (SQLAlchemy insert, params dict)
        """
        if not data:
            raise ValidationError("Insert data cannot be empty")

        for key, value in data.items():
            cls.validate_identifier(key, "column name")
            cls.validate_value(value, f"value for {key}")

        table_obj = cls._build_table(table, set(data.keys()))
        params = {key: value for key, value in data.items()}
        stmt = insert(table_obj).values(**{k: bindparam(k) for k in data})
        return stmt, params

    @classmethod
    def build_update(
        cls, table: str, data: dict[str, Any], where_conditions: dict[str, Any]
    ):
        """
        Build a secure UPDATE statement with bound parameters.

        Returns:
            Tuple of (SQLAlchemy update, params dict)
        """
        if not data:
            raise ValidationError("Update data cannot be empty")
        if not where_conditions:
            raise ValidationError("WHERE conditions required for UPDATE")

        for key, value in data.items():
            cls.validate_identifier(key, "update column")
            cls.validate_value(value, f"update value for {key}")
        for key, value in where_conditions.items():
            cls.validate_identifier(key, "where column")
            cls.validate_value(value, f"where value for {key}")

        table_obj = cls._build_table(
            table, set(data.keys()) | set(where_conditions.keys())
        )
        params: dict[str, Any] = {}
        stmt = update(table_obj).values(**{k: bindparam(f"v_{k}") for k in data})
        params.update({f"v_{k}": v for k, v in data.items()})

        clauses = []
        for idx, (col, value) in enumerate(where_conditions.items()):
            bind_key = f"w_{idx}"
            clauses.append(table_obj.c[col] == bindparam(bind_key))
            params[bind_key] = value
        stmt = stmt.where(and_(*clauses))
        return stmt, params

    @classmethod
    def build_delete(cls, table: str, where_conditions: dict[str, Any]):
        """
        Build a secure DELETE statement with bound parameters.

        Returns:
            Tuple of (SQLAlchemy delete, params dict)
        """
        if not where_conditions:
            raise ValidationError("WHERE conditions required for DELETE")

        for key, value in where_conditions.items():
            cls.validate_identifier(key, "where column")
            cls.validate_value(value, f"where value for {key}")

        table_obj = cls._build_table(table, set(where_conditions.keys()))
        params: dict[str, Any] = {}
        clauses = []
        for idx, (col, value) in enumerate(where_conditions.items()):
            bind_key = f"w_{idx}"
            clauses.append(table_obj.c[col] == bindparam(bind_key))
            params[bind_key] = value
        stmt = delete(table_obj).where(and_(*clauses))
        return stmt, params


class SecureDatabase:
    """Wrapper for database operations with built-in security."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._engine: Engine | None = None

    def connect(self) -> Engine:
        """Get database engine with security settings."""
        if self._engine is None:
            self._engine = create_engine(f"sqlite:///{self.db_path}", future=True)
            with self._engine.connect() as conn:
                conn.exec_driver_sql("PRAGMA foreign_keys = ON")
                conn.exec_driver_sql("PRAGMA journal_mode = WAL")
                conn.exec_driver_sql("PRAGMA synchronous = NORMAL")
        return self._engine

    def select(
        self,
        table: str,
        columns: list[str],
        where_conditions: dict[str, Any] | None = None,
        order_by: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Execute secure SELECT query."""
        stmt, params = ParameterizedQuery.build_select(
            table, columns, where_conditions, order_by, limit
        )

        engine = self.connect()
        try:
            with engine.connect() as conn:
                result = conn.execute(stmt, params)
                return [dict(row) for row in result.mappings().all()]
        except SQLAlchemyError as e:
            logger.error(
                "Database query error",
                event="sql.query.error",
                error=str(e),
                stmt=str(stmt),
                params=params,
            )
            raise SQLSecurityError(f"Database operation failed: {e}") from e

    def insert(self, table: str, data: dict[str, Any]) -> int:
        """Execute secure INSERT query."""
        stmt, params = ParameterizedQuery.build_insert(table, data)

        engine = self.connect()
        try:
            with engine.begin() as conn:
                result = conn.execute(stmt, params)
                inserted_pk = result.inserted_primary_key
                if inserted_pk:
                    return int(inserted_pk[0])
                if hasattr(result, "lastrowid") and result.lastrowid is not None:
                    return int(result.lastrowid)
                return 0
        except SQLAlchemyError as e:
            logger.error(
                "Database insert error",
                event="sql.insert.error",
                error=str(e),
                stmt=str(stmt),
                params=params,
            )
            raise SQLSecurityError(f"Database operation failed: {e}") from e

    def update(
        self, table: str, data: dict[str, Any], where_conditions: dict[str, Any]
    ) -> int:
        """Execute secure UPDATE query."""
        stmt, params = ParameterizedQuery.build_update(table, data, where_conditions)

        engine = self.connect()
        try:
            with engine.begin() as conn:
                result = conn.execute(stmt, params)
                return int(result.rowcount or 0)
        except SQLAlchemyError as e:
            logger.error(
                "Database update error",
                event="sql.update.error",
                error=str(e),
                stmt=str(stmt),
                params=params,
            )
            raise SQLSecurityError(f"Database operation failed: {e}") from e

    def delete(self, table: str, where_conditions: dict[str, Any]) -> int:
        """Execute secure DELETE query."""
        stmt, params = ParameterizedQuery.build_delete(table, where_conditions)

        engine = self.connect()
        try:
            with engine.begin() as conn:
                result = conn.execute(stmt, params)
                return int(result.rowcount or 0)
        except SQLAlchemyError as e:
            logger.error(
                "Database delete error",
                event="sql.delete.error",
                error=str(e),
                stmt=str(stmt),
                params=params,
            )
            raise SQLSecurityError(f"Database operation failed: {e}") from e

    def close(self):
        """Close database connection."""
        if self._engine:
            self._engine.dispose()
            self._engine = None


def sanitize_sql_input(value: Any) -> Any:
    """Sanitize input for SQL queries."""
    return ParameterizedQuery.validate_value(value)


def validate_sql_identifier(identifier: str) -> str:
    """Validate SQL identifier (table/column name)."""
    return ParameterizedQuery.validate_identifier(identifier)
