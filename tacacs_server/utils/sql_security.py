"""
SQL security utilities to prevent injection attacks.
Provides parameterized query helpers and input sanitization.
"""

import re
import sqlite3
from typing import Any

from .exceptions import ValidationError
from .logger import get_logger

logger = get_logger(__name__)


class SQLSecurityError(Exception):
    """SQL security related error."""
    pass


class ParameterizedQuery:
    """Helper for building secure parameterized SQL queries."""
    
    # SQL keywords that should never appear in user input
    DANGEROUS_KEYWORDS = {
        'DROP', 'DELETE', 'INSERT', 'UPDATE', 'CREATE', 'ALTER', 'EXEC', 
        'EXECUTE', 'UNION', 'TRUNCATE', 'REPLACE', 'MERGE', 'CALL'
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
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', identifier):
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
    def build_select(cls, table: str, columns: list[str], 
                    where_conditions: dict[str, Any] | None = None,
                    order_by: str | None = None,
                    limit: int | None = None) -> tuple[str, list[Any]]:
        """
        Build a secure SELECT query with parameters.
        
        Args:
            table: Table name
            columns: List of column names
            where_conditions: Dictionary of column->value conditions
            order_by: Column name for ORDER BY
            limit: LIMIT value
            
        Returns:
            Tuple of (query_string, parameters)
        """
        # Validate table name
        table = cls.validate_identifier(table, "table name")
        
        # Validate column names
        validated_columns = []
        for col in columns:
            validated_columns.append(cls.validate_identifier(col, "column name"))
        
        # Build query
        query = f"SELECT {', '.join(validated_columns)} FROM {table}"
        params = []
        
        # Add WHERE clause
        if where_conditions:
            where_parts = []
            for col, value in where_conditions.items():
                col = cls.validate_identifier(col, "where column")
                cls.validate_value(value, f"where value for {col}")
                where_parts.append(f"{col} = ?")
                params.append(value)
            
            if where_parts:
                query += f" WHERE {' AND '.join(where_parts)}"
        
        # Add ORDER BY
        if order_by:
            order_by = cls.validate_identifier(order_by, "order by column")
            query += f" ORDER BY {order_by}"
        
        # Add LIMIT
        if limit is not None:
            if not isinstance(limit, int) or limit < 0:
                raise ValidationError("LIMIT must be a non-negative integer")
            query += f" LIMIT {limit}"
        
        return query, params
    
    @classmethod
    def build_insert(cls, table: str, data: dict[str, Any]) -> tuple[str, list[Any]]:
        """
        Build a secure INSERT query with parameters.
        
        Args:
            table: Table name
            data: Dictionary of column->value data
            
        Returns:
            Tuple of (query_string, parameters)
        """
        if not data:
            raise ValidationError("Insert data cannot be empty")
        
        # Validate table name
        table = cls.validate_identifier(table, "table name")
        
        # Validate columns and values
        columns = []
        values = []
        placeholders = []
        
        for col, value in data.items():
            col = cls.validate_identifier(col, "column name")
            cls.validate_value(value, f"value for {col}")
            columns.append(col)
            values.append(value)
            placeholders.append("?")
        
        query = (
            f"INSERT INTO {table} ({', '.join(columns)}) "
            f"VALUES ({', '.join(placeholders)})"
        )
        
        return query, values
    
    @classmethod
    def build_update(cls, table: str, data: dict[str, Any], 
                    where_conditions: dict[str, Any]) -> tuple[str, list[Any]]:
        """
        Build a secure UPDATE query with parameters.
        
        Args:
            table: Table name
            data: Dictionary of column->value data to update
            where_conditions: Dictionary of column->value conditions
            
        Returns:
            Tuple of (query_string, parameters)
        """
        if not data:
            raise ValidationError("Update data cannot be empty")
        if not where_conditions:
            raise ValidationError("WHERE conditions required for UPDATE")
        
        # Validate table name
        table = cls.validate_identifier(table, "table name")
        
        # Build SET clause
        set_parts = []
        params = []
        
        for col, value in data.items():
            col = cls.validate_identifier(col, "update column")
            cls.validate_value(value, f"update value for {col}")
            set_parts.append(f"{col} = ?")
            params.append(value)
        
        # Build WHERE clause
        where_parts = []
        for col, value in where_conditions.items():
            col = cls.validate_identifier(col, "where column")
            cls.validate_value(value, f"where value for {col}")
            where_parts.append(f"{col} = ?")
            params.append(value)
        
        query = (
            f"UPDATE {table} SET {', '.join(set_parts)} "
            f"WHERE {' AND '.join(where_parts)}"
        )
        
        return query, params
    
    @classmethod
    def build_delete(
        cls, table: str, where_conditions: dict[str, Any]
    ) -> tuple[str, list[Any]]:
        """
        Build a secure DELETE query with parameters.
        
        Args:
            table: Table name
            where_conditions: Dictionary of column->value conditions
            
        Returns:
            Tuple of (query_string, parameters)
        """
        if not where_conditions:
            raise ValidationError("WHERE conditions required for DELETE")
        
        # Validate table name
        table = cls.validate_identifier(table, "table name")
        
        # Build WHERE clause
        where_parts = []
        params = []
        
        for col, value in where_conditions.items():
            col = cls.validate_identifier(col, "where column")
            cls.validate_value(value, f"where value for {col}")
            where_parts.append(f"{col} = ?")
            params.append(value)
        
        query = f"DELETE FROM {table} WHERE {' AND '.join(where_parts)}"
        
        return query, params


class SecureDatabase:
    """Wrapper for database operations with built-in security."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._connection = None
    
    def connect(self) -> sqlite3.Connection:
        """Get database connection with security settings."""
        if self._connection is None:
            self._connection = sqlite3.connect(self.db_path)
            # Enable foreign key constraints
            self._connection.execute("PRAGMA foreign_keys = ON")
            # Set secure defaults
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = NORMAL")
        return self._connection
    
    def execute_query(
        self, query: str, params: list[Any] | None = None
    ) -> sqlite3.Cursor:
        """Execute a parameterized query safely."""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            return cursor
        except sqlite3.Error as e:
            logger.error(f"Database query error: {e}")
            logger.error(f"Query: {query}")
            logger.error(f"Params: {params}")
            raise SQLSecurityError(f"Database operation failed: {e}") from e
    
    def select(self, table: str, columns: list[str], 
              where_conditions: dict[str, Any] | None = None,
              order_by: str | None = None,
              limit: int | None = None) -> list[dict[str, Any]]:
        """Execute secure SELECT query."""
        query, params = ParameterizedQuery.build_select(
            table, columns, where_conditions, order_by, limit
        )
        
        cursor = self.execute_query(query, params)
        
        # Convert to list of dictionaries
        column_names = [desc[0] for desc in cursor.description]
        results = []
        for row in cursor.fetchall():
            results.append(dict(zip(column_names, row)))
        
        return results
    
    def insert(self, table: str, data: dict[str, Any]) -> int:
        """Execute secure INSERT query."""
        query, params = ParameterizedQuery.build_insert(table, data)
        
        cursor = self.execute_query(query, params)
        self.connect().commit()
        
        return cursor.lastrowid
    
    def update(self, table: str, data: dict[str, Any], 
              where_conditions: dict[str, Any]) -> int:
        """Execute secure UPDATE query."""
        query, params = ParameterizedQuery.build_update(table, data, where_conditions)
        
        cursor = self.execute_query(query, params)
        self.connect().commit()
        
        return cursor.rowcount
    
    def delete(self, table: str, where_conditions: dict[str, Any]) -> int:
        """Execute secure DELETE query."""
        query, params = ParameterizedQuery.build_delete(table, where_conditions)
        
        cursor = self.execute_query(query, params)
        self.connect().commit()
        
        return cursor.rowcount
    
    def close(self):
        """Close database connection."""
        if self._connection:
            self._connection.close()
            self._connection = None


def sanitize_sql_input(value: Any) -> Any:
    """Sanitize input for SQL queries."""
    return ParameterizedQuery.validate_value(value)


def validate_sql_identifier(identifier: str) -> str:
    """Validate SQL identifier (table/column name)."""
    return ParameterizedQuery.validate_identifier(identifier)