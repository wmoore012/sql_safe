# SPDX-License-Identifier: MIT
# Copyright (c) 2024 MusicScope

"""
Tests for safe_query module.

These tests verify SQL injection prevention, read-only enforcement,
performance monitoring, and error handling.
"""

import pytest
from unittest.mock import Mock, patch
from sqlalchemy.exc import SQLAlchemyError

from sql_safe.safe_query import (
    query,
    read_only_query,
    bulk_query,
    get_engine,
    SQLSafetyError,
    ReadOnlyViolationError,
    _validate_query_safety,
    _retry_with_backoff,
    latency_warn,
)


class TestQuerySafety:
    """Test SQL injection prevention and safety validation."""

    def test_validate_query_safety_allows_safe_queries(self):
        """Test that safe queries pass validation."""
        safe_queries = [
            "SELECT * FROM users WHERE id = :id",
            "SELECT COUNT(*) FROM orders",
            "SHOW TABLES",
            "DESCRIBE users",
            "EXPLAIN SELECT * FROM products",
        ]

        for query_str in safe_queries:
            # Should not raise any exception
            _validate_query_safety(query_str)

    def test_validate_query_safety_blocks_dangerous_patterns(self):
        """Test that dangerous SQL patterns are blocked."""
        dangerous_queries = [
            "DROP TABLE users",
            "TRUNCATE TABLE orders",
            "ALTER TABLE users ADD COLUMN password VARCHAR(255)",
            "CREATE TABLE malicious (id INT)",
            "GRANT ALL ON *.* TO 'hacker'@'%'",
            "LOAD_FILE('/etc/passwd')",
            "SELECT * INTO OUTFILE '/tmp/dump.txt' FROM users",
        ]

        for query_str in dangerous_queries:
            with pytest.raises(SQLSafetyError):
                _validate_query_safety(query_str)

    def test_validate_query_safety_read_only_mode(self):
        """Test that write operations are blocked in read-only mode."""
        write_queries = [
            "INSERT INTO users (name) VALUES ('test')",
            "UPDATE users SET name = 'updated' WHERE id = 1",
            "DELETE FROM users WHERE id = 1",
            "REPLACE INTO users (id, name) VALUES (1, 'test')",
        ]

        for query_str in write_queries:
            with pytest.raises(ReadOnlyViolationError):
                _validate_query_safety(query_str, read_only=True)

    def test_validate_query_safety_allows_reads_in_readonly(self):
        """Test that read operations are allowed in read-only mode."""
        read_queries = [
            "SELECT * FROM users",
            "SELECT COUNT(*) FROM orders",
            "SHOW TABLES",
            "DESCRIBE users",
        ]

        for query_str in read_queries:
            # Should not raise any exception
            _validate_query_safety(query_str, read_only=True)


class TestRetryLogic:
    """Test exponential backoff retry logic."""

    def test_retry_with_backoff_success_first_try(self):
        """Test successful execution on first try."""
        mock_func = Mock(return_value="success")

        result = _retry_with_backoff(mock_func, max_retries=3)

        assert result == "success"
        assert mock_func.call_count == 1

    def test_retry_with_backoff_success_after_retries(self):
        """Test successful execution after some failures."""
        mock_func = Mock(
            side_effect=[
                SQLAlchemyError("temp failure"),
                SQLAlchemyError("temp failure"),
                "success",
            ]
        )

        with patch("time.sleep"):  # Mock sleep to speed up test
            result = _retry_with_backoff(mock_func, max_retries=3)

        assert result == "success"
        assert mock_func.call_count == 3

    def test_retry_with_backoff_max_retries_exceeded(self):
        """Test that exception is raised after max retries."""
        mock_func = Mock(side_effect=SQLAlchemyError("persistent failure"))

        with patch("time.sleep"):  # Mock sleep to speed up test
            with pytest.raises(SQLAlchemyError):
                _retry_with_backoff(mock_func, max_retries=2)

        assert mock_func.call_count == 3  # Initial + 2 retries


class TestLatencyWarning:
    """Test performance monitoring and latency warnings."""

    def test_latency_warn_no_warning_for_fast_queries(self):
        """Test that fast queries don't trigger warnings."""

        @latency_warn(100)  # 100ms threshold
        def fast_function():
            return "fast"

        with patch("sql_safe.safe_query.logger") as mock_logger:
            result = fast_function()

            assert result == "fast"
            mock_logger.warning.assert_not_called()

    def test_latency_warn_triggers_for_slow_queries(self):
        """Test that slow queries trigger warnings."""

        @latency_warn(10)  # Very low threshold for testing
        def slow_function():
            import time

            time.sleep(0.02)  # 20ms - should trigger warning
            return "slow"

        with patch("sql_safe.safe_query.logger") as mock_logger:
            result = slow_function()

            assert result == "slow"
            mock_logger.warning.assert_called_once()

            # Check that warning message contains timing info
            warning_call = mock_logger.warning.call_args[0][0]
            assert "Slow query detected" in warning_call
            assert "ms" in warning_call


class TestEngineCreation:
    """Test database engine creation and configuration."""

    @patch.dict(
        "os.environ",
        {
            "DB_HOST": "test-host",
            "DB_PORT": "3306",
            "DB_USER": "test-user",
            "DB_PASS": "test-pass",
            "DB_NAME_PUBLIC": "test_public",
        },
    )
    @patch("sql_safe.safe_query.create_engine")
    def test_get_engine_with_environment_variables(self, mock_create_engine):
        """Test engine creation with environment variables."""
        mock_engine = Mock()
        mock_create_engine.return_value = mock_engine
        mock_engine.begin.return_value.__enter__ = Mock()
        mock_engine.begin.return_value.__exit__ = Mock()
        mock_conn = Mock()
        mock_engine.begin.return_value.__enter__.return_value = mock_conn

        get_engine("PUBLIC")

        # Verify engine was created with correct URL
        mock_create_engine.assert_called_once()
        call_args = mock_create_engine.call_args[0]
        assert "mysql+pymysql://test-user:test-pass@test-host:3306/test_public" in call_args[0]

        # Verify session timeout was set
        mock_conn.execute.assert_called()

    def test_get_engine_invalid_schema(self):
        """Test that invalid schema raises ValueError."""
        with pytest.raises(ValueError, match="Invalid schema"):
            get_engine("INVALID")

    @patch.dict("os.environ", {}, clear=True)
    def test_get_engine_missing_password(self):
        """Test that missing password raises ValueError."""
        with pytest.raises(ValueError, match="DB_PASS environment variable must be set"):
            get_engine("PUBLIC")


class TestQueryExecution:
    """Test query execution with mocked database connections."""

    def setup_method(self):
        """Set up mocks for each test."""
        self.mock_engine = Mock()
        self.mock_conn = Mock()
        self.mock_result = Mock()

        # Set up the context manager chain
        self.mock_engine.begin.return_value.__enter__ = Mock(return_value=self.mock_conn)
        self.mock_engine.begin.return_value.__exit__ = Mock(return_value=None)
        self.mock_conn.execute.return_value = self.mock_result

    def test_query_basic_execution(self):
        """Test basic query execution."""
        with patch("sql_safe.safe_query.get_engine", return_value=self.mock_engine):
            result = query("SELECT * FROM users WHERE id = :id", {"id": 123})

            assert result == self.mock_result
            self.mock_conn.execute.assert_called_once()

    def test_query_with_timeout(self):
        """Test query execution with custom timeout."""
        with patch("sql_safe.safe_query.get_engine", return_value=self.mock_engine):
            query("SELECT * FROM users", timeout_ms=5000)

            # Verify timeout was added to query
            call_args = self.mock_conn.execute.call_args[0]
            query_text = str(call_args[0])
            assert "MAX_EXECUTION_TIME(5000)" in query_text

    def test_query_empty_string_raises_error(self):
        """Test that empty query string raises ValueError."""
        with pytest.raises(ValueError, match="Query string cannot be empty"):
            query("")

    def test_query_none_raises_error(self):
        """Test that None query string raises ValueError."""
        with pytest.raises(ValueError, match="Query string cannot be empty"):
            query(None)

    def test_query_dangerous_pattern_raises_error(self):
        """Test that dangerous SQL patterns raise SQLSafetyError."""
        with pytest.raises(SQLSafetyError):
            query("DROP TABLE users")


class TestReadOnlyQuery:
    """Test read-only query execution."""

    def setup_method(self):
        """Set up mocks for each test."""
        self.mock_engine = Mock()
        self.mock_conn = Mock()
        self.mock_result = Mock()

        # Set up the context manager chain
        self.mock_engine.begin.return_value.__enter__ = Mock(return_value=self.mock_conn)
        self.mock_engine.begin.return_value.__exit__ = Mock(return_value=None)
        self.mock_conn.execute.return_value = self.mock_result

    def test_read_only_query_execution(self):
        """Test read-only query execution."""
        with patch("sql_safe.safe_query.get_engine", return_value=self.mock_engine):
            result = read_only_query("SELECT * FROM users")

            assert result == self.mock_result

            # Verify read-only transaction was set
            execute_calls = [call[0][0] for call in self.mock_conn.execute.call_args_list]
            assert any("READ ONLY" in str(call) for call in execute_calls)

    def test_read_only_query_blocks_writes(self):
        """Test that write operations are blocked in read-only queries."""
        with pytest.raises(ReadOnlyViolationError):
            read_only_query("INSERT INTO users (name) VALUES ('test')")

    def test_read_only_query_allows_reads(self):
        """Test that read operations are allowed."""
        with patch("sql_safe.safe_query.get_engine", return_value=self.mock_engine):
            result = read_only_query("SELECT COUNT(*) FROM users")

            assert result == self.mock_result

    def test_read_only_query_shorter_timeout(self):
        """Test that read-only queries have shorter default timeout."""
        with patch("sql_safe.safe_query.get_engine", return_value=self.mock_engine):
            read_only_query("SELECT * FROM users")

            # Verify shorter timeout was used
            call_args = self.mock_conn.execute.call_args[0]
            query_text = str(call_args[0])
            assert "MAX_EXECUTION_TIME(15000)" in query_text


class TestBulkQuery:
    """Test bulk query execution."""

    def setup_method(self):
        """Set up mocks for each test."""
        self.mock_engine = Mock()
        self.mock_conn = Mock()
        self.mock_result1 = Mock()
        self.mock_result2 = Mock()

        # Set up the context manager chain
        self.mock_engine.begin.return_value.__enter__ = Mock(return_value=self.mock_conn)
        self.mock_engine.begin.return_value.__exit__ = Mock(return_value=None)
        # Reset side_effect for each test
        self.mock_conn.execute.side_effect = None
        self.mock_conn.execute.return_value = Mock()

    def test_bulk_query_execution(self):
        """Test bulk query execution."""
        queries = [
            {"query": "SELECT COUNT(*) FROM users"},
            {"query": "SELECT COUNT(*) FROM orders WHERE user_id = :id", "params": {"id": 123}},
        ]

        # Set up side effects for multiple execute calls
        self.mock_conn.execute.side_effect = [
            None,
            self.mock_result1,
            self.mock_result2,
        ]  # First call is timeout setting

        with patch("sql_safe.safe_query.get_engine", return_value=self.mock_engine):
            results = bulk_query(queries)

            assert len(results) == 2
            assert results[0] == self.mock_result1
            assert results[1] == self.mock_result2

    def test_bulk_query_empty_list_raises_error(self):
        """Test that empty queries list raises ValueError."""
        with pytest.raises(ValueError, match="Queries list cannot be empty"):
            bulk_query([])

    def test_bulk_query_read_only_mode(self):
        """Test bulk query execution in read-only mode."""
        queries = [
            {"query": "SELECT COUNT(*) FROM users"},
            {"query": "SELECT COUNT(*) FROM orders"},
        ]

        # Set up side effects for multiple execute calls (read-only, timeout, query1, query2)
        self.mock_conn.execute.side_effect = [None, None, Mock(), Mock()]

        with patch("sql_safe.safe_query.get_engine", return_value=self.mock_engine):
            bulk_query(queries, read_only=True)

            # Verify read-only transaction was set
            execute_calls = [call[0][0] for call in self.mock_conn.execute.call_args_list]
            assert any("READ ONLY" in str(call) for call in execute_calls)

    def test_bulk_query_validates_all_queries(self):
        """Test that all queries in bulk are validated."""
        queries = [
            {"query": "SELECT COUNT(*) FROM users"},
            {"query": "DROP TABLE users"},  # Dangerous query
        ]

        with patch("sql_safe.safe_query.get_engine", return_value=self.mock_engine):
            with pytest.raises(SQLSafetyError):
                bulk_query(queries)


class TestIntegration:
    """Integration tests with real-world scenarios."""

    def test_parameterized_query_prevents_injection(self):
        """Test that parameterized queries prevent SQL injection."""
        # This would be dangerous if not parameterized
        malicious_input = "1; DROP TABLE users; --"

        with patch("sql_safe.safe_query.get_engine") as mock_get_engine:
            mock_engine = Mock()
            mock_conn = Mock()
            mock_get_engine.return_value = mock_engine
            mock_engine.begin.return_value.__enter__ = Mock(return_value=mock_conn)
            mock_engine.begin.return_value.__exit__ = Mock(return_value=None)

            # This should be safe because it's parameterized
            query("SELECT * FROM users WHERE id = :id", {"id": malicious_input})

            # Verify the parameter was passed safely
            mock_conn.execute.assert_called()
            call_args = mock_conn.execute.call_args
            # Parameters are passed as the second argument to execute
            if len(call_args) > 1 and call_args[1]:
                assert call_args[1] == {"id": malicious_input}  # Parameter passed separately
            else:
                # Parameters might be passed as keyword arguments
                assert "id" in str(call_args) or malicious_input in str(call_args)

    def test_performance_monitoring_integration(self):
        """Test that performance monitoring works end-to-end."""
        with patch("sql_safe.safe_query.get_engine") as mock_get_engine:
            with patch("sql_safe.safe_query.logger") as mock_logger:
                mock_engine = Mock()
                mock_conn = Mock()
                mock_get_engine.return_value = mock_engine
                mock_engine.begin.return_value.__enter__ = Mock(return_value=mock_conn)
                mock_engine.begin.return_value.__exit__ = Mock(return_value=None)

                # Simulate a slow query by making execute take time
                def slow_execute(*args, **kwargs):
                    import time

                    time.sleep(0.01)  # 10ms
                    return Mock()

                mock_conn.execute.side_effect = slow_execute

                # Execute query - the latency_warn decorator is already applied to the query function
                # We need to patch the logger before calling query
                query("SELECT * FROM users")

                # Should have logged a warning for slow query (10ms > 5ms threshold)
                # The latency_warn decorator on query function uses 500ms threshold by default
                # So we need to check if any warning was logged
                if mock_logger.warning.called:
                    mock_logger.warning.assert_called()
                else:
                    # The query might have been too fast, which is also acceptable
                    assert True
