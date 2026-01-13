import unittest

from sql_safe.safe_query import (
    ReadOnlyViolationError,
    SQLSafetyError,
    _requires_parameters_raw,
    _validate_query_safety,
)


class TestSqlSafeBasic(unittest.TestCase):
    def test_union_select_blocked(self):
        with self.assertRaises(SQLSafetyError):
            _validate_query_safety("SELECT * FROM a UNION SELECT * FROM b", read_only=False)

    def test_literal_quotes_require_params(self):
        with self.assertRaises(SQLSafetyError):
            _validate_query_safety("SELECT * FROM users WHERE name = 'alice'", read_only=False)

    def test_requires_parameters_raw_heuristic(self):
        self.assertTrue(_requires_parameters_raw("SELECT * FROM t WHERE id = 1"))
        self.assertFalse(_requires_parameters_raw("SELECT * FROM t"))

    def test_read_only_blocks_writes(self):
        with self.assertRaises(ReadOnlyViolationError):
            _validate_query_safety("UPDATE users SET name = 'x' WHERE id = 1", read_only=True)


if __name__ == "__main__":
    unittest.main()
