from sql_safe import mysql_with_timeout
from sqlalchemy import text


def test_mysql_with_timeout_prefixes_query():
    q = mysql_with_timeout("SELECT 1")
    assert isinstance(q, type(text("")))
    assert "MAX_EXECUTION_TIME" in str(q)
