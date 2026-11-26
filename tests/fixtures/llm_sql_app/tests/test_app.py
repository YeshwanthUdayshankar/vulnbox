"""Existing unit tests for llm_sql_app."""

from app import init_db, lookup_user


def test_lookup_alice():
    conn = init_db()
    users = lookup_user(conn, "alice")
    assert users == [{"id": 1, "name": "alice", "role": "admin"}]
