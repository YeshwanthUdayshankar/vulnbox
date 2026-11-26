"""Basic unit test for the integrated sample app."""

from app import _verify_hs256_jwt


def test_invalid_jwt_rejected():
    assert _verify_hs256_jwt("not.a.jwt", "secret") is None
