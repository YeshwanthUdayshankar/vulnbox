"""Existing unit tests for py_sample_app."""

from app import parse_config, read_public_file


def test_parse_valid_yaml():
    data = parse_config("service: billing\nreplicas: 2\n")
    assert data == {"service": "billing", "replicas": 2}


def test_read_welcome_file():
    content = read_public_file("welcome.txt")
    assert "Hello from py_sample_app!" in content
