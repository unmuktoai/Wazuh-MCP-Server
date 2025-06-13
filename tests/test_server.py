import pytest
from src.config import WazuhConfig


def test_config_creation():
    config = WazuhConfig()
    assert config.host
    assert config.port > 0


def test_base_url():
    config = WazuhConfig()
    assert config.base_url.startswith("https://")
