import os
from unittest import mock
import pytest

# Set environment variables for testing before importing config
@pytest.fixture
def mock_env():
    with mock.patch.dict(os.environ, {
        "DATABASE_URL": "postgresql://test_user:test_pass@localhost:5432/test_db",
        "ABUSEIPDB_API_KEY": "test_abuse_key",
        "ALIENVAULT_API_KEY": "test_alien_key",
        "DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/test",
        "INGESTION_INTERVAL": "2"
    }):
        # Reload the module to apply mock environment variables
        import importlib
        import backend.app.config as config
        importlib.reload(config)
        yield config

def test_config_loads_from_env(mock_env):
    """Test that configuration variables are read from the environment correctly."""
    assert mock_env.DATABASE_URL == "postgresql://test_user:test_pass@localhost:5432/test_db"
    assert mock_env.ABUSEIPDB_API_KEY == "test_abuse_key"
    assert mock_env.ALIENVAULT_API_KEY == "test_alien_key"
    assert mock_env.DISCORD_WEBHOOK_URL == "https://discord.com/api/webhooks/test"
    assert mock_env.INGESTION_INTERVAL == 2  # Must be an integer

def test_config_defaults(mock_env):
    """Test that default values are applied when optional env vars are missing."""
    with mock.patch.dict(os.environ, {}, clear=True):
        import importlib
        import backend.app.config as config
        importlib.reload(config)
        
        # database URL might not have a default, but ingestion interval should
        assert config.INGESTION_INTERVAL == 1  # default fallback
        assert config.ABUSEIPDB_API_KEY is None
        assert config.ALIENVAULT_API_KEY is None
        assert config.DISCORD_WEBHOOK_URL is None
