import pytest
from backend.app.core.ingestors import AbuseIPIngestor, PhishTankIngestor

def test_base_ingestor_enforces_interface():
    """Ensure that child classes must implement their own parsing logic."""
    with pytest.raises(TypeError):
        from backend.app.core.ingestors import BaseIngestor
        BaseIngestor(api_key="test")

def test_abuseip_ingestor_initialization():
    """Verify clean setup of properties across Java-style classes."""
    ingestor = AbuseIPIngestor(api_key="SECRET_KEY")
    assert ingestor.api_key == "SECRET_KEY"
    assert ingestor.feed_name == "AbuseIPDB"
    assert "abuseipdb.com" in ingestor.base_url

def test_phishtank_ingestor_no_auth_required():
    """Verify that public feeds initialize safely without keys."""
    ingestor = PhishTankIngestor()
    assert ingestor.api_key is None
    assert ingestor.feed_name == "PhishTank"
