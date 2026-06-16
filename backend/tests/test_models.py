"""
ThreatWatch V2.0 - Test Suite: models.py
=========================================
Full TDD suite for the SQLAlchemy ORM models.

Covers:
  - Threat model: instantiation, attribute assignment, defaults, edge cases
  - HoneypotLog model: instantiation, attacker metadata, credential capture
  - FirewallRule model: instantiation, rule string generation
  - Cross-model consistency and required field enforcement

Dependencies:
  - pytest          (add to requirements-dev.txt)
  - unittest.mock   (stdlib — no extra install needed)

Run with:
  pytest backend/tests/test_models.py -v
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from backend.app.models import Threat, HoneypotLog, FirewallRule


# ---------------------------------------------------------------------------
# 1. Threat Model
# ---------------------------------------------------------------------------

class TestThreat:

    def test_instantiation_with_required_fields(self):
        """Threat can be created with core fields: indicator, type, source, severity."""
        threat = Threat(
            indicator="192.168.1.1",
            type="ip",
            source="AbuseIPDB",
            severity="high",
        )
        assert threat.indicator == "192.168.1.1"
        assert threat.type == "ip"
        assert threat.source == "AbuseIPDB"
        assert threat.severity == "high"

    def test_country_field_assignment(self):
        """Threat model must support an optional country field."""
        threat = Threat(
            indicator="10.0.0.1",
            type="ip",
            source="Blocklist.de",
            severity="medium",
            country="ZA",
        )
        assert threat.country == "ZA"

    def test_country_defaults_to_none(self):
        """When country is not provided, it must default to None."""
        threat = Threat(
            indicator="10.0.0.1",
            type="ip",
            source="Blocklist.de",
            severity="medium",
        )
        assert threat.country is None

    def test_timestamp_field_exists(self):
        """Threat must have a timestamp field (created_at or similar)."""
        threat = Threat(
            indicator="evil.example.com",
            type="domain",
            source="AlienVault OTX",
            severity="critical",
        )
        assert hasattr(threat, "created_at")

    def test_indicator_stores_domain(self):
        """Indicator field must accept domain-type values, not just IPs."""
        threat = Threat(
            indicator="malware-c2.example.com",
            type="domain",
            source="AlienVault OTX",
            severity="high",
        )
        assert threat.indicator == "malware-c2.example.com"
        assert threat.type == "domain"

    def test_indicator_stores_url(self):
        """Indicator field must accept full URL values."""
        threat = Threat(
            indicator="http://evil.example.com/payload.exe",
            type="url",
            source="URLhaus",
            severity="critical",
        )
        assert threat.indicator == "http://evil.example.com/payload.exe"
        assert threat.type == "url"

    def test_severity_accepts_all_levels(self):
        """Severity field must accept low, medium, high, and critical."""
        for level in ("low", "medium", "high", "critical"):
            threat = Threat(
                indicator="1.2.3.4",
                type="ip",
                source="TestFeed",
                severity=level,
            )
            assert threat.severity == level

    def test_repr_or_str_contains_indicator(self):
        """
        __repr__ or __str__ should include the indicator for debugging.
        At minimum, the string representation must not be the default object repr.
        """
        threat = Threat(
            indicator="203.0.113.50",
            type="ip",
            source="AbuseIPDB",
            severity="high",
        )
        text = repr(threat)
        assert "203.0.113.50" in text


# ---------------------------------------------------------------------------
# 2. HoneypotLog Model
# ---------------------------------------------------------------------------

class TestHoneypotLog:

    def test_instantiation_with_required_fields(self):
        """HoneypotLog can be created with attacker_ip and port."""
        log = HoneypotLog(
            attacker_ip="45.33.32.156",
            port=22,
        )
        assert log.attacker_ip == "45.33.32.156"
        assert log.port == 22

    def test_credentials_captured(self):
        """HoneypotLog must store captured username and password."""
        log = HoneypotLog(
            attacker_ip="185.220.101.1",
            port=23,
            username="admin",
            password="password123",
        )
        assert log.username == "admin"
        assert log.password == "password123"

    def test_credentials_default_to_none(self):
        """When no credentials are captured, username/password must be None."""
        log = HoneypotLog(
            attacker_ip="185.220.101.1",
            port=22,
        )
        assert log.username is None
        assert log.password is None

    def test_timestamp_field_exists(self):
        """HoneypotLog must have a timestamp for when the connection occurred."""
        log = HoneypotLog(
            attacker_ip="10.0.0.1",
            port=8080,
        )
        assert hasattr(log, "created_at")

    def test_protocol_field(self):
        """HoneypotLog should support an optional protocol field (tcp/udp)."""
        log = HoneypotLog(
            attacker_ip="10.0.0.1",
            port=53,
            protocol="udp",
        )
        assert log.protocol == "udp"

    def test_protocol_defaults_to_tcp(self):
        """Protocol should default to 'tcp' if not specified."""
        log = HoneypotLog(
            attacker_ip="10.0.0.1",
            port=22,
        )
        assert log.protocol == "tcp"

    def test_repr_contains_attacker_ip(self):
        """String representation must include the attacker IP for debugging."""
        log = HoneypotLog(
            attacker_ip="203.0.113.99",
            port=22,
        )
        text = repr(log)
        assert "203.0.113.99" in text


# ---------------------------------------------------------------------------
# 3. FirewallRule Model
# ---------------------------------------------------------------------------

class TestFirewallRule:

    def test_instantiation_with_required_fields(self):
        """FirewallRule can be created with target_ip and rule_command."""
        rule = FirewallRule(
            target_ip="185.220.101.1",
            rule_command="ufw deny from 185.220.101.1",
        )
        assert rule.target_ip == "185.220.101.1"
        assert rule.rule_command == "ufw deny from 185.220.101.1"

    def test_rule_type_field(self):
        """FirewallRule must store what type of rule it is (ufw, iptables, mikrotik)."""
        rule = FirewallRule(
            target_ip="10.0.0.1",
            rule_command="iptables -A INPUT -s 10.0.0.1 -j DROP",
            rule_type="iptables",
        )
        assert rule.rule_type == "iptables"

    def test_is_active_defaults_to_true(self):
        """Newly generated firewall rules should be active by default."""
        rule = FirewallRule(
            target_ip="10.0.0.1",
            rule_command="ufw deny from 10.0.0.1",
        )
        assert rule.is_active is True

    def test_is_active_can_be_set_false(self):
        """FirewallRule must support deactivation (soft-delete pattern)."""
        rule = FirewallRule(
            target_ip="10.0.0.1",
            rule_command="ufw deny from 10.0.0.1",
            is_active=False,
        )
        assert rule.is_active is False

    def test_timestamp_field_exists(self):
        """FirewallRule must have a created_at timestamp."""
        rule = FirewallRule(
            target_ip="1.2.3.4",
            rule_command="ufw deny from 1.2.3.4",
        )
        assert hasattr(rule, "created_at")

    def test_source_threat_reference(self):
        """FirewallRule should optionally reference the source threat indicator."""
        rule = FirewallRule(
            target_ip="45.33.32.156",
            rule_command="ufw deny from 45.33.32.156",
            source="AbuseIPDB",
        )
        assert rule.source == "AbuseIPDB"

    def test_repr_contains_target_ip(self):
        """String representation must include the target IP."""
        rule = FirewallRule(
            target_ip="203.0.113.10",
            rule_command="ufw deny from 203.0.113.10",
        )
        text = repr(rule)
        assert "203.0.113.10" in text


# ===========================================================================
# ORM Integration Tests
# ===========================================================================
#
# The tests below validate the SQLAlchemy ORM mapping for each model.
# They use an in-memory SQLite database so they are fast and side-effect-free.
# ===========================================================================

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from backend.app.database import Base


@pytest.fixture
def db_session():
    """
    Yield a scoped SQLAlchemy session backed by an in-memory SQLite database.

    Tables are created from Base.metadata before each test and the session
    is rolled-back + closed after each test so every test starts clean.
    """
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.rollback()
    session.close()


# ---------------------------------------------------------------------------
# 4. Threat ORM
# ---------------------------------------------------------------------------

class TestThreatORM:

    def test_tablename_is_threats(self):
        """Threat model must be mapped to the 'threats' table."""
        assert Threat.__tablename__ == "threats"

    def test_threat_has_id_column(self):
        """Threat model must expose an 'id' attribute for its primary key."""
        assert hasattr(Threat, "id")

    def test_can_add_threat_to_session(self, db_session):
        """A Threat with all required fields can be persisted and receives an id."""
        threat = Threat(
            indicator="192.168.1.1",
            type="ip",
            source="AbuseIPDB",
            severity="high",
        )
        db_session.add(threat)
        db_session.flush()
        assert threat.id is not None

    def test_indicator_not_nullable(self, db_session):
        """Attempting to flush a Threat with indicator=None must raise IntegrityError."""
        threat = Threat(
            indicator=None,
            type="ip",
            source="AbuseIPDB",
            severity="high",
        )
        db_session.add(threat)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_type_not_nullable(self, db_session):
        """Attempting to flush a Threat with type=None must raise IntegrityError."""
        threat = Threat(
            indicator="192.168.1.1",
            type=None,
            source="AbuseIPDB",
            severity="high",
        )
        db_session.add(threat)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_source_not_nullable(self, db_session):
        """Attempting to flush a Threat with source=None must raise IntegrityError."""
        threat = Threat(
            indicator="192.168.1.1",
            type="ip",
            source=None,
            severity="high",
        )
        db_session.add(threat)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_severity_not_nullable(self, db_session):
        """Attempting to flush a Threat with severity=None must raise IntegrityError."""
        threat = Threat(
            indicator="192.168.1.1",
            type="ip",
            source="AbuseIPDB",
            severity=None,
        )
        db_session.add(threat)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_country_nullable(self, db_session):
        """Country is optional — flushing without it must succeed and leave it None."""
        threat = Threat(
            indicator="10.0.0.1",
            type="ip",
            source="Blocklist.de",
            severity="medium",
        )
        db_session.add(threat)
        db_session.flush()
        assert threat.country is None

    def test_created_at_auto_set(self, db_session):
        """created_at must be populated automatically when a Threat is flushed."""
        threat = Threat(
            indicator="10.0.0.1",
            type="ip",
            source="Blocklist.de",
            severity="medium",
        )
        db_session.add(threat)
        db_session.flush()
        assert threat.created_at is not None

    def test_repr_still_works_after_orm(self, db_session):
        """__repr__ must still include the indicator after ORM persistence."""
        threat = Threat(
            indicator="203.0.113.50",
            type="ip",
            source="AbuseIPDB",
            severity="high",
        )
        db_session.add(threat)
        db_session.flush()
        assert "203.0.113.50" in repr(threat)


# ---------------------------------------------------------------------------
# 5. HoneypotLog ORM
# ---------------------------------------------------------------------------

class TestHoneypotLogORM:

    def test_tablename_is_honeypot_logs(self):
        """HoneypotLog model must be mapped to the 'honeypot_logs' table."""
        assert HoneypotLog.__tablename__ == "honeypot_logs"

    def test_has_id_column(self):
        """HoneypotLog model must expose an 'id' attribute for its primary key."""
        assert hasattr(HoneypotLog, "id")

    def test_can_add_to_session(self, db_session):
        """A HoneypotLog with attacker_ip and port can be persisted and receives an id."""
        log = HoneypotLog(attacker_ip="45.33.32.156", port=22)
        db_session.add(log)
        db_session.flush()
        assert log.id is not None

    def test_attacker_ip_not_nullable(self, db_session):
        """Attempting to flush a HoneypotLog with attacker_ip=None must raise IntegrityError."""
        log = HoneypotLog(attacker_ip=None, port=22)
        db_session.add(log)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_port_not_nullable(self, db_session):
        """Attempting to flush a HoneypotLog with port=None must raise IntegrityError."""
        log = HoneypotLog(attacker_ip="45.33.32.156", port=None)
        db_session.add(log)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_username_nullable(self, db_session):
        """Username is optional — flushing without it must succeed."""
        log = HoneypotLog(attacker_ip="45.33.32.156", port=22)
        db_session.add(log)
        db_session.flush()
        assert log.username is None

    def test_password_nullable(self, db_session):
        """Password is optional — flushing without it must succeed."""
        log = HoneypotLog(attacker_ip="45.33.32.156", port=22)
        db_session.add(log)
        db_session.flush()
        assert log.password is None

    def test_protocol_defaults_to_tcp(self, db_session):
        """Protocol must default to 'tcp' when not explicitly provided."""
        log = HoneypotLog(attacker_ip="45.33.32.156", port=22)
        db_session.add(log)
        db_session.flush()
        assert log.protocol == "tcp"

    def test_created_at_auto_set(self, db_session):
        """created_at must be populated automatically when a HoneypotLog is flushed."""
        log = HoneypotLog(attacker_ip="45.33.32.156", port=22)
        db_session.add(log)
        db_session.flush()
        assert log.created_at is not None


# ---------------------------------------------------------------------------
# 6. FirewallRule ORM
# ---------------------------------------------------------------------------

class TestFirewallRuleORM:

    def test_tablename_is_firewall_rules(self):
        """FirewallRule model must be mapped to the 'firewall_rules' table."""
        assert FirewallRule.__tablename__ == "firewall_rules"

    def test_has_id_column(self):
        """FirewallRule model must expose an 'id' attribute for its primary key."""
        assert hasattr(FirewallRule, "id")

    def test_can_add_to_session(self, db_session):
        """A FirewallRule with target_ip and rule_command can be persisted and receives an id."""
        rule = FirewallRule(
            target_ip="185.220.101.1",
            rule_command="ufw deny from 185.220.101.1",
        )
        db_session.add(rule)
        db_session.flush()
        assert rule.id is not None

    def test_target_ip_not_nullable(self, db_session):
        """Attempting to flush a FirewallRule with target_ip=None must raise IntegrityError."""
        rule = FirewallRule(
            target_ip=None,
            rule_command="ufw deny from 185.220.101.1",
        )
        db_session.add(rule)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_rule_command_not_nullable(self, db_session):
        """Attempting to flush a FirewallRule with rule_command=None must raise IntegrityError."""
        rule = FirewallRule(
            target_ip="185.220.101.1",
            rule_command=None,
        )
        db_session.add(rule)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_is_active_defaults_to_true(self, db_session):
        """is_active must default to True when not explicitly provided."""
        rule = FirewallRule(
            target_ip="10.0.0.1",
            rule_command="ufw deny from 10.0.0.1",
        )
        db_session.add(rule)
        db_session.flush()
        assert rule.is_active is True

    def test_source_nullable(self, db_session):
        """Source is optional — flushing without it must succeed."""
        rule = FirewallRule(
            target_ip="10.0.0.1",
            rule_command="ufw deny from 10.0.0.1",
        )
        db_session.add(rule)
        db_session.flush()
        assert rule.source is None

    def test_created_at_auto_set(self, db_session):
        """created_at must be populated automatically when a FirewallRule is flushed."""
        rule = FirewallRule(
            target_ip="10.0.0.1",
            rule_command="ufw deny from 10.0.0.1",
        )
        db_session.add(rule)
        db_session.flush()
        assert rule.created_at is not None
