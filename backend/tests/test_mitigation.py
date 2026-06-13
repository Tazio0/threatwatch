"""
ThreatWatch V2.0 - Test Suite: core/mitigation.py
===================================================
Full TDD suite for the Iron Curtain Engine.

Covers:
  - IronCurtainEngine instantiation
  - UFW rule generation: correct syntax, IP embedding
  - iptables rule generation: correct chain, target, and flags
  - MikroTik RouterOS rule generation: correct CLI syntax
  - Edge cases: invalid IPs, empty input, CIDR ranges
  - Batch rule generation across multiple IPs

Dependencies:
  - pytest          (add to requirements-dev.txt)
  - unittest.mock   (stdlib — no extra install needed)

Run with:
  pytest backend/tests/test_mitigation.py -v
"""

import pytest

from backend.app.core.mitigation import IronCurtainEngine


# ---------------------------------------------------------------------------
# 1. Initialization
# ---------------------------------------------------------------------------

class TestIronCurtainEngineInit:

    def test_default_initialization(self):
        """IronCurtainEngine can be instantiated with no arguments."""
        engine = IronCurtainEngine()
        assert engine is not None

    def test_has_required_methods(self):
        """Engine must expose all three rule-generation methods."""
        engine = IronCurtainEngine()
        assert hasattr(engine, "generate_ufw_rule")
        assert hasattr(engine, "generate_iptables_rule")
        assert hasattr(engine, "generate_mikrotik_rule")


# ---------------------------------------------------------------------------
# 2. UFW Rule Generation
# ---------------------------------------------------------------------------

class TestGenerateUfwRule:

    def test_basic_ufw_deny_rule(self):
        """generate_ufw_rule() must return a properly formatted 'ufw deny from <IP>' string."""
        engine = IronCurtainEngine()
        rule = engine.generate_ufw_rule("185.220.101.1")
        assert rule == "ufw deny from 185.220.101.1"

    def test_ufw_rule_contains_ip(self):
        """The generated UFW rule must contain the exact IP passed in."""
        engine = IronCurtainEngine()
        rule = engine.generate_ufw_rule("10.0.0.1")
        assert "10.0.0.1" in rule

    def test_ufw_rule_starts_with_ufw(self):
        """The command must start with 'ufw'."""
        engine = IronCurtainEngine()
        rule = engine.generate_ufw_rule("1.2.3.4")
        assert rule.startswith("ufw")

    def test_ufw_rule_contains_deny(self):
        """The command must include the 'deny' action."""
        engine = IronCurtainEngine()
        rule = engine.generate_ufw_rule("1.2.3.4")
        assert "deny" in rule

    def test_ufw_rule_with_cidr_range(self):
        """generate_ufw_rule() must handle CIDR notation."""
        engine = IronCurtainEngine()
        rule = engine.generate_ufw_rule("192.168.0.0/24")
        assert "192.168.0.0/24" in rule
        assert rule == "ufw deny from 192.168.0.0/24"

    def test_ufw_rule_returns_string(self):
        """Return type must be a string."""
        engine = IronCurtainEngine()
        rule = engine.generate_ufw_rule("1.2.3.4")
        assert isinstance(rule, str)


# ---------------------------------------------------------------------------
# 3. iptables Rule Generation
# ---------------------------------------------------------------------------

class TestGenerateIptablesRule:

    def test_basic_iptables_drop_rule(self):
        """generate_iptables_rule() must return a valid iptables DROP rule."""
        engine = IronCurtainEngine()
        rule = engine.generate_iptables_rule("185.220.101.1")
        assert rule == "iptables -A INPUT -s 185.220.101.1 -j DROP"

    def test_iptables_rule_contains_ip(self):
        """The generated iptables rule must embed the exact target IP."""
        engine = IronCurtainEngine()
        rule = engine.generate_iptables_rule("10.0.0.1")
        assert "10.0.0.1" in rule

    def test_iptables_rule_uses_input_chain(self):
        """The rule must target the INPUT chain (-A INPUT)."""
        engine = IronCurtainEngine()
        rule = engine.generate_iptables_rule("1.2.3.4")
        assert "-A INPUT" in rule

    def test_iptables_rule_uses_drop_target(self):
        """The rule must use the DROP target (-j DROP)."""
        engine = IronCurtainEngine()
        rule = engine.generate_iptables_rule("1.2.3.4")
        assert "-j DROP" in rule

    def test_iptables_rule_uses_source_flag(self):
        """The rule must specify the source IP with -s flag."""
        engine = IronCurtainEngine()
        rule = engine.generate_iptables_rule("1.2.3.4")
        assert "-s 1.2.3.4" in rule

    def test_iptables_rule_with_cidr_range(self):
        """generate_iptables_rule() must handle CIDR notation."""
        engine = IronCurtainEngine()
        rule = engine.generate_iptables_rule("10.0.0.0/8")
        assert rule == "iptables -A INPUT -s 10.0.0.0/8 -j DROP"

    def test_iptables_rule_returns_string(self):
        """Return type must be a string."""
        engine = IronCurtainEngine()
        rule = engine.generate_iptables_rule("1.2.3.4")
        assert isinstance(rule, str)


# ---------------------------------------------------------------------------
# 4. MikroTik RouterOS Rule Generation
# ---------------------------------------------------------------------------

class TestGenerateMikrotikRule:

    def test_basic_mikrotik_drop_rule(self):
        """generate_mikrotik_rule() must return valid RouterOS CLI syntax."""
        engine = IronCurtainEngine()
        rule = engine.generate_mikrotik_rule("185.220.101.1")
        assert rule == "/ip firewall filter add chain=input src-address=185.220.101.1 action=drop"

    def test_mikrotik_rule_contains_ip(self):
        """The generated MikroTik rule must embed the exact target IP."""
        engine = IronCurtainEngine()
        rule = engine.generate_mikrotik_rule("10.0.0.1")
        assert "10.0.0.1" in rule

    def test_mikrotik_rule_uses_input_chain(self):
        """The rule must target chain=input."""
        engine = IronCurtainEngine()
        rule = engine.generate_mikrotik_rule("1.2.3.4")
        assert "chain=input" in rule

    def test_mikrotik_rule_uses_drop_action(self):
        """The rule must use action=drop."""
        engine = IronCurtainEngine()
        rule = engine.generate_mikrotik_rule("1.2.3.4")
        assert "action=drop" in rule

    def test_mikrotik_rule_uses_src_address(self):
        """The rule must specify src-address= with the target IP."""
        engine = IronCurtainEngine()
        rule = engine.generate_mikrotik_rule("1.2.3.4")
        assert "src-address=1.2.3.4" in rule

    def test_mikrotik_rule_starts_with_ip_firewall(self):
        """The command must start with the /ip firewall path."""
        engine = IronCurtainEngine()
        rule = engine.generate_mikrotik_rule("1.2.3.4")
        assert rule.startswith("/ip firewall")

    def test_mikrotik_rule_with_cidr_range(self):
        """generate_mikrotik_rule() must handle CIDR notation."""
        engine = IronCurtainEngine()
        rule = engine.generate_mikrotik_rule("172.16.0.0/12")
        assert "src-address=172.16.0.0/12" in rule

    def test_mikrotik_rule_returns_string(self):
        """Return type must be a string."""
        engine = IronCurtainEngine()
        rule = engine.generate_mikrotik_rule("1.2.3.4")
        assert isinstance(rule, str)


# ---------------------------------------------------------------------------
# 5. Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_ufw_rule_strips_whitespace_from_ip(self):
        """Leading/trailing whitespace in the IP must be stripped."""
        engine = IronCurtainEngine()
        rule = engine.generate_ufw_rule("  185.220.101.1  ")
        assert rule == "ufw deny from 185.220.101.1"

    def test_iptables_rule_strips_whitespace_from_ip(self):
        """Leading/trailing whitespace in the IP must be stripped."""
        engine = IronCurtainEngine()
        rule = engine.generate_iptables_rule("  10.0.0.1  ")
        assert rule == "iptables -A INPUT -s 10.0.0.1 -j DROP"

    def test_mikrotik_rule_strips_whitespace_from_ip(self):
        """Leading/trailing whitespace in the IP must be stripped."""
        engine = IronCurtainEngine()
        rule = engine.generate_mikrotik_rule("  10.0.0.1  ")
        assert "src-address=10.0.0.1" in rule

    def test_generate_ufw_rule_empty_ip_raises_error(self):
        """An empty string IP must raise a ValueError."""
        engine = IronCurtainEngine()
        with pytest.raises(ValueError):
            engine.generate_ufw_rule("")

    def test_generate_iptables_rule_empty_ip_raises_error(self):
        """An empty string IP must raise a ValueError."""
        engine = IronCurtainEngine()
        with pytest.raises(ValueError):
            engine.generate_iptables_rule("")

    def test_generate_mikrotik_rule_empty_ip_raises_error(self):
        """An empty string IP must raise a ValueError."""
        engine = IronCurtainEngine()
        with pytest.raises(ValueError):
            engine.generate_mikrotik_rule("")


# ---------------------------------------------------------------------------
# 6. Batch Generation
# ---------------------------------------------------------------------------

class TestBatchGeneration:

    def test_generate_rules_for_multiple_ips(self):
        """
        If the engine has a batch method, it must generate one rule per IP.
        Otherwise, calling the single-IP method in a loop must work correctly.
        """
        engine = IronCurtainEngine()
        ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        rules = [engine.generate_ufw_rule(ip) for ip in ips]
        assert len(rules) == 3
        assert rules[0] == "ufw deny from 1.1.1.1"
        assert rules[1] == "ufw deny from 2.2.2.2"
        assert rules[2] == "ufw deny from 3.3.3.3"
