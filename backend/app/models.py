from datetime import datetime

class Threat:

    def __init__(self, indicator, type, source, severity, country = None):
        self.indicator = indicator
        self.type = type
        self.source = source
        self.severity = severity
        self.country = country
        self.created_at = datetime.now()

    def __repr__(self):
        return f"Threat(indicator={self.indicator})"

class HoneypotLog:
    def __init__(self, attacker_ip, port, username=None, password=None,protocol="tcp"):
        self.attacker_ip = attacker_ip
        self.port = port
        self.username = username
        self.password = password
        self.protocol = protocol
        self.created_at = datetime.now()

    def __repr__(self):
        return f"HoneypotLog(attacker_ip={self.attacker_ip})"

class FirewallRule:
    def __init__(self, target_ip, rule_command, rule_type= None, is_active = True, source = None):
        self.target_ip = target_ip
        self.rule_command = rule_command
        self.rule_type = rule_type
        self.is_active = is_active
        self.source = source
        self.created_at = datetime.now()

    def __repr__(self):
        return f"FirewallRule(target_ip={self.target_ip})"




