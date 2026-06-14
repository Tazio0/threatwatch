class IronCurtainEngine:
    def __init__(self):
        ...

    def generate_ufw_rule(self, ip):
        ip = ip.strip()
        if not ip:
            raise ValueError

        return f"ufw deny from {ip}"

    def generate_iptables_rule(self, ip):
        ip = ip.strip()

        if not ip:
            raise ValueError

        return f"iptables -A INPUT -s {ip} -j DROP"

    def generate_mikrotik_rule(self, ip):
        ip = ip.strip()

        if not ip:
            raise ValueError

        return f"/ip firewall filter add chain=input src-address={ip} action=drop"

