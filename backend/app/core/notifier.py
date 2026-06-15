import requests
from datetime import datetime

'''
Sends notifications to discord via webhook
'''
class DiscordNotifier:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url

    def format_card(self, title, description, severity, fields = None):
        colors = {
            "critical": 0xFF0000,
            "high": 0xFF8C00,
            "medium": 0xFFD700,
            "low": 0x00FF00
        }
        discord_card = {"title" : title, "description" : description,
                        "color" : colors.get(severity, 0x808080),
                        "timestamp" : datetime.now().isoformat(),
                        "fields" : fields}

        return discord_card

    def send_alert(self, card):
        try:
            response = requests.post(self.webhook_url, json={"embeds":[card]})

            if 200<= response.status_code < 300:
                return True
            else:
                return False

        except Exception as e:
            return False


