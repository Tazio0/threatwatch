from abc import ABC, abstractmethod

class BaseIngestor(ABC):
    
    def __init__(self, feed_name, base_url, api_key = None):
        self.feed_name = feed_name
        self.base_url = base_url
        self.api_key = api_key

        @abstractmethod
        def fetch(self):
            pass

        @abstractmethod
        def parse(self, raw_data):
            pass

class AbuseIPIngestor(BaseIngestor):
    def __init__(self, api_key):
        super().__init__(feed_name = "AbuseIPDB", base_url="abuseipdb.com", api_key=api_key)


    def fetch(self):
        pass

    def parse(self, raw_data):
        data = raw_data["data"]

        if not data:
            return []

        new_data = []

        for i in data:
            j = {
                "indicator": i["ipAddress"],
                "type":"ip",
                "source": self.feed_name,
                "severity": i["abuseConfidenceScore"],
                "country": i.get("countryCode")
            }
            new_data.append(j)
        return new_data


class AlienVaultIngestor(BaseIngestor):
    pass

class URLhausIngestor(BaseIngestor):
    pass

class PhishTankIngestor(BaseIngestor):
    pass

class BlocklistDeIngestor(BaseIngestor):
    pass