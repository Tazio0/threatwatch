class SeverityScorer:

    def normalize(self, raw_severity, source: str) -> str:
        source_name = (source or "").strip().lower()

        if source_name == "abuseipdb":
            try:
                score = int(raw_severity)
            except (TypeError, ValueError):
                return  "medium"

            if score <= 25:
                return "low"
            if score <= 50:
                return "medium"
            if score <= 75:
                return "high"
            return "critical"

        elif source_name == "urlhaus":
            category = (raw_severity or "").strip().lower()

            if category == "malware_download":
                return "critical"
            if category == "phishing":
                return "high"
            return "medium"

        elif source_name == "alienvault otx":
            severity = (raw_severity or "").strip().lower()

            if  severity in {"low", "medium", "high", "critical"}:
                return severity
            return "medium"

        elif source_name == "blocklist.de":
            return "medium"

        elif source_name == "phishtank":
            return "high"

        return "medium"
