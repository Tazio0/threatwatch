import geoip2.database

from backend.app.services.geoip_service import ASN_DB_PATH, COUNTRY_DB_PATH

def geo_lookup(ip: str) -> dict:
    ip = ip.strip()

    result = {}

    try:
        with geoip2.database.Reader(COUNTRY_DB_PATH) as reader:
            response = reader.country(ip)
        if response.country.iso_code:
            result["country_code"] = response.country.iso_code
    except Exception:
        pass

    try:
        with geoip2.database.Reader(ASN_DB_PATH) as reader:
            asn_response = reader.asn(ip)
        if asn_response.autonomous_system_organization:
            result["isp"] = asn_response.autonomous_system_organization
    except Exception:
        pass

    return result

class ThreatEnricher:
    def enrich(self, threat: dict) -> dict:
        result = threat.copy()

        if result.get("type") != "ip":
            return result

        try:
            geo_data = geo_lookup(result.get("indicator", ""))
            result.update(geo_data)
        except Exception:
            return result

        return result
