import logging
import shutil
import tarfile
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

from backend.app.config import MAXMIND_LICENSE_KEY


LOGGER = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parents[3]
GEOIP_DIR = PROJECT_ROOT / "data" / "geoip"
COUNTRY_DB_PATH = GEOIP_DIR / "GeoLite2-Country.mmdb"
ASN_DB_PATH = GEOIP_DIR / "GeoLite2-ASN.mmdb"
MAXMIND_DOWNLOAD_URL = "https://download.maxmind.com/app/geoip_download"

GEOIP_EDITIONS = {
    "GeoLite2-Country": COUNTRY_DB_PATH,
    "GeoLite2-ASN": ASN_DB_PATH,
}


def ensure_geoip_databases() -> None:
    license_key = (MAXMIND_LICENSE_KEY or "").strip()
    missing_editions = [edition for edition, path in GEOIP_EDITIONS.items() if not path.exists()]

    if not missing_editions or not license_key:
        return

    GEOIP_DIR.mkdir(parents=True, exist_ok=True)

    for edition in missing_editions:
        try:
            _download_geoip_edition(edition, GEOIP_EDITIONS[edition], license_key)
        except Exception as error:
            LOGGER.warning("Could not download %s database: %s", edition, error)


def _download_geoip_edition(edition: str, target_path: Path, license_key: str) -> None:
    query = urllib.parse.urlencode({
        "edition_id": edition,
        "license_key": license_key,
        "suffix": "tar.gz",
    })
    url = f"{MAXMIND_DOWNLOAD_URL}?{query}"

    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        archive_path = temp_dir / f"{edition}.tar.gz"

        with urllib.request.urlopen(url, timeout=60) as response, archive_path.open("wb") as archive_file:
            shutil.copyfileobj(response, archive_file)

        extracted_mmdb = _extract_mmdb(archive_path, temp_dir)
        if extracted_mmdb is None:
            raise RuntimeError(f"No .mmdb file found in {edition} archive")

        temp_target = target_path.with_name(f"{target_path.name}.tmp")
        shutil.copyfile(extracted_mmdb, temp_target)
        temp_target.replace(target_path)


def _extract_mmdb(archive_path: Path, temp_dir: Path) -> Path | None:
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile() or not member.name.endswith(".mmdb"):
                continue

            source = archive.extractfile(member)
            if source is None:
                return None

            extracted_path = temp_dir / Path(member.name).name
            with source, extracted_path.open("wb") as output:
                shutil.copyfileobj(source, output)
            return extracted_path

    return None
