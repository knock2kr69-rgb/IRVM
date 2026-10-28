import json
import os
import threading
import time
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent
PORT = int(os.environ.get("PORT", "8080"))
NVD_CVES_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_SECONDS = 900
TARGETS = [
    {
        "assetId": "LIVE-PHP-82",
        "department": "PHP 자산",
        "system": "PHP 8.2.34",
        "product": "PHP",
        "version": "8.2.34",
        "cpeName": "cpe:2.3:a:php:php:8.2.34:*:*:*:*:*:*:*",
    },
    {
        "assetId": "LIVE-TOMCAT-110",
        "department": "Tomcat 자산",
        "system": "Apache Tomcat 11.0.22",
        "product": "Apache Tomcat",
        "version": "11.0.22",
        "cpeName": "cpe:2.3:a:apache:tomcat:11.0.22:*:*:*:*:*:*:*",
    },
]
_cache = {"expires": 0, "data": None}
_cache_lock = threading.Lock()


def _request_json(url, *, headers=None, timeout=30):
    request_headers = {
        "Accept": "application/json",
        "User-Agent": "InformationSystemVulnerabilityManagement/1.0",
    }
    request_headers.update(headers or {})
    request = Request(url, headers=request_headers)
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _nvd_cves(target):
    params = urlencode({"cpeName": target["cpeName"], "resultsPerPage": 2000})
    headers = {}
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    payload = _request_json(f"{NVD_CVES_URL}?{params}", headers=headers)
    return payload.get("vulnerabilities", [])


def _has_vulnerable_product_match(cve, target):
    target_parts = target["cpeName"].split(":")
    configurations = cve.get("configurations", [])

    def visit(value):
        if isinstance(value, dict):
            for match in value.get("cpeMatch", []):
                criteria = match.get("criteria", "").split(":")
                if (
                    match.get("vulnerable") is True
                    and len(criteria) > 4
                    and criteria[2:5] == target_parts[2:5]
                ):
                    return True
            return any(visit(item) for item in value.values())
        if isinstance(value, list):
            return any(visit(item) for item in value)
        return False

    return visit(configurations)


def _cvss_metrics(cve):
    metrics = cve.get("metrics", {})
    result = []
    for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for item in metrics.get(metric_key, []):
            data = item.get("cvssData", {})
            if data.get("baseScore") is None:
                continue
            result.append(
                {
                    "version": data.get("version", ""),
                    "score": data["baseScore"],
                    "severity": data.get("baseSeverity", item.get("baseSeverity", "")),
                    "sourceType": item.get("type", ""),
                    "source": item.get("source", ""),
                }
            )
    result.sort(key=lambda item: (item["sourceType"] != "Primary", item["version"]), reverse=False)
    return result


def _normalize_cve(entry, target, kev_by_id, kev_available):
    cve = entry.get("cve", {})
    descriptions = cve.get("descriptions", [])
    description = next(
        (item.get("value", "") for item in descriptions if item.get("lang") == "en"),
        descriptions[0].get("value", "") if descriptions else "",
    )
    kev = kev_by_id.get(cve.get("id"))
    return {
        "assetId": target["assetId"],
        "department": target["department"],
        "system": target["system"],
        "product": target["product"],
        "version": target["version"],
        "cveId": cve.get("id", ""),
        "description": description,
        "published": cve.get("published", ""),
        "lastModified": cve.get("lastModified", ""),
        "cvss": _cvss_metrics(cve),
        "kev": None if not kev_available else kev is not None,
        "kevStatus": "listed" if kev else "not-listed" if kev_available else "unavailable",
        "kevDateAdded": kev.get("dateAdded", "") if kev else "",
        "kevName": kev.get("vulnerabilityName", "") if kev else "",
        "kevRequiredAction": kev.get("requiredAction", "") if kev else "",
        "nvdUrl": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
    }


def get_live_vulnerabilities():
    now = time.time()
    with _cache_lock:
        if _cache["data"] is not None and _cache["expires"] > now:
            return _cache["data"]

        kev_error = ""
        try:
            kev_payload = _request_json(CISA_KEV_URL, timeout=12)
            kev_entries = kev_payload.get("vulnerabilities", [])
            kev_by_id = {item.get("cveID"): item for item in kev_entries if item.get("cveID")}
            kev_available = True
        except (HTTPError, URLError, TimeoutError, ValueError) as error:
            kev_by_id = {}
            kev_available = False
            kev_error = f"CISA KEV 조회 실패: {error}"

        vulnerabilities = []
        for target in TARGETS:
            for entry in _nvd_cves(target):
                cve = entry.get("cve", {})
                if not _has_vulnerable_product_match(cve, target):
                    continue
                vulnerabilities.append(_normalize_cve(entry, target, kev_by_id, kev_available))

        vulnerabilities.sort(
            key=lambda item: (
                not item["kev"],
                -max((metric["score"] for metric in item["cvss"]), default=-1),
                item["cveId"],
            )
        )
        payload = {
            "retrievedAt": datetime.now(timezone.utc).isoformat(),
            "sources": {
                "nvd": "https://nvd.nist.gov/developers/vulnerabilities",
                "cisaKev": CISA_KEV_URL,
            },
            "kevAvailable": kev_available,
            "kevError": None if not kev_available else kev_error,
            "targets": TARGETS,
            "total": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        }
        _cache["data"] = payload
        _cache["expires"] = now + CACHE_SECONDS
        return payload


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self):
        if urlsplit(self.path).path != "/api/real-vulnerabilities":
            return super().do_GET()
        try:
            body = json.dumps(get_live_vulnerabilities(), ensure_ascii=False).encode("utf-8")
            self.send_response(200)
        except (HTTPError, URLError, TimeoutError, ValueError) as error:
            body = json.dumps(
                {"error": f"NVD CVE 조회에 실패했습니다: {error}"}, ensure_ascii=False
            ).encode("utf-8")
            self.send_response(502)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"서버 실행: http://127.0.0.1:{PORT}")
    print("종료하려면 Ctrl+C를 누르세요.")
    server.serve_forever()