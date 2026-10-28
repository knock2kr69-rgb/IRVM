import json
from http.server import BaseHTTPRequestHandler
from urllib.error import HTTPError, URLError

from assetguard.server import get_live_vulnerabilities


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            payload = get_live_vulnerabilities()
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            status = 200
        except (HTTPError, URLError, TimeoutError, ValueError) as error:
            body = json.dumps(
                {"error": f"NVD CVE 조회에 실패했습니다: {error}"},
                ensure_ascii=False,
            ).encode("utf-8")
            status = 502

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)