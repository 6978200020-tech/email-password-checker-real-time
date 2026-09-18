#!/usr/bin/env python3
"""Small local server for the privacy-safe domain auditor."""
import json
import os
import sys
import threading
import webbrowser
import argparse
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import smtp_probe

HOST = "127.0.0.1"
PORT = 8765
MAX_DOMAIN_LENGTH = 253
RATE_WINDOW_SECONDS = 60
MAX_PROBES_PER_WINDOW = 12
DOMAIN_COOLDOWN_SECONDS = 10
MAX_IN_FLIGHT_PROBES = 2
REQUEST_TIMEOUT_SECONDS = 30


class AuditorHandler(BaseHTTPRequestHandler):
    _rate_lock = threading.Lock()
    _client_requests = {}
    _domain_requests = {}
    _probe_slots = threading.BoundedSemaphore(MAX_IN_FLIGHT_PROBES)

    def _send(self, status, payload, content_type="application/json; charset=utf-8"):
        body = payload if isinstance(payload, bytes) else (
            json.dumps(payload, ensure_ascii=True).encode("utf-8")
        )
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self._send(200, {"ok": True, "service": "domain-auditor"})
            return
        if parsed.path == "/api/probe":
            self._probe(parse_qs(parsed.query).get("domain", [""])[0])
            return
        if parsed.path in ("/", "/main"):
            self._serve_main()
            return
        self._send(404, {"ok": False, "error": "Not found"})

    def _probe(self, raw_domain):
        if not isinstance(raw_domain, str) or len(raw_domain) > MAX_DOMAIN_LENGTH:
            self._send(400, {"ok": False, "error": "Domain is missing or too long"})
            return
        domain = smtp_probe.normalize_domain(raw_domain)
        if not domain:
            self._send(400, {"ok": False, "error": "Invalid domain"})
            return
        client = self.client_address[0]
        allowed, retry_after, reason = self._allow_probe(client, domain)
        if not allowed:
            self._send(
                429,
                {
                    "ok": False,
                    "error": reason,
                    "retry_after_seconds": retry_after,
                },
            )
            return
        if not self._probe_slots.acquire(blocking=False):
            self._send(
                429,
                {
                    "ok": False,
                    "error": "Too many probes are running; try again shortly",
                    "retry_after_seconds": 2,
                },
            )
            return
        started = time.monotonic()
        try:
            result = smtp_probe.probe_domain(
                domain,
                probe_mx_connect=True,
                mx_probe_limit=3,
                smtp_timeout=4.0,
                smtp_delay=0.5,
            )
            result["api_duration_ms"] = round((time.monotonic() - started) * 1000)
            self._send(200, {"ok": True, "result": result})
        except Exception as exc:
            self._send(502, {"ok": False, "error": "Probe failed", "detail": str(exc)[:300]})
        finally:
            self._probe_slots.release()

    @classmethod
    def _allow_probe(cls, client, domain):
        now = time.monotonic()
        with cls._rate_lock:
            client_history = [
                timestamp for timestamp in cls._client_requests.get(client, [])
                if now - timestamp < RATE_WINDOW_SECONDS
            ]
            if len(client_history) >= MAX_PROBES_PER_WINDOW:
                retry = max(1, int(RATE_WINDOW_SECONDS - (now - client_history[0])))
                cls._client_requests[client] = client_history
                return False, retry, "Rate limit reached; reduce probe frequency"

            last_domain = cls._domain_requests.get(domain)
            if last_domain is not None and now - last_domain < DOMAIN_COOLDOWN_SECONDS:
                retry = max(1, int(DOMAIN_COOLDOWN_SECONDS - (now - last_domain)))
                cls._client_requests[client] = client_history
                return False, retry, "This domain was checked recently; wait before probing again"

            client_history.append(now)
            cls._client_requests[client] = client_history
            cls._domain_requests[domain] = now
            if len(cls._client_requests) > 256:
                cls._client_requests = {
                    key: values for key, values in cls._client_requests.items()
                    if values and now - values[-1] < RATE_WINDOW_SECONDS
                }
            if len(cls._domain_requests) > 2048:
                cls._domain_requests = {
                    key: timestamp for key, timestamp in cls._domain_requests.items()
                    if now - timestamp < DOMAIN_COOLDOWN_SECONDS
                }
            return True, 0, ""

    def _serve_main(self):
        path = os.path.join(os.path.dirname(__file__), "main")
        try:
            with open(path, "rb") as handle:
                self._send(200, handle.read(), "text/html; charset=utf-8")
        except OSError as exc:
            self._send(500, {"ok": False, "error": "Unable to serve main", "detail": str(exc)})

    def log_message(self, format_string, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), format_string % args))


def main():
    parser = argparse.ArgumentParser(description="Start the local email domain auditor")
    parser.add_argument("--host", default=HOST, help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=PORT, help="HTTP port (default: 8765)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open a browser automatically")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), AuditorHandler)
    address = "http://%s:%d" % (args.host, args.port)
    print("Domain auditor: %s" % address)
    if not args.no_browser:
        threading.Timer(0.5, webbrowser.open, args=(address,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
