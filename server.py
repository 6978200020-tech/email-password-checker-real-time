#!/usr/bin/env python3
"""Small local server for the privacy-safe domain auditor."""
import json
import os
import sys
import threading
import webbrowser
import argparse
import time
from concurrent.futures import ThreadPoolExecutor
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
MAX_EMAIL_LENGTH = 320
EMAIL_REPORT_CACHE_SECONDS = 300
DOMAIN_REPORT_CACHE_SECONDS = 300
MAX_EMAIL_LIST_ITEMS = 100
MAX_BATCH_BODY_BYTES = 1_000_000
MAX_BATCH_REQUESTS_PER_WINDOW = 3


class AuditorHandler(BaseHTTPRequestHandler):
    _rate_lock = threading.Lock()
    _client_requests = {}
    _domain_requests = {}
    _probe_slots = threading.BoundedSemaphore(MAX_IN_FLIGHT_PROBES)
    _email_report_cache = {}
    _domain_report_cache = {}
    _batch_requests = {}

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
        if parsed.path == "/api/email-report":
            self._email_report(parse_qs(parsed.query).get("email", [""])[0])
            return
        if parsed.path in ("/", "/main"):
            self._serve_main()
            return
        self._send(404, {"ok": False, "error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/email-list-report":
            self._email_list_report()
            return
        self._send(404, {"ok": False, "error": "Not found"})

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None, "Invalid request length"
        if length <= 0 or length > MAX_BATCH_BODY_BYTES:
            return None, "Request body is missing or too large"
        try:
            return json.loads(self.rfile.read(length).decode("utf-8")), ""
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, "Request body must be valid JSON"

    def _email_list_report(self):
        payload, error = self._read_json_body()
        if error:
            self._send(400, {"ok": False, "error": error})
            return
        if not isinstance(payload, dict) or not isinstance(payload.get("emails"), list):
            self._send(400, {"ok": False, "error": "Send an emails array"})
            return
        raw_emails = payload["emails"]
        if not raw_emails or len(raw_emails) > MAX_EMAIL_LIST_ITEMS:
            self._send(
                400,
                {"ok": False, "error": "Provide between 1 and 100 email addresses"},
            )
            return
        client = self.client_address[0]
        if not self._allow_batch(client):
            self._send(
                429,
                {
                    "ok": False,
                    "error": "Batch limit reached; wait before starting another list",
                    "retry_after_seconds": RATE_WINDOW_SECONDS,
                },
            )
            return

        emails = []
        seen = set()
        rejected = []
        for item in raw_emails:
            if not isinstance(item, str):
                rejected.append("non-text input")
                continue
            value = item.strip()
            if not value:
                continue
            # Deliberately reject credential-shaped input instead of guessing
            # which part is an address.
            if ":" in value:
                rejected.append(value[:120])
                continue
            address = smtp_probe.split_email_address(value)
            key = address["input"].lower()
            if key in seen:
                continue
            seen.add(key)
            emails.append(value)
        if not emails:
            self._send(
                400,
                {
                    "ok": False,
                    "error": "No email-only lines found; password formats are not accepted",
                    "rejected": rejected[:10],
                },
            )
            return

        domain_names = list(dict.fromkeys(
            smtp_probe.split_email_address(email)["domain"]
            for email in emails
            if smtp_probe.split_email_address(email)["valid"]
        ))

        def make_domain_report(domain):
            try:
                cached = self._get_cached_domain_report(domain)
                if cached is not None:
                    return domain, cached, ""
                if not self._probe_slots.acquire(timeout=REQUEST_TIMEOUT_SECONDS):
                    return domain, None, "Probe capacity timed out"
                try:
                    result = smtp_probe.probe_domain(
                        domain, probe_mx_connect=False
                    )
                    self._cache_domain_report(domain, result)
                    return domain, result, ""
                finally:
                    self._probe_slots.release()
            except Exception as exc:
                return domain, None, str(exc)[:200]

        with ThreadPoolExecutor(max_workers=4) as executor:
            domain_results = dict(
                (domain, (result, error))
                for domain, result, error in executor.map(
                    make_domain_report, domain_names
                )
            )

        def make_report(email):
            address = smtp_probe.split_email_address(email)
            if not address["valid"]:
                return smtp_probe.build_email_report(
                    email, probe_domain_result=False
                )
            domain_result, error = domain_results.get(
                address["domain"], (None, "Domain report unavailable")
            )
            if error:
                return {
                    "email": email,
                    "valid_email_syntax": True,
                    "status": "error",
                    "error": error,
                }
            return smtp_probe.build_email_report(
                email,
                probe_domain_result=False,
                domain_result=domain_result,
            )

        reports = [make_report(email) for email in emails]
        self._send(
            200,
            {
                "ok": True,
                "results": reports,
                "accepted": len(reports),
                "rejected": rejected[:10],
                "limits": {
                    "max_items": MAX_EMAIL_LIST_ITEMS,
                    "account_verification": "not_performed",
                    "credential_check": "not_performed",
                    "smtp_recipient_probe": "not_performed",
                },
            },
        )

    @classmethod
    def _allow_batch(cls, client):
        now = time.monotonic()
        with cls._rate_lock:
            history = [
                timestamp
                for timestamp in cls._batch_requests.get(client, [])
                if now - timestamp < RATE_WINDOW_SECONDS
            ]
            if len(history) >= MAX_BATCH_REQUESTS_PER_WINDOW:
                cls._batch_requests[client] = history
                return False
            history.append(now)
            cls._batch_requests[client] = history
            return True

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

    def _email_report(self, raw_email):
        if not isinstance(raw_email, str) or not raw_email or len(raw_email) > MAX_EMAIL_LENGTH:
            self._send(400, {"ok": False, "error": "Email is missing or too long"})
            return
        address = smtp_probe.split_email_address(raw_email)
        if not address["valid"]:
            self._send(
                400,
                {
                    "ok": False,
                    "result": smtp_probe.build_email_report(
                        raw_email, probe_domain_result=False
                    ),
                },
            )
            return
        cache_key = address["input"].lower()
        now = time.monotonic()
        with self._rate_lock:
            cached = self._email_report_cache.get(cache_key)
            if cached and now - cached[0] < EMAIL_REPORT_CACHE_SECONDS:
                report = dict(cached[1])
                report["cached"] = True
                self._send(200, {"ok": True, "result": report})
                return
            if cached:
                self._email_report_cache.pop(cache_key, None)
        cached_domain_report = self._get_cached_domain_report(address["domain"])
        if cached_domain_report is not None:
            report = smtp_probe.build_email_report(
                raw_email,
                probe_domain_result=False,
                domain_result=cached_domain_report,
            )
            report["cached"] = True
            with self._rate_lock:
                self._email_report_cache[cache_key] = (
                    time.monotonic(), dict(report)
                )
            self._send(200, {"ok": True, "result": report})
            return
        allowed, retry_after, reason = self._allow_probe(
            self.client_address[0], address["domain"]
        )
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
        try:
            report = smtp_probe.build_email_report(raw_email, probe_domain_result=True)
            self._cache_domain_report(
                address["domain"], report.get("domain_report", {})
            )
            with self._rate_lock:
                self._email_report_cache[cache_key] = (time.monotonic(), dict(report))
                if len(self._email_report_cache) > 512:
                    oldest = sorted(
                        self._email_report_cache.items(), key=lambda item: item[1][0]
                    )[:128]
                    for key, _ in oldest:
                        self._email_report_cache.pop(key, None)
            self._send(200, {"ok": True, "result": report})
        except Exception as exc:
            self._send(502, {"ok": False, "error": "Email report failed", "detail": str(exc)[:300]})
        finally:
            self._probe_slots.release()

    @classmethod
    def _get_cached_domain_report(cls, domain):
        now = time.monotonic()
        with cls._rate_lock:
            entry = cls._domain_report_cache.get(domain)
            if entry and now - entry[0] < DOMAIN_REPORT_CACHE_SECONDS:
                return entry[1]
            if entry:
                cls._domain_report_cache.pop(domain, None)
        return None

    @classmethod
    def _cache_domain_report(cls, domain, result):
        with cls._rate_lock:
            cls._domain_report_cache[domain] = (time.monotonic(), result)
            if len(cls._domain_report_cache) > 512:
                now = time.monotonic()
                cls._domain_report_cache = {
                    key: entry
                    for key, entry in cls._domain_report_cache.items()
                    if now - entry[0] < DOMAIN_REPORT_CACHE_SECONDS
                }
                if len(cls._domain_report_cache) > 512:
                    oldest = sorted(
                        cls._domain_report_cache.items(),
                        key=lambda item: item[1][0],
                    )[:-512]
                    for key, _ in oldest:
                        cls._domain_report_cache.pop(key, None)

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
