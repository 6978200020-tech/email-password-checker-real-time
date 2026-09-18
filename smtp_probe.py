#!/usr/bin/env python3
"""
smtp_probe.py
Safe SMTP probing + DNS/MX/SPF/DMARC checks for a domain.
Dependencies: dnspython (recommended). Install: pip install dnspython

Usage: python smtp_probe.py example.com

Design notes (keeps connections minimal and polite):
- Uses timeouts and single EHLO only (no VRFY/RCPT/MAIL) to avoid spamming/abuse
- Uses one bounded connection per selected MX host and reports connectivity,
  TLS support, and the server response
- Performs TXT checks for SPF, DMARC and basic disposable-domain heuristics
- Adds sanity checks so malformed domains, blocked SMTP ports, and dead hosts are
  identified quickly instead of being treated as "live" solely by name.
"""
import re
import socket
import json
import ssl
import smtplib
import threading
import time
import random
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

try:
    import dns.resolver
    import dns.exception
except Exception:
    dns = None

# Small disposable domain sample list — extend as needed
DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "10minutemail.com",
    "guerrillamail.com",
    "trashmail.com",
    "tempmail.com",
}

# Port 25 is sufficient to establish SMTP reachability and avoids probing
# submission services unnecessarily.
SMTP_PORTS = (25,)
DEFAULT_TIMEOUT = 5.0
DEFAULT_CONNECT_DELAY = 0.5
DEFAULT_JITTER_SECONDS = 0.15
DNS_CACHE_SECONDS = 30.0
SMTP_CACHE_SECONDS = 60.0
SMTP_POLICY_COOLDOWN_SECONDS = 900.0
MAX_SMTP_ATTEMPTS_PER_HOST = 1
PROVIDER_MX_MARKERS = {
    "Google Workspace": ("google.com", "googlemail.com", "aspmx.l.google.com"),
    "Microsoft 365": ("protection.outlook.com", "mail.protection.outlook.com"),
    "Proton Mail": ("protonmail.ch", "protonmail.com"),
}
CONSUMER_GOOGLE_DOMAINS = {"gmail.com", "googlemail.com"}
ROLE_LOCAL_PARTS = {
    "admin", "administrator", "billing", "contact", "help", "info", "mail",
    "no-reply", "noreply", "office", "root", "sales", "security", "support",
    "team",
}
COMMON_DOMAIN_TYPOS = {
    "gmai.com": "gmail.com",
    "gmial.com": "gmail.com",
    "gmail.co": "gmail.com",
    "gmail.con": "gmail.com",
    "yaho.com": "yahoo.com",
    "yahho.com": "yahoo.com",
    "hotnail.com": "hotmail.com",
    "hotmai.com": "hotmail.com",
    "outlok.com": "outlook.com",
}

_DNS_CACHE = {}
_DNS_CACHE_LOCK = threading.Lock()
_SMTP_CACHE = {}
_SMTP_CACHE_LOCK = threading.Lock()
_SMTP_POLICY_UNTIL = {}

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


def normalize_domain(domain):
    """Normalize domain input and reject malformed values early."""
    if domain is None:
        return ""
    value = str(domain).strip().strip(".").lower()
    if not value:
        return ""
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    if "://" in value:
        value = urlsplit(value).hostname or value
    elif "//" in value:
        value = urlsplit("//" + value).hostname or value
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    value = value.rstrip(".")
    if value.startswith("."):
        value = value.lstrip(".")
    try:
        import idna
        value = idna.encode(value, uts46=True).decode("ascii")
    except Exception:
        pass
    if len(value) > 253:
        return ""
    labels = value.split(".")
    if not labels or any(not label for label in labels):
        return ""
    for label in labels:
        if len(label) > 63:
            return ""
        if label.startswith("-") or label.endswith("-"):
            return ""
        if not re.fullmatch(r"[A-Za-z0-9_-]+", label):
            if "xn--" not in label and "-" in label:
                keep = True
                for ch in label:
                    if not (ch.isalnum() or ch == "-"):
                        keep = False
                        break
                if not keep:
                    return ""
            else:
                return ""
    if not DOMAIN_RE.fullmatch(value):
        # Accept punycode domains and practical email domains with multi-part TLDs.
        if not all(label and re.fullmatch(r"[A-Za-z0-9-]+", label) for label in labels):
            return ""
    return value


def domain_summary(domain):
    normalized = normalize_domain(domain)
    return {
        "input": str(domain),
        "normalized": normalized,
        "valid": bool(normalized),
    }


def split_email_address(email):
    """Parse an address without implying that the mailbox exists."""
    value = str(email or "").strip()
    if value.count("@") != 1:
        return {"input": value, "valid": False, "local": "", "domain": ""}
    local, raw_domain = value.rsplit("@", 1)
    domain = normalize_domain(raw_domain)
    valid = bool(local and domain and len(local) <= 64 and not any(
        char.isspace() for char in local
    ))
    return {
        "input": value,
        "valid": valid,
        "local": local if valid else "",
        "domain": domain if valid else "",
    }


def build_email_report(email, probe_domain_result=True):
    """Return public domain evidence only; never check credentials or a mailbox."""
    address = split_email_address(email)
    report = {
        "email": address["input"],
        "valid_email_syntax": address["valid"],
        "account_verification": "not_performed",
        "credential_check": "not_performed",
        "privacy_note": (
            "This report uses public DNS/MX evidence and cannot prove that a "
            "specific mailbox or password exists."
        ),
    }
    if not address["valid"]:
        report["status"] = "invalid_email"
        return report
    report["domain"] = address["domain"]
    local = address["local"]
    report["local_part"] = local
    report["address_type"] = "role_or_shared" if local.lower() in ROLE_LOCAL_PARTS else "individual_or_unknown"
    report["domain_suggestion"] = COMMON_DOMAIN_TYPOS.get(address["domain"], "")
    if address["domain"] in CONSUMER_GOOGLE_DOMAINS:
        report["google_account_scope"] = "Google consumer mail domain"
        report["gmail_alias_notes"] = [
            "Dots in the Gmail local part are generally ignored for delivery.",
            "A plus suffix is commonly used for labels, such as user+tag@gmail.com.",
        ]
    else:
        report["google_account_scope"] = "Not a consumer Gmail domain"
    if not probe_domain_result:
        report["status"] = "syntax_valid"
        return report
    result = probe_domain(address["domain"], probe_mx_connect=False)
    report["domain_report"] = result
    provider = result.get("mail_provider", "Other/Custom")
    report["mail_provider"] = provider
    if provider == "Google Workspace":
        report["provider_scope"] = (
            "Google-hosted mail infrastructure detected for this domain"
        )
    else:
        report["provider_scope"] = "Public mail infrastructure classification only"
    signals = result.get("signals", {})
    if result.get("status") == "active" and signals.get("mail_exchange_present"):
        report["deliverability_signal"] = "public_mail_infrastructure_present"
    elif signals.get("mail_exchange_present"):
        report["deliverability_signal"] = "public_mail_infrastructure_uncertain"
    else:
        report["deliverability_signal"] = "no_confirmed_mail_exchange"
    report["status"] = "domain_reported"
    return report


def lookup_mx(domain):
    """Return sorted list of (priority, host) for MX records or []"""
    if dns is None:
        return {"error": "dnspython not installed"}
    cached = _get_cached_dns("MX", domain)
    if cached is not None:
        return cached
    res = dns.resolver.Resolver()
    res.lifetime = DEFAULT_TIMEOUT
    res.timeout = min(DEFAULT_TIMEOUT, 2.0)
    try:
        answers = res.resolve(domain, "MX")
    except dns.resolver.NXDOMAIN:
        result = {"error": "NXDOMAIN", "error_type": "nxdomain"}
        _cache_dns("MX", domain, result)
        return result
    except dns.resolver.NoAnswer:
        # RFC 5321 permits implicit MX: the domain's own address is the
        # delivery host when no MX RR exists.
        result = {"mx": [], "implicit_mx": True, "note": "No MX record; checking the domain host as an implicit MX."}
        _cache_dns("MX", domain, result)
        return result
    except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
        result = {"error": str(e), "error_type": "resolver_unavailable"}
        _cache_dns("MX", domain, result)
        return result
    except Exception as e:
        result = {"error": str(e), "error_type": "lookup_failed"}
        _cache_dns("MX", domain, result)
        return result
    mxs = []
    null_mx = False
    for r in answers:
        # r.exchange is a Name object
        exchange = str(r.exchange).rstrip(".")
        if exchange:
            mxs.append((r.preference, exchange))
        else:
            null_mx = True
    mxs.sort(key=lambda x: x[0])
    result = {"mx": mxs}
    if null_mx:
        result["null_mx"] = True
        result["note"] = "The domain explicitly does not accept email (null MX)."
    _cache_dns("MX", domain, result)
    return result


def _get_cached_dns(record_type, domain):
    key = (record_type, domain)
    now = time.monotonic()
    with _DNS_CACHE_LOCK:
        entry = _DNS_CACHE.get(key)
        if entry and now - entry[0] < DNS_CACHE_SECONDS:
            return entry[1]
        if entry:
            _DNS_CACHE.pop(key, None)
    return None


def _cache_dns(record_type, domain, result):
    with _DNS_CACHE_LOCK:
        _DNS_CACHE[(record_type, domain)] = (time.monotonic(), result)
        if len(_DNS_CACHE) > 512:
            oldest = sorted(_DNS_CACHE.items(), key=lambda item: item[1][0])[:128]
            for key, _ in oldest:
                _DNS_CACHE.pop(key, None)


def _get_cached_smtp(host, ports):
    key = (host.lower(), tuple(ports))
    now = time.monotonic()
    with _SMTP_CACHE_LOCK:
        entry = _SMTP_CACHE.get(key)
        if entry and now - entry[0] < SMTP_CACHE_SECONDS:
            return entry[1]
        if entry:
            _SMTP_CACHE.pop(key, None)
    return None


def _cache_smtp(host, ports, result):
    key = (host.lower(), tuple(ports))
    with _SMTP_CACHE_LOCK:
        _SMTP_CACHE[key] = (time.monotonic(), result)
        if len(_SMTP_CACHE) > 512:
            oldest = sorted(_SMTP_CACHE.items(), key=lambda item: item[1][0])[:128]
            for old_key, _ in oldest:
                _SMTP_CACHE.pop(old_key, None)


def _policy_cooldown_active(host):
    """Avoid retrying a host that explicitly asked us to slow down."""
    now = time.monotonic()
    with _SMTP_CACHE_LOCK:
        until = _SMTP_POLICY_UNTIL.get(host.lower(), 0.0)
        if until <= now:
            _SMTP_POLICY_UNTIL.pop(host.lower(), None)
            return 0
        return max(1, int(until - now))


def _remember_policy_cooldown(host):
    with _SMTP_CACHE_LOCK:
        _SMTP_POLICY_UNTIL[host.lower()] = (
            time.monotonic() + SMTP_POLICY_COOLDOWN_SECONDS
        )


def _resolve_host_addresses(host):
    """Resolve an MX host before connecting and return unique A/AAAA addresses."""
    addresses = {"A": [], "AAAA": [], "error": ""}
    try:
        infos = socket.getaddrinfo(host, 25, type=socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in infos:
            address = sockaddr[0]
            if family == socket.AF_INET:
                addresses["A"].append(address)
            elif family == socket.AF_INET6:
                addresses["AAAA"].append(address)
    except (socket.gaierror, socket.herror, OSError) as exc:
        addresses["error"] = str(exc)
    addresses["A"] = sorted(set(addresses["A"]))
    addresses["AAAA"] = sorted(set(addresses["AAAA"]))
    return addresses


def lookup_a_aaaa(domain):
    """Return A and AAAA addresses using getaddrinfo."""
    cached = _get_cached_dns("A+AAAA", domain)
    if cached is not None:
        return cached
    results = {"A": [], "AAAA": []}
    try:
        infos = socket.getaddrinfo(domain, None)
        for fam, _, _, _, sockaddr in infos:
            if fam == socket.AF_INET:
                results["A"].append(sockaddr[0])
            elif fam == socket.AF_INET6:
                results["AAAA"].append(sockaddr[0])
    except (socket.gaierror, socket.herror, OSError) as e:
        results["error"] = str(e)
    results["A"] = sorted(set(results["A"]))
    results["AAAA"] = sorted(set(results["AAAA"]))
    _cache_dns("A+AAAA", domain, results)
    return results


def lookup_txt(domain):
    if dns is None:
        return {"error": "dnspython not installed"}
    cached = _get_cached_dns("TXT", domain)
    if cached is not None:
        return cached
    res = dns.resolver.Resolver()
    res.lifetime = DEFAULT_TIMEOUT
    res.timeout = min(DEFAULT_TIMEOUT, 2.0)
    try:
        answers = res.resolve(domain, "TXT")
    except dns.resolver.NXDOMAIN:
        result = {"error": "NXDOMAIN", "error_type": "nxdomain"}
        _cache_dns("TXT", domain, result)
        return result
    except dns.resolver.NoAnswer:
        result = {"txt": []}
        _cache_dns("TXT", domain, result)
        return result
    except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
        result = {"error": str(e), "error_type": "resolver_unavailable"}
        _cache_dns("TXT", domain, result)
        return result
    except Exception as e:
        result = {"error": str(e), "error_type": "lookup_failed"}
        _cache_dns("TXT", domain, result)
        return result
    txts = []
    for r in answers:
        try:
            txt = b"".join(r.strings).decode('utf-8', errors='ignore')
        except Exception:
            txt = str(r)
        txts.append(txt)
    result = {"txt": txts}
    _cache_dns("TXT", domain, result)
    return result


def check_spf(domain):
    txt = lookup_txt(domain)
    if "error" in txt:
        return {"error": txt["error"]}
    spfs = [t for t in txt.get("txt", []) if "v=spf1" in t.lower()]
    return {"spf": spfs}


def check_dmarc(domain):
    dname = "_dmarc." + domain
    txt = lookup_txt(dname)
    if "error" in txt:
        return {"error": txt["error"]}
    dms = txt.get("txt", [])
    return {"dmarc": dms}


def check_policy_records(domain):
    """Check published mail-security policy TXT records without contacting providers."""
    names = (
        ("_mta-sts." + domain, "mta_sts"),
        ("_smtp._tls." + domain, "tls_rpt"),
    )
    selectors = ("google", "default", "selector1", "selector2", "dkim")
    queries = list(names) + [
        ("%s._domainkey.%s" % (selector, domain), selector)
        for selector in selectors
    ]
    records = {}
    with ThreadPoolExecutor(max_workers=len(queries)) as executor:
        results = list(executor.map(lambda query: lookup_txt(query[0]), queries))
    for (name, label), result in zip(queries, results):
        if label in ("mta_sts", "tls_rpt"):
            records[label] = result
        elif result.get("txt"):
            records.setdefault("dkim", {})[label] = result
    records.setdefault("dkim", {})
    records["mta_sts_policy"] = fetch_mta_sts_policy(domain)
    return records


def fetch_mta_sts_policy(domain):
    """Fetch only the public MTA-STS policy file with a short bounded timeout."""
    url = "https://mta-sts.%s/.well-known/mta-sts.txt" % domain
    request = Request(url, headers={"User-Agent": "email-domain-auditor/1.0"})
    try:
        with urlopen(request, timeout=3.0) as response:
            if response.status != 200:
                return {"published": False, "error": "HTTP %s" % response.status}
            body = response.read(8192).decode("utf-8", errors="replace")
        fields = {}
        for line in body.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key.strip().lower()] = value.strip()
        valid = fields.get("version") == "STSv1" and fields.get("mode") in (
            "enforce", "testing", "none"
        )
        return {"published": True, "valid": valid, "fields": fields}
    except HTTPError as error:
        return {"published": False, "error": "HTTP %s" % error.code}
    except (URLError, TimeoutError, OSError) as error:
        return {"published": False, "error": str(error)[:160]}


def identify_mail_provider(mx_hosts):
    """Classify common hosted mail providers from MX hostnames only."""
    hosts = [str(host).lower().rstrip(".") for host in mx_hosts]
    for provider, markers in PROVIDER_MX_MARKERS.items():
        if any(
            host == marker or host.endswith("." + marker)
            for host in hosts
            for marker in markers
        ):
            return provider
    return "Other/Custom"


def calculate_domain_health(result):
    """Return a transparent 0-100 infrastructure score, never mailbox validity."""
    signals = result.get("signals", {})
    score = 0
    if signals.get("dns_resolves"):
        score += 25
    if signals.get("mail_exchange_present"):
        score += 30
    if signals.get("smtp_connected"):
        score += 25
    if signals.get("smtp_reachable"):
        score += 10
    if result.get("spf", {}).get("spf"):
        score += 5
    if result.get("dmarc", {}).get("dmarc"):
        score += 5
    if result.get("status") in ("inactive", "invalid"):
        score = min(score, 20)
    return score


def _sleep_with_jitter(base_delay, jitter=DEFAULT_JITTER_SECONDS):
    if base_delay <= 0:
        return
    time.sleep(base_delay + random.uniform(0.0, max(0.0, jitter)))


def _classify_smtp_failure(error_text, code=None):
    text = (error_text or "").lower()
    if not text:
        if code is not None and code >= 500:
            return "permanent_refusal"
        if code is not None and code >= 400:
            return "temporary_refusal"
        return "temporary_or_network_failure"
    if any(token in text for token in ("timed out", "timeout", "connection reset", "network is unreachable", "no route to host", "temporary failure", "connection refused", "cannot assign requested address")):
        return "temporary_or_network_failure"
    if any(token in text for token in ("blocked", "rate limit", "too many connections", "anti-spam", "spam", "policy", "unauthorized", "forbidden", "greylist")):
        return "policy_or_blocked"
    if code is not None:
        if code >= 500:
            return "permanent_refusal"
        if code >= 400:
            return "temporary_refusal"
    return "temporary_or_network_failure"


def safe_smtp_probe(host, ports=SMTP_PORTS, timeout=DEFAULT_TIMEOUT, delay=DEFAULT_CONNECT_DELAY):
    """Connect to the SMTP host on a small set of common ports.

    This is intentionally conservative: only banner/HELO information is collected,
    no mail is delivered and no authentication is attempted.
    """
    cached = _get_cached_smtp(host, ports)
    if cached is not None:
        result = dict(cached)
        result["cached"] = True
        return result
    cooldown = _policy_cooldown_active(host)
    if cooldown:
        return {
            "host": host,
            "ports_tried": list(ports),
            "reachable": False,
            "cached": True,
            "classification": "policy_or_blocked",
            "error": "Host requested slower probing; cooldown is active",
            "retry_after_seconds": cooldown,
        }

    result = {
        "host": host,
        "ports_tried": list(ports),
        "reachable": False,
        "cached": False,
        "classification": "temporary_or_network_failure",
    }
    result["host_addresses"] = _resolve_host_addresses(host)
    if not (result["host_addresses"]["A"] or result["host_addresses"]["AAAA"]):
        result["classification"] = "dns_failure"
        result["error"] = "MX host has no usable A/AAAA address"
        _cache_smtp(host, ports, result)
        return result
    for index, port in enumerate(ports[:MAX_SMTP_ATTEMPTS_PER_HOST]):
        if index and delay > 0:
            _sleep_with_jitter(delay)
        attempt = {"port": port, "reachable": False}
        try:
            if port == 465:
                smtp = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ssl.create_default_context())
            else:
                smtp = smtplib.SMTP(host, port, timeout=timeout)
            smtp.set_debuglevel(0)
            banner = None
            tls_active = port == 465
            try:
                banner = smtp.sock.getpeername() if getattr(smtp, 'sock', None) else None
            except Exception:
                banner = None
            try:
                code, response = smtp.ehlo()
                attempt.update({
                    "code": code,
                    "ehlo_response": str(response),
                    "supports_starttls": smtp.has_extn('starttls'),
                    "tls_active": tls_active,
                    "banner": str(banner),
                    "connected": True,
                    "reachable": code < 400,
                })
                if code >= 500:
                    attempt["policy"] = "permanent_refusal"
                    attempt["classification"] = "policy_or_blocked"
                elif code >= 400:
                    attempt["policy"] = "temporary_refusal"
                    attempt["classification"] = "policy_or_blocked"
                else:
                    attempt["policy"] = "accepted_ehlo"
            except Exception as e:
                attempt.update({
                    "error": str(e),
                    "reachable": False,
                    "supports_starttls": False,
                    "tls_active": tls_active,
                    "ehlo_response": "",
                    "banner": str(banner),
                })
                attempt["classification"] = _classify_smtp_failure(str(e))
            finally:
                try:
                    smtp.quit()
                except Exception:
                    try:
                        smtp.close()
                    except Exception:
                        pass
            result["reachable"] = result["reachable"] or attempt["reachable"]
            result.setdefault("attempts", []).append(attempt)
            if attempt.get("classification") == "policy_or_blocked":
                _remember_policy_cooldown(host)
            if attempt["reachable"]:
                result["classification"] = "reachable"
                _cache_smtp(host, ports, result)
                return result
        except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, socket.timeout, socket.error, OSError) as e:
            attempt.update({"error": str(e), "reachable": False})
            attempt["classification"] = _classify_smtp_failure(str(e))
            result.setdefault("attempts", []).append(attempt)
            if attempt.get("classification") == "policy_or_blocked":
                _remember_policy_cooldown(host)
            continue
        except Exception as e:
            attempt.update({"error": str(e), "reachable": False})
            attempt["classification"] = _classify_smtp_failure(str(e))
            result.setdefault("attempts", []).append(attempt)
            if attempt.get("classification") == "policy_or_blocked":
                _remember_policy_cooldown(host)
            continue
    if result.get("attempts"):
        last = result["attempts"][-1]
        result["error"] = last.get("error") or "No reachable SMTP port responded within timeout"
        result["classification"] = last.get("classification", result["classification"])
    else:
        result["error"] = "No reachable SMTP port responded within timeout"
    _cache_smtp(host, ports, result)
    return result


def is_disposable(domain):
    return domain.lower() in DISPOSABLE_DOMAINS


def probe_domain(
    domain,
    probe_mx_connect=True,
    mx_probe_limit=3,
    smtp_ports=SMTP_PORTS,
    smtp_timeout=DEFAULT_TIMEOUT,
    smtp_delay=DEFAULT_CONNECT_DELAY,
):
    normalized = normalize_domain(domain)
    out = {"domain": normalized or domain, "timestamp": time.time(), "status": "unknown"}

    validation = domain_summary(domain)
    out["valid_domain"] = validation["valid"]
    out["normalized_domain"] = validation["normalized"]

    if not validation["valid"]:
        out["status"] = "invalid"
        out["notes"] = ["Input is not a valid public domain name."]
        return out

    # Basic heuristics
    out["disposable_hint"] = is_disposable(normalized)
    out["address_records"] = lookup_a_aaaa(normalized)

    # MX
    mx = lookup_mx(normalized)
    out["mx_lookup"] = mx
    out["dns_health"] = {
        "has_address": bool(
            out["address_records"].get("A") or out["address_records"].get("AAAA")
        ),
        "has_mx_answer": bool(isinstance(mx, dict) and mx.get("mx")),
        "resolver_error": (
            out["address_records"].get("error")
            or (mx.get("error") if isinstance(mx, dict) else "")
        ),
    }

    # SPF
    out["spf"] = check_spf(normalized)

    # DMARC
    out["dmarc"] = check_dmarc(normalized)
    out["mail_security"] = check_policy_records(normalized)

    mx_hosts = []
    if isinstance(mx, dict) and "mx" in mx:
        mx_hosts = [h for _, h in mx["mx"]]
        if mx.get("implicit_mx"):
            mx_hosts = [normalized]
    elif isinstance(mx, dict) and "error" in mx:
        out.setdefault("notes", []).append("MX lookup error: %s" % mx["error"])

    out["mx_probes"] = []
    if probe_mx_connect and mx_hosts:
        count = 0
        seen_hosts = set()
        for host in mx_hosts:
            if count >= mx_probe_limit:
                break
            host = normalize_domain(host)
            if not host or host in seen_hosts:
                continue
            seen_hosts.add(host)
            p = safe_smtp_probe(host, ports=smtp_ports, timeout=smtp_timeout, delay=smtp_delay)
            out["mx_probes"].append(p)
            count += 1

    has_a_or_aaaa = bool(out["address_records"].get("A") or out["address_records"].get("AAAA"))
    has_mx = bool(isinstance(mx, dict) and (
        (mx.get("mx") and not mx.get("null_mx")) or mx.get("implicit_mx")
    ))
    if isinstance(mx, dict) and mx.get("mx"):
        out["mail_provider"] = identify_mail_provider([host for _, host in mx["mx"]])
    smtp_reachable = any(p.get("reachable") for p in out["mx_probes"])
    smtp_connected = any(p.get("connected") for p in out["mx_probes"])
    smtp_attempted = bool(out["mx_probes"])
    smtp_network_failure = smtp_attempted and all(
        not p.get("reachable")
        and p.get("classification") in ("temporary_or_network_failure", "dns_failure")
        for p in out["mx_probes"]
    )
    # More conservative classification: a timeout/refusal is never treated as a
    # definitive "inactive" signal when the domain has valid MX records.
    anti_abuse_block = any(
        p.get("classification") == "policy_or_blocked" for p in out["mx_probes"]
    )
    out["signals"] = {
        "dns_resolves": has_a_or_aaaa,
        "mail_exchange_present": has_mx,
        "smtp_tested": smtp_attempted,
        "smtp_reachable": smtp_reachable,
        "smtp_connected": smtp_connected,
        "smtp_blocked_or_policy": anti_abuse_block,
    }
    out["health_score"] = calculate_domain_health(out)

    if isinstance(mx, dict) and mx.get("null_mx"):
        out["status"] = "inactive"
        out["notes"] = out.get("notes", []) + [
            "The domain publishes a null MX and explicitly does not accept email."
        ]
    elif not has_mx and isinstance(mx, dict) and mx.get("error_type") == "nxdomain":
        out["status"] = "inactive"
        out["notes"] = out.get("notes", []) + ["The domain does not exist (NXDOMAIN)."]
    elif not has_mx:
        out["status"] = "unknown"
        out["notes"] = out.get("notes", []) + [
            "MX information was unavailable; DNS failure is not proof that the domain is inactive."
        ]
    elif out["disposable_hint"]:
        out["status"] = "suspicious"
        out["notes"] = out.get("notes", []) + ["Domain resembles a disposable mail provider."]
    elif has_mx and not probe_mx_connect:
        out["status"] = "active"
        out["notes"] = out.get("notes", []) + [
            "MX records are present; SMTP connectivity was not tested."
        ]
    elif smtp_reachable:
        out["status"] = "active"
        out["notes"] = out.get("notes", []) + ["MX records are present and at least one SMTP endpoint responded."]
        out["confidence"] = "high"
    elif anti_abuse_block:
        out["status"] = "unknown"
        out["notes"] = out.get("notes", []) + [
            "MX records exist, but the SMTP server appears to be blocking or rate-limiting the probe. "
            "This is treated as an uncertain result instead of a definitive inactive domain."
        ]
        out["confidence"] = "low"
    elif smtp_network_failure:
        out["status"] = "unknown"
        out["notes"] = out.get("notes", []) + [
            "MX records exist, but SMTP connectivity could not be established. "
            "This may be caused by a firewall, provider policy, or a temporary network failure."
        ]
        out["confidence"] = "low"
    elif has_a_or_aaaa:
        out["status"] = "suspicious"
        out["notes"] = out.get("notes", []) + ["Domain resolves but no SMTP listener responded within the probe timeout."]
        out["confidence"] = "medium"
    else:
        out["status"] = "inactive"
        out["notes"] = out.get("notes", []) + ["Domain has no usable A/AAAA records or SMTP response."]
        out["confidence"] = "medium"

    out.setdefault("confidence", "medium")
    return out


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Safe SMTP + DNS/MX/SPF/DMARC probe")
    p.add_argument("domain", help="Domain to probe, e.g. example.com")
    p.add_argument("--no-connect", dest="no_connect", action="store_true", help="Do not connect to MX hosts (only DNS/TXT lookups)")
    p.add_argument("--limit", type=int, default=3, help="Max number of MX hosts to probe (default 3)")
    p.add_argument("--delay", type=float, default=DEFAULT_CONNECT_DELAY,
                   help="Seconds between SMTP port attempts (default 0.5)")
    p.add_argument("--json", dest="raw_json", action="store_true", help="Output compact JSON on one line")
    args = p.parse_args()

    domain = args.domain.strip()
    result = probe_domain(
        domain,
        probe_mx_connect=not args.no_connect,
        mx_probe_limit=max(0, args.limit),
        smtp_delay=max(0.0, args.delay),
    )
    if args.raw_json:
        print(json.dumps(result, separators=(',', ':')))
    else:
        print(json.dumps(result, indent=2))
