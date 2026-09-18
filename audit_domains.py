#!/usr/bin/env python3
"""Run a bounded, privacy-safe domain audit for CI or local automation."""
import argparse
import json
import os
from concurrent.futures import ThreadPoolExecutor

import smtp_probe


def read_domains(path):
    values = []
    with open(path, encoding="utf-8", errors="replace") as handle:
        values.extend(line.strip() for line in handle)
    return sorted({smtp_probe.normalize_domain(value) for value in values if smtp_probe.normalize_domain(value)})


def main():
    parser = argparse.ArgumentParser(description="Audit authorized domains without credentials")
    parser.add_argument("--file", default="domains.txt")
    parser.add_argument("--output", default="domain-audit.json")
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    domains = read_domains(args.file)
    workers = max(1, min(args.workers, 2))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(
            lambda domain: smtp_probe.probe_domain(
                domain, probe_mx_connect=True, mx_probe_limit=1,
                smtp_timeout=4.0, smtp_delay=1.0
            ),
            domains,
        ))
    payload = {"count": len(results), "results": results}
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=True)
    print("Audited %d authorized domain(s); wrote %s" % (len(results), args.output))


if __name__ == "__main__":
    main()
