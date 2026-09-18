#!/usr/bin/env python3
"""Offline defensive training helpers using synthetic, non-recoverable fixtures."""
import argparse
import hashlib
import json
import secrets

from hash_audit import audit_records


def make_synthetic_records(count=5):
    """Create fake SHA-256 fixtures for learning hash-audit reporting."""
    if count < 1 or count > 100:
        raise ValueError("count must be between 1 and 100")
    records = []
    for index in range(count):
        fixture = "synthetic-fixture-" + secrets.token_hex(16)
        digest = hashlib.sha256(fixture.encode("utf-8")).hexdigest()
        records.append(("lab-user-%03d" % (index + 1), digest))
    return records


def build_lab_report(count=5):
    records = make_synthetic_records(count)
    return {
        "mode": "offline-synthetic",
        "warning": "Training fixtures only; no password recovery or login test was performed.",
        "records": audit_records(records),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic hashes for defensive audit training"
    )
    parser.add_argument("--count", type=int, default=5, choices=range(1, 101))
    args = parser.parse_args()
    print(json.dumps(build_lab_report(args.count), indent=2))


if __name__ == "__main__":
    main()
