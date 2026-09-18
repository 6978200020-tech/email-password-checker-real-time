#!/usr/bin/env python3
"""Defensive password-hash metadata audit; never cracks or recovers passwords."""
import argparse
import csv
import hashlib
import json
import re
from collections import Counter

HASH_PATTERNS = (
    ("bcrypt", re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"), True, True),
    ("argon2id", re.compile(r"^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[^$]+\$[^$]+$"), True, True),
    ("scrypt", re.compile(r"^\$7\$[^$]+(\$[^$]+){2,}$"), True, True),
    ("pbkdf2", re.compile(r"^\$pbkdf2-[^$]+\$[^$]+\$[^$]+\$[^$]+$"), True, True),
    ("md5", re.compile(r"^[a-fA-F0-9]{32}$"), False, False),
    ("sha1", re.compile(r"^[a-fA-F0-9]{40}$"), False, False),
    ("sha256", re.compile(r"^[a-fA-F0-9]{64}$"), False, False),
)


def classify_hash(value):
    """Return metadata only; the original hash is never returned."""
    text = str(value or "").strip()
    if not text:
        return {"algorithm": "missing", "salted": False, "risk": "critical"}
    for algorithm, pattern, salted, adaptive in HASH_PATTERNS:
        if pattern.fullmatch(text):
            return {
                "algorithm": algorithm,
                "salted": salted,
                "adaptive": adaptive,
                "risk": "low" if adaptive else "high",
            }
    return {"algorithm": "unknown", "salted": None, "adaptive": None, "risk": "review"}


def audit_records(records):
    """Audit (user, hash) records without attempting password recovery."""
    metadata = []
    fingerprints = Counter()
    for user, value in records:
        info = classify_hash(value)
        fingerprint = hashlib.sha256(str(value).strip().encode("utf-8")).hexdigest()
        fingerprints[fingerprint] += 1
        metadata.append({
            "user": str(user).strip()[:254],
            **info,
            "hash_fingerprint": fingerprint[:16],
        })
    # Keep full fingerprints private and expose only a short report identifier.
    for row, (_, value) in zip(metadata, records):
        fingerprint = hashlib.sha256(str(value).strip().encode("utf-8")).hexdigest()
        row["reused_hash"] = fingerprints[fingerprint] > 1
    return metadata


def main():
    parser = argparse.ArgumentParser(description="Audit hash formats without cracking passwords")
    parser.add_argument("file", help="CSV/TXT with user,hash or email:hash records")
    parser.add_argument("--json", action="store_true", help="Print JSON report")
    args = parser.parse_args()
    records = []
    with open(args.file, newline="", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            if "," in raw:
                user, value = next(csv.reader([raw]))
            elif ":" in raw and not raw.startswith("$"):
                user, value = raw.split(":", 1)
            else:
                user, value = "row-%d" % (len(records) + 1), raw
            records.append((user, value))
    report = audit_records(records)
    if args.json:
        print(json.dumps(report, ensure_ascii=True))
    else:
        for row in report:
            print("%s | %s | %s | risk=%s | reused=%s" % (
                row["user"], row["algorithm"], "salted=%s" % row["salted"],
                row["risk"], row["reused_hash"],
            ))


if __name__ == "__main__":
    main()
