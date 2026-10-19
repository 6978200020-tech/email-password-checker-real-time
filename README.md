# email-password-checker-real-time

This repo includes a privacy-safe local email quality auditor and a batch
email-list DNS/MX checker. It performs real DNS/MX/SPF/DMARC lookups and, when
explicitly enabled for the legacy domain audit, conservative SMTP reachability
checks.

It does **not** test email/password credentials against Google, Microsoft, or any
other provider. Passwords stay in the browser and are never sent to a server.
It does not log in, enumerate mailboxes, or determine whether a specific user
account exists. An `active` domain result only describes DNS/MX/SMTP
infrastructure.

## সবচেয়ে সহজে চালানোর নিয়ম (Windows)

1. এই repository folder খুলুন।
2. `run_auditor.bat`-এ double-click করুন।
3. প্রথমবার DNS package install হতে কয়েক সেকেন্ড লাগতে পারে।
4. Browser নিজে খুলবে; না খুললে `http://127.0.0.1:8765` খুলুন।
5. সাধারণ DNS/MX report-এর জন্য **Email list** box-এ শুধু এক লাইনে একটি email
   দিন:

   ```text
   user@gmail.com
   admin@your-company.com
   person@example.org
   ```

   **Check Email List DNS/MX** চাপলে syntax, DNS, MX host, provider,
   SPF/DMARC এবং domain health/status রিপোর্ট হবে। CSV download-ও করা যাবে।
   সর্বোচ্চ 100টি address একবারে নেওয়া হয়।
6. পুরনো local password-hygiene audit দরকার হলে নিচের legacy input-এ
   `email:password` format ব্যবহার করতে পারেন। উদাহরণ:

   ```text
   test@gmail.com:ExamplePassword!123
   user@example.com:AnotherPassword!456
   ```

7. শুধু local password/format check চাইলে **Real DNS/MX checks** unchecked রাখুন।
   `.txt` বা `.csv` list চাইলে **Load a local list** ব্যবহার করতে পারেন; file
   browser-এর ভেতরেই পড়া হয়, server-এ upload হয় না, এবং 5 MB/5,000-line limit
   আছে।
   Domain সত্যিই mail server-এ active কি না দেখতে সেটি checked করে **Run Audit &
   Build CSV** চাপুন।
8. কাজ শেষ হলে terminal window-তে `Ctrl+C` চাপুন।

Password কোনো server-এ login করার জন্য ব্যবহার করা হয় না; report-এ password
শুধু masked অবস্থায় থাকে।

## Usage

```bash
python smtp_probe.py gmail.com
python smtp_probe.py outlook.com --json
python smtp_probe.py --no-connect example.com
python server.py
```

Manual start করতে আগে dependency install করুন:

```bash
python -m pip install -r requirements.txt
python server.py
```

For the browser UI, start `python server.py` and open
`http://127.0.0.1:8765`. The UI's **Real DNS/MX checks** option calls the local
API once per unique domain and records the returned evidence in the CSV.
The API allows at most 12 probes per client per 60 seconds, applies a 10-second
cooldown per domain, and runs no more than two probes concurrently. Exceeding
these limits returns HTTP 429 instead of retrying aggressively.
DNS policy lookups run in parallel with bounded workers so personal domains do
not wait through each selector serially; the response includes probe duration.

If `dnspython` is not installed, install the optional DNS dependency:

```bash
python -m pip install dnspython
```

The probe checks:
- domain normalization and validation
- DNS A/AAAA records
- MX records, including RFC 5321 implicit-MX behavior when a domain has no MX answer
- SPF and DMARC TXT lookups
- common DKIM selector discovery, MTA-STS/TLS-RPT TXT checks, and a bounded MTA-STS policy-file validation
- a single short SMTP banner/EHLO check on port 25 for each selected MX host
- MX-host A/AAAA sanity checks before opening an SMTP socket
- a short in-process DNS and SMTP-result cache to avoid repeating identical lookups
- a 15-minute per-host policy cooldown after an explicit 4xx/5xx anti-abuse refusal
- explicit signals and confidence so DNS resolution, MX presence, SMTP reachability,
  and temporary network/provider failures are not confused with one another

It never attempts authentication, recipient validation, or message delivery.

For an address-level public report, use the local endpoint
`/api/email-report?email=user%40example.com`. It returns syntax status and the
same public domain/DNS evidence as the domain audit, including common provider
classification such as Google Workspace. `account_verification` and
`credential_check` are always `not_performed`; no endpoint can prove that a
specific Google user or password is real. Uncached address reports share the same
rate-limit and domain cooldown protections as normal probes.
Repeated requests for the same normalized address or domain reuse a
short-lived public-domain report, which avoids unnecessary repeat DNS traffic
and local rate-limit responses without bypassing provider controls. Reports
also include the local-part type (individual/unknown or role/shared), a possible
common domain typo, a public deliverability signal, published
SPF/DMARC/DKIM/MTA-STS security signals, and a separate Google
consumer/Workspace scope. Gmail consumer addresses are distinguished from
Google Workspace custom domains in the provider label. For
`gmail.com`/`googlemail.com`, the report may show a canonical alias hint based
on Gmail's documented dot/plus conventions. This is only a delivery-equivalence
hint; it does not verify that the user exists. The report never uses recipient
commands, login attempts, retries, proxy rotation, or other block-evasion
techniques. Provider rate limits and refusals remain valid results.
The browser UI exposes the same feature through **Public Email Report**; it
uses only the first input line's email portion and never sends the
`email:password` value to this endpoint.

For a batch email-only report, send a JSON POST to
`/api/email-list-report`:

```json
{"emails":["user@gmail.com","admin@example.org"]}
```

The endpoint accepts at most 100 addresses per request, rejects
credential-shaped lines containing `:`, deduplicates domain lookups, and
reuses cached public-domain evidence. It checks public DNS and mail-policy
signals, but never performs SMTP recipient checks, login, password checks,
mailbox enumeration, or delivery.

## Operational limits

Remote providers may rate-limit or refuse SMTP probes; no client can guarantee
that a probe will never be blocked. To reduce unnecessary traffic, the tool
resolves and deduplicates MX hosts before connecting, uses one EHLO connection
per unique MX host, port 25 only, bounded timeouts, short DNS/SMTP caches,
per-domain cooldowns, a per-host cooldown after policy refusals, and server-side
concurrency/rate limits. A timeout or refusal is reported as an uncertain
connectivity result rather than falsely declaring the domain inactive. A
successful TCP connection is reported separately from an accepted EHLO, because
some providers intentionally accept connections but reject automated probes.
It deliberately does not use authentication, `VRFY`, `RCPT TO`, aggressive
retries, proxy rotation, or other bypass techniques. Use it only on
infrastructure you are authorized to assess, and increase `--delay` when
checking multiple domains.

The result is a deliverability signal, not proof that a particular mailbox
exists. A domain may publish a null MX, have resolver failures, or accept a
connection while rejecting mail for policy reasons.

## Optional Ubuntu/Debian VPS deployment

The app can run on a VPS as a systemd service. Copy the project to the VPS and
run `bash deploy_vps.sh` from the project directory. The service binds to
`127.0.0.1:8765` and does not open a browser on the server. Put an
authenticated reverse proxy (HTTPS) in front of it if it must be accessed
remotely; do not expose the development port directly to the internet.

On Windows, `run_vps.bat` can restart an already-deployed service over SSH:

```bat
set VPS_HOST=203.0.113.10
set VPS_USER=ubuntu
set VPS_APP_DIR=/opt/email-domain-auditor
run_vps.bat
```

Use SSH keys or an SSH agent; never put a password, private key, or API token in
the batch file. The VPS runs the same privacy-safe domain checks and never
performs provider login or credential testing.

## Defensive hash audit

For an authorized user database, `hash_audit.py` reports hash format, whether
the format appears salted/adaptive, weak legacy algorithms, unknown values, and
duplicate hash reuse. It never downloads wordlists, invokes Hashcat, cracks
hashes, or outputs recovered passwords.

```bash
python hash_audit.py authorized_hashes.txt --json
```

Input may be `user,hash`, `user:hash`, or one hash per line. The report contains
only a short hash fingerprint and metadata; keep the source file protected and
delete temporary copies after the audit.

## GitHub Actions (free-plan automation)

GitHub Actions is not a monthly VPS: runners are temporary, have plan quotas,
and stop after each workflow. It cannot provide a full-power 24/7 server. For
authorized domain monitoring, copy `domains.example.txt` to `domains.txt`, add
only domains you own or have written permission to assess, commit that file,
then run **Actions -> Authorized domain audit -> Run workflow**. It also runs
daily on the included schedule and uploads a seven-day JSON artifact.
The workflow also runs when the authorized domain list or audit code changes,
and performs a bounded pull-request validation. Manual runs accept a repository
domain-file selection and worker count of 1 or 2.
After the initial repository setup, no button click is required for daily
monitoring. GitHub may delay scheduled workflows, and Actions quotas still
apply.

### Quick start from another computer

This repository is already public. The supported browser-based quick start is
GitHub Codespaces:

<https://github.com/codespaces/new?hide_repo_select=true&ref=main&repo=6978200020-tech%2Femail-password-checker-real-time>

Sign in to GitHub, create the Codespace, and wait for the forwarded
**Domain auditor** port to open. The dev container installs the dependency and
starts the local API automatically. Codespaces requires an eligible GitHub
account and available quota; it is not an anonymous public VPS, and startup
time depends on GitHub capacity. The forwarded URL is protected by GitHub
authentication and should not be shared publicly.

When the local browser page or workflow is stopped, it remains stopped rather
than consuming resources. Use the UI **Run Now (Real Domain)** button for an
on-demand local run, or GitHub Actions **Run workflow** for an on-demand remote
run. A browser button cannot start a GitHub runner without authentication, so
the two controls intentionally remain separate.

The workflow is deliberately bounded to two workers and one MX host per domain.
It does not accept passwords, run login checks, download wordlists, rotate
proxies, or bypass provider controls.

## Offline defensive learning lab

To learn the reporting workflow without using real users or passwords, generate
synthetic fixtures locally:

```bash
python defensive_lab.py --count 5
```

This creates random SHA-256 training values and audits only their metadata. It
does not recover passwords, invoke cracking tools, download wordlists, or make
network/login requests.
