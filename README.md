# Lightweight Attack Surface Analysis Tool (v2)

A Python, standard-library-only tool that maps the publicly exposed parts of a domain, finds likely
weaknesses, scores the risk, tracks changes between scans and produces an interactive report.

## Quick start (Windows PowerShell)
    py lab/demo_server.py                         # terminal 1: deliberately weak LOCAL demo target
    py main.py localhost --authorized --ports 8000   # terminal 2: scan it
Open `output\report.html` in a browser.

Other examples:
    py main.py scanme.nmap.org --authorized --profile quick
    py main.py yourdomain.com --authorized --profile extended
    py main.py yourdomain.com --authorized --no-passive --delay 0.5
    py -W ignore -m unittest discover -s tests -v   # run the test-suite

## What it does
| Stage | Module | Checks |
|---|---|---|
| Input | `modules/validator.py`, `core/safety.py` | validation, protected-domain refusal, audit log |
| DNS | `modules/dns_client.py`, `dns_enum.py` | own DNS client (A/AAAA/NS/MX/TXT), wordlist + Certificate-Transparency (crt.sh) subdomains, wildcard filtering |
| DNS security | `modules/dns_security.py` | SPF, DMARC, dangling CNAMEs (subdomain takeover) |
| Ports | `modules/port_scan.py` | threaded TCP scan, banner verification, canary check for local interception, 3 profiles |
| Web | `modules/http_check.py` | scoped redirects, security headers, cookie flags, CORS, tech hints, exposed `.git/.env/phpinfo...` |
| TLS | `modules/tls_check.py` | certificate trust/expiry/hostname, TLS 1.0-1.3 support, weak ciphers |
| Risk | `reports/risk.py` | 58 rules with CWE/OWASP refs, de-duplicated findings, 0-100 score, per-host score |
| History | `reports/history.py` | stores every scan, shows new/resolved findings, hosts and ports |
| Reports | `reports/report.py` | interactive HTML, JSON, CSV, Markdown |

## Options
`--profile quick|common|extended`, `--ports`, `--no-subdomains`, `--no-passive`, `--no-paths`,
`--no-tls-probe`, `--dns-server`, `--timeout`, `--http-timeout`, `--threads`, `--delay`, `--max-hosts`,
`--formats html,json,csv,md`, `--output`, `--no-history`.

## Ethics and legal
Assess only systems you own or have written permission to test. The tool refuses well-known third-party
platforms and government zones, logs every run to `output/audit.log`, never brute-forces directories,
never follows redirects outside the target's scope and sends only ordinary GET requests.
Results may contain false positives; verify manually.
