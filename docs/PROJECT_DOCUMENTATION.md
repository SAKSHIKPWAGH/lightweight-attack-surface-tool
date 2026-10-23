# Lightweight Attack Surface Analysis Tool - Project Documentation

## 1. Abstract
Organisations often do not know everything they expose to the internet. This project is a Python tool that
discovers the externally visible assets of a domain (subdomains, open ports, web services, TLS and DNS
configuration), analyses them for common weaknesses, converts the observations into prioritised findings
with a risk score and presents them in an interactive report. Repeated scans are compared so that
security improvements or regressions become visible. The tool uses only the Python standard library.

## 2. Problem statement
Manual reconnaissance is slow and inconsistent, while large commercial scanners are heavy and costly.
A lightweight, transparent, repeatable tool is needed to give small teams visibility of their attack surface.

## 3. Objectives
1. Automate discovery of public assets (DNS, subdomains, ports, web services).
2. Detect common misconfigurations (headers, cookies, CORS, TLS, exposed files, email spoofing protections).
3. Prioritise findings with a transparent scoring model mapped to CWE/OWASP.
4. Reduce false positives (banner verification, soft-404-safe file checks, wildcard-DNS filtering, de-duplication).
5. Track change over time and report in HTML/JSON/CSV/Markdown.
6. Enforce ethical use (authorization gate, protected targets, audit log).

## 4. Architecture
```
            +-----------+     +--------------+
 CLI/main --> safety    | --> | scanner.py   |  orchestration
            +-----------+     +------+-------+
                                     |
   +-------------+--------------+----+---------+---------------+
   | dns_client  | dns_enum     | port_scan    | http_check    | tls_check
   | dns_security| (wordlist+CT)| (+banners)   | (headers,CORS)| (certs,protocols)
   +------+------+------+-------+------+-------+-------+-------+---------+
          \_____________________________ results dict ________________/
                                     |
                             risk.py (rules -> findings -> score)
                                     |
                  history.py (diff) -+-> report.py (HTML/JSON/CSV/MD)
```

## 5. Methodology (pipeline)
1. **Validate & authorise** the target; refuse protected zones; write an audit entry.
2. **DNS** records via a hand-written UDP DNS client (packet building, name compression parsing).
3. **Subdomains**: wordlist brute force + passive Certificate-Transparency lookup; wildcard DNS detection.
4. **Port scan**: TCP connect on a profile of ports; mail/FTP/SSH ports are accepted only if the server sends
   a valid greeting; two random closed ports act as a *canary* to detect local interception (antivirus/proxy).
5. **Web analysis**: scope-limited redirect following, header and cookie checks, CORS reflection test,
   technology hints, fixed list of well-known sensitive files validated by content signature.
6. **TLS**: certificate trust/expiry, negotiated cipher, per-version protocol probing.
7. **DNS security**: SPF/DMARC parsing; dangling CNAME detection for subdomain-takeover risk.
8. **Risk engine** merges repeats (one finding per rule per host) and scores them.
9. **History** compares with the previous scan; **reports** are generated.

## 6. Risk model
Weights: Critical 10, High 7, Medium 4, Low 1, Info 0. Score = sum of weights of *unique* findings, capped
at 100. Rating: <15 Low, <40 Medium, <70 High, otherwise Critical (0 = Minimal). Each rule carries a
severity, category, recommendation and standard references (CWE, OWASP Top 10 2021, RFCs, CIS Controls).
Because findings are merged per host, a missing header on five ports counts once, not five times.

## 7. Testing
`tests/test_core.py` (12 tests): DNS packet building/parsing with compression, CT parsing, banner
verification (valid vs. silent server), cookie analysis, HTTP/CORS/sensitive-path checks against the local lab
server, TLS against a self-signed local server, risk de-duplication/scoring, history diff and a full
end-to-end scan that produces all report files. The `lab/demo_server.py` is a deliberately weak local target
so the tool can be demonstrated without touching anyone else's systems.

## 8. Limitations
- TCP-connect scanning only (no UDP, no SYN scan); small port lists keep it lightweight.
- No CVE matching: version disclosure is reported, but versions are not looked up in a vulnerability database.
- Passive discovery needs internet access to crt.sh; DNS checks need UDP 53 to the chosen resolver.
- Findings depend on the vantage point (firewalls, CDNs such as Cloudflare, antivirus proxies) and may be
  false positives - always verify manually. TLS legacy-protocol probing depends on the local OpenSSL build.
- It does not test authentication, business logic or exploit vulnerabilities by design.

## 9. Future scope
CVE matching through the NVD API, UDP service checks, screenshots of web services, cloud-bucket discovery,
scheduled scans with e-mail alerts, a Flask dashboard, and PDF export.

## 10. Ethics and legal
Scanning without permission can be illegal (for example under India's IT Act, 2000). The tool therefore requires
explicit authorization, refuses protected domains, logs usage, sends only ordinary requests, stays inside
the target's scope and does not exploit anything.

## 11. Viva questions and answers
**Q: What is an attack surface?** The sum of all points where an attacker can try to interact with a system:
subdomains, open ports, services, web endpoints, misconfigurations.
**Q: Why standard library only?** Portability, easy installation and to show the underlying protocols
(DNS packets, TLS handshakes, HTTP) instead of hiding them behind libraries.
**Q: How do you reduce false positives?** Banner verification, canary ports, content-signature checks for
sensitive files, wildcard-DNS filtering, de-duplication and scope-limited redirects.
**Q: Why was POP3/IMAP wrongly shown as open earlier?** The local antivirus mail proxy accepted the connection;
a real server must send `+OK` / `* OK`, which the proxy cannot, so these ports are now ignored.
**Q: What is subdomain takeover?** A DNS CNAME points to an external service that was deleted; an attacker
can register it and serve content on your subdomain. The tool flags CNAMEs whose target no longer resolves.
**Q: Why SPF/DMARC in an attack-surface tool?** Weak email authentication lets attackers spoof the domain, so it is part of what is exposed.
**Q: Why not follow redirects to other domains?** To stay inside the authorised scope.
**Q: Difference from Nmap?** Nmap is a far more capable port scanner; this tool combines DNS, web, TLS and
email posture into one scored, comparable report and is deliberately lightweight.
**Q: How is the score computed?** Sum of unique-finding weights, capped at 100 (section 6).
**Q: What are the limitations?** See section 8.
