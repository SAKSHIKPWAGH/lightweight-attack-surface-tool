"""Risk engine: rule catalogue -> de-duplicated findings -> scores."""
import re

from modules.port_scan import ALL_PORTS, TLS_PORTS

WEIGHT = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Info": 0}
SEVERITIES = list(WEIGHT)

# rule id -> (title, severity, category, recommendation, references)
RULES = {
    "HDR-HSTS": ("Missing HSTS header", "Medium", "Web security headers", "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.", "CWE-319 | OWASP A02:2021"),
    "HDR-CSP": ("Missing Content-Security-Policy header", "Medium", "Web security headers", "Define a Content-Security-Policy to limit script sources and reduce XSS impact.", "CWE-79 | OWASP A05:2021"),
    "HDR-XFO": ("Missing clickjacking protection", "Low", "Web security headers", "Send X-Frame-Options or a CSP frame-ancestors directive.", "CWE-1021"),
    "HDR-XCTO": ("Missing X-Content-Type-Options header", "Low", "Web security headers", "Send 'X-Content-Type-Options: nosniff'.", "CWE-693"),
    "HDR-REF": ("Missing Referrer-Policy header", "Low", "Web security headers", "Send a Referrer-Policy such as 'strict-origin-when-cross-origin'.", "CWE-200"),
    "INFO-DISC": ("Software version disclosed in HTTP headers", "Low", "Information disclosure", "Hide version details from Server / X-Powered-By; exact versions help attackers match known CVEs.", "CWE-200"),
    "HTTP-NOREDIR": ("HTTP does not redirect to HTTPS", "Medium", "Transport security", "Redirect all HTTP traffic to HTTPS with a 301.", "CWE-319"),
    "HTTP-NOHTTPS": ("Web service offered only over HTTP", "Medium", "Transport security", "Enable TLS for the service.", "CWE-319 | OWASP A02:2021"),
    "COOKIE-SECURE": ("Cookie without Secure flag", "Medium", "Session management", "Set the Secure attribute on cookies served over HTTPS.", "CWE-614"),
    "COOKIE-HTTPONLY": ("Cookie without HttpOnly flag", "Medium", "Session management", "Set HttpOnly so scripts cannot read session cookies.", "CWE-1004"),
    "COOKIE-SAMESITE": ("Cookie without SameSite attribute", "Low", "Session management", "Set SameSite=Lax or Strict to reduce CSRF risk.", "CWE-1275"),
    "CORS-WILDCARD": ("CORS allows any origin (*)", "Medium", "Access control", "Restrict Access-Control-Allow-Origin to trusted origins.", "CWE-942"),
    "CORS-REFLECT": ("CORS reflects arbitrary Origin", "High", "Access control", "Validate the Origin against an allow-list; never reflect it blindly (especially with credentials).", "CWE-942 | OWASP A05:2021"),
    "PATH-GIT": ("Exposed .git repository", "Critical", "Sensitive exposure", "Block /.git at the web server and remove it from the web root; rotate any secrets it contained.", "CWE-538 | OWASP A05:2021"),
    "PATH-ENV": ("Exposed .env configuration file", "Critical", "Sensitive exposure", "Remove the file from the web root and rotate every credential it contains.", "CWE-538 | OWASP A05:2021"),
    "PATH-PHPINFO": ("Exposed phpinfo() page", "Medium", "Sensitive exposure", "Delete phpinfo pages from production servers.", "CWE-200"),
    "PATH-STATUS": ("Exposed Apache server-status page", "Medium", "Sensitive exposure", "Restrict /server-status to localhost or admin IPs.", "CWE-200"),
    "PATH-DSSTORE": ("Exposed .DS_Store file", "Low", "Sensitive exposure", "Remove .DS_Store files; they leak directory listings.", "CWE-538"),
    "INFO-ROBOTS": ("robots.txt lists disallowed paths", "Info", "Reconnaissance", "robots.txt is public; protect sensitive paths with authentication rather than hiding them.", "CWE-200"),
    "INFO-NOSECTXT": ("No security.txt published", "Info", "Process", "Publish /.well-known/security.txt so researchers know how to report issues.", "RFC 9116"),
    "TLS-UNTRUSTED": ("Untrusted or invalid TLS certificate", "High", "TLS", "Install a valid certificate from a trusted CA that covers the hostname.", "CWE-295"),
    "TLS-HOSTNAME": ("TLS certificate does not match the hostname", "High", "TLS", "Issue a certificate whose SAN covers this hostname.", "CWE-297"),
    "TLS-EXPIRED": ("TLS certificate has expired", "High", "TLS", "Renew the certificate immediately and automate renewal.", "CWE-298"),
    "TLS-EXPIRING": ("TLS certificate expires within 30 days", "Medium", "TLS", "Renew the certificate and automate renewal.", "CWE-298"),
    "TLS-LEGACY": ("Legacy TLS protocol (1.0 / 1.1) accepted", "High", "TLS", "Disable TLS 1.0 and 1.1; allow TLS 1.2 and 1.3 only.", "CWE-326 | PCI DSS 4.0"),
    "TLS-NO13": ("TLS 1.3 not supported", "Info", "TLS", "Enable TLS 1.3 for better security and performance.", "NIST SP 800-52r2"),
    "TLS-WEAKCIPHER": ("Weak cipher negotiated", "High", "TLS", "Disable RC4, 3DES, export and NULL cipher suites.", "CWE-327"),
    "EMAIL-SPF-MISSING": ("No SPF record", "Medium", "Email security", "Publish an SPF record listing authorised mail senders.", "RFC 7208"),
    "EMAIL-SPF-WEAK": ("Weak SPF policy", "Medium", "Email security", "End the SPF record with '-all' (or at least '~all'); never '+all'.", "RFC 7208"),
    "EMAIL-DMARC-MISSING": ("No DMARC record", "Medium", "Email security", "Publish a DMARC record at _dmarc.<domain>, starting with p=none and moving to quarantine/reject.", "RFC 7489"),
    "EMAIL-DMARC-NONE": ("DMARC policy is p=none (monitor only)", "Low", "Email security", "Move to p=quarantine or p=reject once reports look clean.", "RFC 7489"),
    "DNS-DANGLING": ("Dangling CNAME (possible subdomain takeover)", "High", "DNS", "Remove the stale DNS record or re-claim the external service it points to.", "OWASP WSTG-CONF-10"),
    "ASSET-SENSITIVE": ("Non-production or admin-style host is publicly resolvable", "Low", "Attack surface", "Put dev/admin/internal hosts behind VPN or SSO, or remove their public DNS.", "CWE-200"),
    "ASSET-SUBDOMAINS": ("Public subdomains discovered", "Info", "Attack surface", "Review the asset inventory and decommission hosts that are no longer needed.", "CIS Control 1"),
}

# port -> (severity, why it matters)
RISKY_PORTS = {
    21: ("Medium", "FTP sends credentials in clear text."),
    22: ("Low", "SSH is exposed; use key-only auth and rate limiting."),
    23: ("High", "Telnet is unencrypted; replace it with SSH."),
    111: ("Medium", "RPCbind exposes service enumeration."),
    139: ("High", "NetBIOS exposed to the internet is a common attack target."),
    389: ("Medium", "LDAP exposed publicly can leak directory data."),
    445: ("High", "SMB exposed to the internet is a common attack target."),
    873: ("Medium", "rsync may allow unauthenticated file access."),
    1433: ("High", "Database service exposed publicly."),
    1521: ("High", "Database service exposed publicly."),
    2049: ("High", "NFS exposed publicly can leak file systems."),
    2375: ("Critical", "Unauthenticated Docker API allows full host takeover."),
    3306: ("High", "Database service exposed publicly."),
    3389: ("High", "RDP exposed to the internet is heavily targeted."),
    5432: ("High", "Database service exposed publicly."),
    5601: ("High", "Kibana dashboards are often unauthenticated."),
    5900: ("High", "VNC exposed to the internet is heavily targeted."),
    5985: ("Medium", "WinRM remote management exposed publicly."),
    6379: ("High", "Redis is often unauthenticated by default."),
    9200: ("High", "Elasticsearch exposed publicly may leak data."),
    10000: ("Medium", "Webmin administration panel exposed."),
    11211: ("High", "Memcached exposed publicly can leak data."),
    15672: ("Medium", "RabbitMQ management console exposed."),
    27017: ("High", "MongoDB exposed publicly."),
}
for _p, (_sev, _why) in RISKY_PORTS.items():
    RULES["EXPOSED-%d" % _p] = ("Exposed %s (port %d)" % (ALL_PORTS.get(_p, "service"), _p), _sev,
                                "Network exposure", _why + " Restrict with a firewall/VPN or disable if unnecessary.",
                                "CWE-284 | CIS Control 4")

SENSITIVE_LABELS = {"dev", "develop", "test", "testing", "qa", "uat", "staging", "stage", "beta", "alpha", "demo",
                    "sandbox", "admin", "administrator", "jenkins", "git", "gitlab", "svn", "internal", "intranet",
                    "db", "database", "sql", "mysql", "postgres", "redis", "mongo", "elastic", "kibana", "grafana",
                    "prometheus", "backup", "old", "legacy", "cpanel", "whm", "jira", "confluence", "docker", "k8s",
                    "kubernetes", "registry", "phpmyadmin"}
LEGACY_WEAK = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5")


class Collector:
    """Merges repeated observations: one finding per (rule, host), ports/evidence combined."""

    def __init__(self):
        self.items = {}

    def add(self, rule, host, evidence="", ports=None, severity=None):
        title, sev, cat, rec, refs = RULES[rule]
        f = self.items.setdefault((rule, host), {"id": rule, "host": host, "title": title,
                                                  "severity": severity or sev, "category": cat,
                                                  "evidence": [], "recommendation": rec, "refs": refs, "ports": []})
        if evidence and evidence not in f["evidence"]:
            f["evidence"].append(evidence)
        for p in ports or []:
            if p not in f["ports"]:
                f["ports"].append(p)
        if severity and WEIGHT[severity] > WEIGHT[f["severity"]]:
            f["severity"] = severity

    def result(self):
        out = []
        for f in self.items.values():
            f["evidence"] = "; ".join(f["evidence"]) or "-"
            f["ports"].sort()
            out.append(f)
        return sorted(out, key=lambda x: (-WEIGHT[x["severity"]], x["host"], x["id"]))


def analyze(res):
    c, target = Collector(), res["target"]
    dns = res.get("dns", {})
    for host, d in res["hosts"].items():
        open_ports = {p["port"] for p in d["ports"]}
        has_https = bool(open_ports & TLS_PORTS)
        for p in d["ports"]:
            if p["port"] in RISKY_PORTS:
                c.add("EXPOSED-%d" % p["port"], host, "%s reachable on %d" % (p["service"], p["port"]), [p["port"]])
        for h in d["http"]:
            if "error" in h:
                continue
            port, hdrs, final_tls = h["port"], h["headers"], h.get("final_tls", h["tls"])
            if h["status"] not in (301, 302, 303, 307, 308):
                if final_tls and "strict-transport-security" not in hdrs:
                    c.add("HDR-HSTS", host, "port %d" % port, [port])
                if "content-security-policy" not in hdrs:
                    c.add("HDR-CSP", host, "port %d" % port, [port])
                if "x-frame-options" not in hdrs and "frame-ancestors" not in hdrs.get("content-security-policy", ""):
                    c.add("HDR-XFO", host, "port %d" % port, [port])
                if "nosniff" not in hdrs.get("x-content-type-options", "").lower():
                    c.add("HDR-XCTO", host, "port %d" % port, [port])
                if "referrer-policy" not in hdrs:
                    c.add("HDR-REF", host, "port %d" % port, [port])
            for name in ("server", "x-powered-by"):
                if re.search(r"\d+\.\d+", hdrs.get(name, "")):
                    c.add("INFO-DISC", host, "%s: %s" % (name, hdrs[name]), [port])
            if not h["tls"]:
                if has_https and not h.get("redirect_to_https"):
                    c.add("HTTP-NOREDIR", host, "port %d returned %d" % (port, h["status"]), [port])
                elif not has_https:
                    c.add("HTTP-NOHTTPS", host, "port %d serves HTTP, no HTTPS port found" % port, [port])
            for ck in h.get("cookie_issues", []):
                if final_tls and not ck["secure"]:
                    c.add("COOKIE-SECURE", host, ck["name"], [port])
                if not ck["httponly"]:
                    c.add("COOKIE-HTTPONLY", host, ck["name"], [port])
                if not ck["samesite"]:
                    c.add("COOKIE-SAMESITE", host, ck["name"], [port])
            cors = h.get("cors") or {}
            if cors.get("reflected"):
                c.add("CORS-REFLECT", host, "Origin reflected" + (" with credentials" if cors["credentials"] else ""),
                      [port], "Critical" if cors["credentials"] else None)
            elif cors.get("acao") == "*":
                c.add("CORS-WILDCARD", host, "Access-Control-Allow-Origin: *", [port])
        web = d.get("web", {})
        for item in web.get("paths", {}).get("found", []):
            c.add(item["rule"], host, item["path"])
        if web.get("paths", {}).get("robots"):
            c.add("INFO-ROBOTS", host, "%d disallowed path(s)" % len(web["paths"]["robots"]))
        if host == target and any("error" not in h for h in d["http"]) and not web.get("paths", {}).get("security_txt"):
            c.add("INFO-NOSECTXT", host)

        t = d.get("tls")
        if t:
            tp = [t["port"]]
            err = t.get("verify_error", "")
            if err:
                c.add("TLS-HOSTNAME" if "hostname" in err.lower() else "TLS-UNTRUSTED", host, err, tp)
            dl = t.get("days_left")
            if dl is not None and dl < 0:
                c.add("TLS-EXPIRED", host, "expired %d days ago" % -dl, tp)
            elif dl is not None and dl < 30:
                c.add("TLS-EXPIRING", host, "%d days left" % dl, tp)
            protos = t.get("protocols") or {}
            legacy = [p for p in ("TLSv1", "TLSv1.1") if protos.get(p)]
            if legacy:
                c.add("TLS-LEGACY", host, ", ".join(legacy), tp)
            if protos.get("TLSv1.2") and not protos.get("TLSv1.3"):
                c.add("TLS-NO13", host, "", tp)
            if any(w in (t.get("cipher") or "").upper() for w in LEGACY_WEAK):
                c.add("TLS-WEAKCIPHER", host, t["cipher"], tp)

        if host != target and host.split(".")[0] in SENSITIVE_LABELS:
            c.add("ASSET-SENSITIVE", host, "public DNS name '%s'" % host.split(".")[0])

    em = dns.get("email", {})
    if em.get("checked"):
        if not em["spf"]:
            c.add("EMAIL-SPF-MISSING", target)
        elif em["spf_all"] == "+":
            c.add("EMAIL-SPF-WEAK", target, "+all allows anyone to send as this domain", severity="High")
        elif em["spf_all"] in ("?", None):
            c.add("EMAIL-SPF-WEAK", target, "no enforcing 'all' mechanism")
        if not em["dmarc"]:
            c.add("EMAIL-DMARC-MISSING", target)
        elif em["dmarc_policy"] == "none":
            c.add("EMAIL-DMARC-NONE", target)
    for dd in dns.get("dangling", []):
        c.add("DNS-DANGLING", dd["host"], "CNAME -> %s (does not resolve)" % dd["cname"])
    if len(res["hosts"]) > 1:
        c.add("ASSET-SUBDOMAINS", target, "%d subdomain(s) resolve publicly" % (len(res["hosts"]) - 1))
    return c.result()


def _rating(total):
    return ("Minimal" if total == 0 else "Low" if total < 15 else "Medium" if total < 40
            else "High" if total < 70 else "Critical")


def score(findings, res=None):
    total = min(100, sum(WEIGHT[f["severity"]] for f in findings))
    per_host = {}
    for f in findings:
        per_host[f["host"]] = per_host.get(f["host"], 0) + WEIGHT[f["severity"]]
    metrics = {}
    if res:
        hosts = res["hosts"]
        metrics = {"hosts": len(hosts),
                   "open_ports": sum(len(h["ports"]) for h in hosts.values()),
                   "web_services": sum(1 for h in hosts.values() for x in h["http"] if "error" not in x)}
    return {"score": total, "rating": _rating(total), "counts": {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES},
            "host_scores": {h: min(100, v) for h, v in per_host.items()}, "metrics": metrics}
