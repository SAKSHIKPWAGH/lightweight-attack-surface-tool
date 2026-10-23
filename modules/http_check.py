"""HTTP analysis: redirects, headers, cookies, CORS, technology hints and exposed files."""
import http.client
import re
import ssl
import random
import string
from urllib.parse import urljoin, urlparse

UA = {"User-Agent": "LightweightASA/2.0 (authorized security assessment)"}
REDIRECTS = (301, 302, 303, 307, 308)

# (path, rule id, validator on the first bytes of the body). A path only counts when the
# body matches a real signature, so soft-404 pages do not cause false positives.
SENSITIVE_PATHS = [
    ("/.git/HEAD", "PATH-GIT", lambda b: b.startswith(b"ref:")),
    ("/.env", "PATH-ENV", lambda b: b"=" in b and any(k in b.upper() for k in (b"DB_", b"SECRET", b"PASSWORD", b"TOKEN", b"APP_KEY"))),
    ("/phpinfo.php", "PATH-PHPINFO", lambda b: b"phpinfo()" in b or b"PHP Version" in b),
    ("/server-status", "PATH-STATUS", lambda b: b"Apache Server Status" in b),
    ("/.DS_Store", "PATH-DSSTORE", lambda b: b.startswith(b"\x00\x00\x00\x01Bud1")),
    ("/robots.txt", "INFO-ROBOTS", lambda b: b"user-agent" in b.lower()),
    ("/.well-known/security.txt", "SECURITYTXT", lambda b: b"contact:" in b.lower()),
]


def _request(host, port, tls, path, extra, timeout, read=4096):
    if tls:
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl._create_unverified_context())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    headers = dict(UA)
    headers.update(extra or {})
    try:
        conn.request("GET", path, headers=headers)
        r = conn.getresponse()
        body = r.read(read)
        hdrs, cookies = {}, []
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                cookies.append(v)
            else:
                hdrs[k.lower()] = v
        return {"status": r.status, "headers": hdrs, "cookies": cookies, "body": body}
    finally:
        conn.close()


def fetch(host, port, tls, scope, path="/", extra=None, timeout=6.0, follow=True):
    """GET with redirect following restricted to the scan scope (never leaves the target)."""
    chain, cur_tls, cur_port, first_https = [], tls, port, None
    for _ in range(6):
        resp = _request(host, cur_port, cur_tls, path, extra, timeout)
        loc = resp["headers"].get("location")
        if resp["status"] in REDIRECTS and loc:
            full = urljoin("%s://%s:%d%s" % ("https" if cur_tls else "http", host, cur_port, path), loc)
            u = urlparse(full)
            if first_https is None:
                first_https = (u.scheme == "https")
            chain.append({"status": resp["status"], "to": full})
            h2 = (u.hostname or "").lower()
            if follow and h2 and (h2 == host or h2 == scope or h2.endswith("." + scope)):
                host = h2
                cur_tls = u.scheme == "https"
                cur_port = u.port or (443 if cur_tls else 80)
                path = (u.path or "/") + ("?" + u.query if u.query else "")
                continue
        break
    resp.update({"port": port, "tls": tls, "final_tls": cur_tls, "redirects": chain,
                 "redirect_to_https": bool(first_https) and not tls})
    return resp


def analyze_cookies(cookies):
    out = []
    for c in cookies:
        parts = [p.strip() for p in c.split(";")]
        attrs = {p.split("=")[0].lower() for p in parts[1:]}
        out.append({"name": parts[0].split("=")[0], "secure": "secure" in attrs,
                    "httponly": "httponly" in attrs, "samesite": "samesite" in attrs})
    return out


def fingerprint(headers, body, cookies):
    tech = set()
    for k in ("server", "x-powered-by", "x-generator", "x-aspnet-version"):
        if k in headers:
            tech.add(headers[k].split(",")[0][:40])
    text = body.decode("utf-8", "ignore").lower()
    if "wp-content" in text:
        tech.add("WordPress")
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', text)
    if m:
        tech.add(m.group(1)[:40])
    names = {c.split("=")[0] for c in cookies}
    for n, label in (("PHPSESSID", "PHP"), ("JSESSIONID", "Java"), ("ASP.NET_SessionId", "ASP.NET"), ("laravel_session", "Laravel")):
        if n in names:
            tech.add(label)
    return sorted(tech)


def inspect(host, port, tls, scope, timeout=6.0):
    try:
        res = fetch(host, port, tls, scope, timeout=timeout)
        body = res.pop("body")
        res["tech"] = fingerprint(res["headers"], body, res["cookies"])
        m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        res["title"] = m.group(1).decode("utf-8", "ignore").strip()[:100] if m else ""
        res["cookie_issues"] = analyze_cookies(res.pop("cookies"))
        origin = "https://asa-origin-test.invalid"
        try:
            c = _request(host, port, tls, "/", {"Origin": origin}, timeout, read=256)["headers"]
            res["cors"] = {"acao": c.get("access-control-allow-origin"),
                           "credentials": c.get("access-control-allow-credentials", "").lower() == "true",
                           "reflected": c.get("access-control-allow-origin") == origin}
        except Exception:
            res["cors"] = {}
        return res
    except Exception as exc:
        return {"port": port, "tls": tls, "error": "%s: %s" % (exc.__class__.__name__, exc)}


def check_paths(host, port, tls, scope, timeout=6.0):
    """Fixed, small list of well-known sensitive files. No directory brute-forcing."""
    found, robots, sectxt = [], [], False
    for path, rule, valid in SENSITIVE_PATHS:
        try:
            r = fetch(host, port, tls, scope, path=path, timeout=timeout, follow=False)
        except Exception:
            continue
        if r["status"] != 200 or not valid(r["body"][:2048]):
            continue
        if rule == "SECURITYTXT":
            sectxt = True
        elif rule == "INFO-ROBOTS":
            robots = [l.split(":", 1)[1].strip() for l in r["body"].decode("utf-8", "ignore").splitlines()
                      if l.lower().startswith("disallow:") and l.split(":", 1)[1].strip()][:10]
            found.append({"rule": rule, "path": path})
        else:
            found.append({"rule": rule, "path": path})
    return {"found": found, "robots": robots, "security_txt": sectxt}
