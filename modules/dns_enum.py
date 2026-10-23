"""Asset discovery: DNS records, wordlist brute force and passive CT-log discovery."""
import json
import os
import random
import socket
import string
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import dns_client

WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "subdomains.txt")
FALLBACK = ["www", "mail", "api", "dev", "test", "staging", "admin", "vpn", "blog", "app"]


def resolve(host: str):
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def load_wordlist(path=WORDLIST_PATH):
    try:
        with open(path, encoding="utf-8") as fh:
            return [w.strip().lower() for w in fh if w.strip() and not w.startswith("#")]
    except OSError:
        return FALLBACK


def crtsh(domain: str, timeout: float = 20.0):
    """Passive discovery: names seen in public Certificate Transparency logs (crt.sh)."""
    url = "https://crt.sh/?q=%25.{}&output=json".format(domain)
    req = urllib.request.Request(url, headers={"User-Agent": "LightweightASA/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        rows = json.loads(r.read().decode("utf-8", "ignore"))
    return parse_ct_rows(rows, domain)


def parse_ct_rows(rows, domain):
    names = set()
    for row in rows:
        for n in str(row.get("name_value", "")).split("\n"):
            n = n.strip().lower()
            if n and not n.startswith("*") and (n == domain or n.endswith("." + domain)):
                names.add(n)
    return names


def collect_records(domain: str, server: str):
    out, ok = {}, False
    for qt in ("A", "AAAA", "NS", "MX", "TXT"):
        vals = dns_client.values(domain, qt, server)
        if vals is not None:
            ok = True
            out[qt] = vals
    if not ok:
        ip = resolve(domain)
        out = {"A": [ip]} if ip else {}
    return {"ok": ok, "records": out}


def discover(domain: str, threads: int = 30, passive: bool = True, log=print):
    names = {}
    for w in load_wordlist():
        names.setdefault("%s.%s" % (w, domain), set()).add("wordlist")
    if passive:
        try:
            for n in crtsh(domain):
                names.setdefault(n, set()).add("crt.sh")
        except Exception as exc:  # network blocked, timeout, bad JSON ...
            log("      crt.sh unavailable (%s) - using wordlist only" % exc.__class__.__name__)
    names.pop(domain, None)

    token = "".join(random.choices(string.ascii_lowercase, k=12))
    wildcard_ip = resolve("asa-%s.%s" % (token, domain))

    hosts = list(names)
    with ThreadPoolExecutor(max_workers=threads) as pool:
        ips = list(pool.map(resolve, hosts))
    found, unresolved = {}, []
    for host, ip in zip(hosts, ips):
        if not ip:
            unresolved.append(host)
        elif wildcard_ip and ip == wildcard_ip and names[host] == {"wordlist"}:
            continue  # wildcard DNS noise
        else:
            found[host] = {"ip": ip, "sources": sorted(names[host])}
    return {"hosts": found, "unresolved": unresolved, "wildcard": bool(wildcard_ip)}
