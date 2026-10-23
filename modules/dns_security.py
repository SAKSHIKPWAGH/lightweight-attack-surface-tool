"""DNS-level security checks: SPF / DMARC and dangling CNAMEs (subdomain takeover)."""
import re
import socket
from concurrent.futures import ThreadPoolExecutor

from . import dns_client


def check_email(domain: str, server: str):
    txt = dns_client.values(domain, "TXT", server)
    dm = dns_client.values("_dmarc." + domain, "TXT", server)
    if txt is None or dm is None:
        return {"checked": False}
    spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)
    dmarc = next((t for t in dm if t.lower().startswith("v=dmarc1")), None)
    m = re.search(r"\s([+\-~?]?)all\b", spf or "")
    pol = re.search(r"\bp=(\w+)", dmarc or "", re.I)
    return {"checked": True, "spf": spf, "spf_all": ((m.group(1) or "+") if m else None),
            "dmarc": dmarc, "dmarc_policy": pol.group(1).lower() if pol else None}


def _dangling(args):
    host, server = args
    r = dns_client.query(host, "CNAME", server)
    if not r:
        return None
    for rec in r[1]:
        if rec["type"] == "CNAME":
            try:
                socket.gethostbyname(rec["value"])
            except OSError:
                return {"host": host, "cname": rec["value"]}
    return None


def find_dangling(candidates, server: str, threads: int = 20, limit: int = 300):
    """CNAME records pointing to names that no longer resolve can be claimed by attackers."""
    with ThreadPoolExecutor(max_workers=threads) as pool:
        res = pool.map(_dangling, [(h, server) for h in candidates[:limit]])
    return [r for r in res if r]
