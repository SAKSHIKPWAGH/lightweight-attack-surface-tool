"""TCP connect scan with banner verification and a canary check for local interception."""
import random
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8000: "HTTP-alt", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}
EXTRA_PORTS = {
    111: "RPCbind", 139: "NetBIOS", 389: "LDAP", 636: "LDAPS", 873: "rsync", 1521: "Oracle",
    2049: "NFS", 2375: "Docker-API", 5000: "HTTP-alt", 5601: "Kibana", 5985: "WinRM",
    8081: "HTTP-alt", 8888: "HTTP-alt", 9000: "HTTP-alt", 9090: "HTTP-alt",
    10000: "Webmin", 15672: "RabbitMQ-mgmt",
}
ALL_PORTS = {**COMMON_PORTS, **EXTRA_PORTS}
PROFILES = {
    "quick": [22, 80, 443, 445, 3389, 8080, 8443],
    "common": list(COMMON_PORTS),
    "extended": list(ALL_PORTS),
}
WEB_PORTS = {80, 8000, 8080, 8081, 8888, 5000, 9000, 9090}
TLS_PORTS = {443, 8443}
IMPLICIT_TLS = {993, 995}
# Services that speak first: a real server must start with this greeting
GREETINGS = {21: "220", 22: "SSH-", 25: "220", 110: "+OK", 143: "* OK", 993: "* OK", 995: "+OK"}


def _read_banner(sock, port, timeout):
    try:
        sock.settimeout(timeout)
        if port in IMPLICIT_TLS:
            sock = ssl._create_unverified_context().wrap_socket(sock)
        return sock.recv(160).decode(errors="ignore").strip()
    except OSError:
        return ""


def _probe(args):
    host, port, timeout = args
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            service = ALL_PORTS.get(port, "unknown")
            if port in GREETINGS:
                banner = _read_banner(s, port, 2.5)
                if not banner.startswith(GREETINGS[port]):
                    return {"port": port, "unverified": True}
                return {"port": port, "service": service, "banner": banner}
            return {"port": port, "service": service, "banner": ""}
    except OSError:
        return None


def scan_ports(host: str, ports=None, timeout: float = 1.0, threads: int = 50, log=print):
    ports = ports or PROFILES["common"]
    canaries = random.sample(range(49152, 65535), 2)
    if any(_probe((host, c, timeout)) for c in canaries):
        log("  WARNING: %s answers on random closed ports - local interception likely; "
            "results may be unreliable." % host)
    with ThreadPoolExecutor(max_workers=threads) as pool:
        results = [r for r in pool.map(_probe, [(host, p, timeout) for p in ports]) if r]
    for r in results:
        if r.get("unverified"):
            log("  note: %s:%d accepted the connection but sent no valid %s greeting - ignored"
                % (host, r["port"], ALL_PORTS.get(r["port"], "service")))
    return sorted([r for r in results if not r.get("unverified")], key=lambda r: r["port"])
