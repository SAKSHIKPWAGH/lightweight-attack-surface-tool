"""Scan orchestration: DNS -> subdomains -> ports -> HTTP/TLS -> results dictionary."""
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from modules import dns_enum, dns_security
from modules.http_check import check_paths, inspect
from modules.port_scan import PROFILES, TLS_PORTS, WEB_PORTS, scan_ports
from modules.tls_check import check_tls
from modules.validator import is_ip


def _analyze_host(host, ports, scope, a):
    http, tls = [], None
    for p in ports:
        port = p["port"]
        if port in WEB_PORTS:
            http.append(inspect(host, port, False, scope, a.http_timeout))
        elif port in TLS_PORTS:
            http.append(inspect(host, port, True, scope, a.http_timeout))
            if tls is None:
                tls = check_tls(host, port, a.http_timeout, deep=not a.no_tls_probe)
    web = {"tech": [], "paths": {"found": [], "robots": [], "security_txt": False}}
    ok = [h for h in http if "error" not in h]
    if ok:
        web["tech"] = sorted({t for h in ok for t in h.get("tech", [])})
        if not a.no_paths:
            prim = next((h for h in ok if h["tls"]), ok[0])
            web["paths"] = check_paths(host, prim["port"], prim["tls"], scope, a.http_timeout)
    return {"http": http, "tls": tls, "web": web}


def run_scan(a, log=print):
    start = time.time()
    target = a.target
    ip = target if is_ip(target) else dns_enum.resolve(target)
    if not ip:
        raise SystemExit("Could not resolve target.")
    is_domain = not is_ip(target) and target != "localhost"

    dns = {"resolver": a.dns_server, "resolver_ok": False, "records": {}, "email": {"checked": False},
           "dangling": [], "sources": {target: ["target"]}, "wildcard": False}
    hosts = {target: ip}

    if is_domain:
        log("[1/5] Collecting DNS records ...")
        rec = dns_enum.collect_records(target, a.dns_server)
        dns["records"], dns["resolver_ok"] = rec["records"], rec["ok"]
        if not dns["resolver_ok"]:
            log("      DNS server %s unreachable (UDP 53 blocked?) - email/takeover checks skipped" % a.dns_server)
        unresolved = []
        if not a.no_subdomains:
            log("[2/5] Discovering subdomains (wordlist%s) ..." % ("" if a.no_passive else " + CT logs"))
            found = dns_enum.discover(target, a.threads, not a.no_passive, log)
            dns["wildcard"], unresolved = found["wildcard"], found["unresolved"]
            for h, v in found["hosts"].items():
                hosts[h] = v["ip"]
                dns["sources"][h] = v["sources"]
            log("      %d subdomain(s) resolve" % len(found["hosts"]))
            if len(hosts) > a.max_hosts:
                keep = [target] + sorted(h for h in hosts if h != target)[:a.max_hosts - 1]
                log("      capped to %d hosts (--max-hosts)" % a.max_hosts)
                hosts = {h: hosts[h] for h in keep}
        else:
            log("[2/5] Subdomain discovery skipped")
        if dns["resolver_ok"]:
            dns["email"] = dns_security.check_email(target, a.dns_server)
            dns["dangling"] = dns_security.find_dangling(unresolved, a.dns_server, a.threads)
    else:
        log("[1/5] DNS stage skipped (IP / localhost target)")
        log("[2/5] Subdomain discovery skipped")

    log("[3/5] Scanning ports on %d host(s) ..." % len(hosts))
    ports_by_ip, results_hosts = {}, {}
    for host, h_ip in hosts.items():
        if h_ip not in ports_by_ip:
            ports_by_ip[h_ip] = scan_ports(h_ip, a.ports or PROFILES[a.profile], a.timeout, a.threads, log)
            if a.delay:
                time.sleep(a.delay)
        results_hosts[host] = {"ip": h_ip, "ports": ports_by_ip[h_ip]}

    log("[4/5] Analysing HTTP, cookies, CORS and TLS ...")
    with ThreadPoolExecutor(max_workers=min(8, len(results_hosts))) as pool:
        futures = {h: pool.submit(_analyze_host, h, d["ports"], target, a) for h, d in results_hosts.items()}
        for h, f in futures.items():
            results_hosts[h].update(f.result())

    log("[5/5] Scoring findings ...")
    return {"target": target, "scanned_at": datetime.now().isoformat(timespec="seconds"),
            "duration_s": round(time.time() - start, 1), "profile": "custom" if a.ports else a.profile,
            "dns": dns, "hosts": results_hosts}
