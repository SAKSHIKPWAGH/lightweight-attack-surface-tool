import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.safety import is_protected
from lab import demo_server
from modules import dns_client, dns_enum, port_scan
from modules.http_check import analyze_cookies, check_paths, inspect
from modules.tls_check import check_tls
from modules.validator import is_valid_target, normalize_target, parse_ports
from reports import history, risk


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestValidatorSafety(unittest.TestCase):
    def test_validator(self):
        self.assertEqual(normalize_target("HTTPS://Example.com/path"), "example.com")
        self.assertTrue(is_valid_target("example.com"))
        self.assertTrue(is_valid_target("127.0.0.1"))
        self.assertFalse(is_valid_target("not a domain"))
        self.assertEqual(parse_ports("80, 443"), [80, 443])
        with self.assertRaises(ValueError):
            parse_ports("70000")

    def test_protected(self):
        self.assertTrue(is_protected("gmail.com"))
        self.assertTrue(is_protected("mail.google.com"))
        self.assertTrue(is_protected("something.gov.in"))
        self.assertFalse(is_protected("mydomain.example"))


class TestDns(unittest.TestCase):
    def test_roundtrip(self):
        tid, pkt = dns_client.build_query("example.com", "MX", tid=0x1234)
        self.assertEqual(struct.unpack("!H", pkt[:2])[0], 0x1234)
        self.assertTrue(pkt.endswith(struct.pack("!HH", 15, 1)))

    def test_parse_response_with_compression(self):
        q = dns_client.encode_name("example.com") + struct.pack("!HH", 16, 1)
        txt = b"v=spf1 -all"
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(txt) + 1) + bytes([len(txt)]) + txt
        mx_host = b"\x04mail\xc0\x0c"
        ans += b"\xc0\x0c" + struct.pack("!HHIH", 15, 1, 60, 2 + len(mx_host)) + struct.pack("!H", 10) + mx_host
        data = struct.pack("!HHHHHH", 1, 0x8180, 1, 2, 0, 0) + q + ans
        rcode, recs = dns_client.parse_response(data)
        self.assertEqual(rcode, 0)
        self.assertEqual(recs[0], {"name": "example.com", "type": "TXT", "value": "v=spf1 -all"})
        self.assertEqual(recs[1]["value"], "10 mail.example.com")

    def test_ct_parsing(self):
        rows = [{"name_value": "a.example.com\n*.example.com\nevil.other.com"}, {"name_value": "B.example.com"}]
        self.assertEqual(dns_enum.parse_ct_rows(rows, "example.com"), {"a.example.com", "b.example.com"})


class TestPortScan(unittest.TestCase):
    def _server(self, banner):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)

        def loop():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                if banner:
                    c.sendall(banner)
                    c.close()
                else:
                    c.settimeout(3)
                    try:
                        c.recv(1)
                    except OSError:
                        pass
                    c.close()
        threading.Thread(target=loop, daemon=True).start()
        return srv, srv.getsockname()[1]

    def test_banner_verification(self):
        good, gp = self._server(b"+OK POP3 ready\r\n")
        bad, bp = self._server(None)  # accepts but never greets (like an AV proxy)
        port_scan.GREETINGS[gp] = port_scan.GREETINGS[bp] = "+OK"
        port_scan.ALL_PORTS[gp] = port_scan.ALL_PORTS[bp] = "POP3"
        try:
            res = port_scan.scan_ports("127.0.0.1", [gp, bp], timeout=1.0, log=lambda *_: None)
        finally:
            good.close()
            bad.close()
        self.assertEqual([r["port"] for r in res], [gp])


class TestHttp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = free_port()
        cls.srv = demo_server.start(cls.port)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_cookie_analysis(self):
        r = analyze_cookies(["a=1; Secure; HttpOnly; SameSite=Lax", "b=2; Path=/"])
        self.assertTrue(r[0]["secure"] and r[0]["httponly"] and r[0]["samesite"])
        self.assertFalse(r[1]["secure"] or r[1]["httponly"] or r[1]["samesite"])

    def test_inspect_and_paths(self):
        r = inspect("127.0.0.1", self.port, False, "127.0.0.1")
        self.assertEqual(r["status"], 200)
        self.assertTrue(r["cors"]["reflected"] and r["cors"]["credentials"])
        self.assertIn("PHP", r["tech"])
        p = check_paths("127.0.0.1", self.port, False, "127.0.0.1")
        rules = {x["rule"] for x in p["found"]}
        self.assertTrue({"PATH-GIT", "PATH-ENV", "PATH-PHPINFO"} <= rules)
        self.assertEqual(p["robots"], ["/admin", "/backup"])


class TestTls(unittest.TestCase):
    @unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
    def test_self_signed(self):
        tmp = tempfile.mkdtemp()
        key, crt = os.path.join(tmp, "k.pem"), os.path.join(tmp, "c.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                        "-days", "10", "-subj", "/CN=localhost"], check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        port = srv.getsockname()[1]

        def loop():
            while True:
                try:
                    c, _ = srv.accept()
                    ctx.wrap_socket(c, server_side=True).close()
                except OSError:
                    if srv.fileno() == -1:
                        return
        threading.Thread(target=loop, daemon=True).start()
        info = check_tls("127.0.0.1", port, 3.0)
        srv.close()
        self.assertFalse(info["verified"])
        self.assertIn("version", info)
        self.assertTrue(info["protocols"]["TLSv1.2"] or info["protocols"]["TLSv1.3"])


class TestRisk(unittest.TestCase):
    def _res(self):
        h = {"port": 80, "tls": False, "final_tls": False, "status": 200, "headers": {"server": "Apache/2.4.1"},
             "cookie_issues": [{"name": "sid", "secure": False, "httponly": False, "samesite": False}],
             "cors": {"reflected": True, "credentials": True}, "redirect_to_https": False}
        h2 = dict(h, port=8080)
        host = {"ip": "1.1.1.1", "ports": [{"port": 80, "service": "HTTP"}, {"port": 3389, "service": "RDP"}],
                "http": [h, h2], "tls": None, "web": {"paths": {"found": [{"rule": "PATH-GIT", "path": "/.git/HEAD"}], "robots": [], "security_txt": False}}}
        dns = {"email": {"checked": True, "spf": None, "dmarc": None}, "dangling": [{"host": "old.x.com", "cname": "gone.io"}]}
        return {"target": "x.com", "hosts": {"x.com": host, "dev.x.com": dict(host)}, "dns": dns}

    def test_dedupe_and_scoring(self):
        f = risk.analyze(self._res())
        ids = [(x["id"], x["host"]) for x in f]
        self.assertEqual(len(ids), len(set(ids)))                       # merged: one finding per rule+host
        csp = next(x for x in f if x["id"] == "HDR-CSP" and x["host"] == "x.com")
        self.assertEqual(csp["ports"], [80, 8080])
        self.assertEqual(next(x for x in f if x["id"] == "CORS-REFLECT")["severity"], "Critical")
        self.assertIn("PATH-GIT", [x["id"] for x in f])
        self.assertIn("EMAIL-SPF-MISSING", [x["id"] for x in f])
        self.assertIn("DNS-DANGLING", [x["id"] for x in f])
        self.assertIn("ASSET-SENSITIVE", [x["id"] for x in f])
        s = risk.score(f, self._res())
        self.assertLessEqual(s["score"], 100)
        self.assertEqual(s["rating"], "Critical")

    def test_history_diff(self):
        res = self._res()
        f1 = risk.analyze(res)
        s1 = risk.score(f1, res)
        res["scanned_at"] = "t"
        prev = {"results": res, "findings": f1, "summary": s1}
        f2 = [x for x in f1 if x["id"] != "PATH-GIT"]
        d = history.diff(prev, res, f2, risk.score(f2, res))
        self.assertEqual([x["id"] for x in d["resolved"]], ["PATH-GIT", "PATH-GIT"])  # one per host
        self.assertEqual(d["new"], [])
        self.assertLess(d["score_delta"], 0)


class TestEndToEnd(unittest.TestCase):
    def test_full_scan(self):
        import main
        port = free_port()
        port_scan.WEB_PORTS.add(port)
        srv = demo_server.start(port)
        out = tempfile.mkdtemp()
        try:
            res, findings, summary = main.main(["localhost", "--authorized", "--ports", str(port), "--output", out, "--timeout", "1"])
            main.main(["localhost", "--authorized", "--ports", str(port), "--output", out])  # 2nd run exercises diff
        finally:
            srv.shutdown()
            srv.server_close()
        ids = {f["id"] for f in findings}
        self.assertTrue({"PATH-GIT", "PATH-ENV", "CORS-REFLECT", "COOKIE-HTTPONLY", "INFO-DISC", "HTTP-NOHTTPS"} <= ids)
        for name in ("report.html", "report.json", "findings.csv", "report.md", "audit.log"):
            self.assertTrue(os.path.exists(os.path.join(out, name)), name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
