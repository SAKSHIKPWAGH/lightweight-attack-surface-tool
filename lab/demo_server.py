"""Deliberately weak LOCAL web server for demonstrating the scanner safely.

Run:   python lab/demo_server.py          (listens on 127.0.0.1:8000)
Scan:  python main.py localhost --authorized --ports 8000

Everything here is fake: the .env values are dummies and the server binds to localhost only.
"""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

FILES = {
    "/.git/HEAD": b"ref: refs/heads/main\n",
    "/.env": b"DB_PASSWORD=demo-not-a-real-secret\nAPP_KEY=demo-key\n",
    "/robots.txt": b"User-agent: *\nDisallow: /admin\nDisallow: /backup\n",
    "/phpinfo.php": b"<html><title>phpinfo()</title>PHP Version 7.2.1</html>",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.29 (Ubuntu)"
    sys_version = ""

    def do_GET(self):
        body = FILES.get(self.path, b"<html><head><title>Demo Corp Portal</title></head><body>Welcome</body></html>")
        code = 200 if (self.path in FILES or self.path == "/") else 404
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Powered-By", "PHP/7.2.1")
        self.send_header("Set-Cookie", "PHPSESSID=abc123; Path=/")
        origin = self.headers.get("Origin")
        if origin:                                   # insecure: reflects any Origin with credentials
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start(port=8000):
    srv = HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    print("Demo target running on http://127.0.0.1:8000  (Ctrl+C to stop)")
    HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
