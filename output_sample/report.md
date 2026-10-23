# Attack Surface Report: localhost

Generated 2026-10-14T09:23:44 | Risk **High** (51/100)

| Severity | Host | Finding | Ports |
|---|---|---|---|
| Critical | localhost | CORS reflects arbitrary Origin | 8000 |
| Critical | localhost | Exposed .env configuration file | - |
| Critical | localhost | Exposed .git repository | - |
| Medium | localhost | Cookie without HttpOnly flag | 8000 |
| Medium | localhost | Missing Content-Security-Policy header | 8000 |
| Medium | localhost | Web service offered only over HTTP | 8000 |
| Medium | localhost | Exposed phpinfo() page | - |
| Low | localhost | Cookie without SameSite attribute | 8000 |
| Low | localhost | Missing Referrer-Policy header | 8000 |
| Low | localhost | Missing X-Content-Type-Options header | 8000 |
| Low | localhost | Missing clickjacking protection | 8000 |
| Low | localhost | Software version disclosed in HTTP headers | 8000 |
| Info | localhost | No security.txt published | - |
| Info | localhost | robots.txt lists disallowed paths | - |
