# VulnLab — Authorized Local Test Application

Deliberately vulnerable HTTP test application used to **verify the custom
Python scanner engine end-to-end** (run locally or inside the compose network
via `host.docker.internal`). Contains intentionally insecure endpoints only —
**never deploy or expose it** beyond an authorized local/dev environment.

Start it:

```bash
python app.py            # listens on 0.0.0.0:8090
```

To scan it, the dev/test bypass must be enabled on the scanning process:

```bash
ALLOW_PRIVATE_SCAN_TARGETS=1 python scanner_engine/main.py \
    --target http://127.0.0.1:8090 --scan-id <scan-uuid> \
    --db-url postgresql://postgres:postgres@localhost:5433/vulnscan_dev
```

| Endpoint | Intended weakness exercised |
|----------|------------------------------|
| `/` | index page with crawlable links + forms |
| `/echo?q=` | raw (unencoded) input reflection — XSS / input reflection detection |
| `/xss_script?q=` | reflection inside a `<script>` block — XSS detection |
| `/sqli?id=` | simulated SQL error reflection (matches real DB error text) — SQLi |
| `/file?path=` | path-traversal sink that leaks `/etc/passwd` content when probed |
| `/redir?url=` | open redirect (302 to attacker-controlled URL) |
| `/setcookie` | insecure `Set-Cookie` (no Secure / HttpOnly / SameSite) |
| `/cors` | reflects `Origin` with `Access-Control-Allow-Credentials` |
| `/options` | allows TRACE — HTTP method audit |
| `/listing/` | directory-listing style page |
| `/disclose` | banner + debug markers — information disclosure |
| every page | `Server` banner, no security headers |
