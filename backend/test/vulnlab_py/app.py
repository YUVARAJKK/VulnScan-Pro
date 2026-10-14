"""VulnLab — intentionally vulnerable HTTP test app (scanner verification only).

Pure stdlib (http.server) so it runs anywhere with no dependencies.
Deliberately insecure — for authorized local testing only. Every response:

  * leaks a Server banner + X-Powered-By,
  * sets an insecure session cookie,
  * reflects any Origin with Access-Control-Allow-Credentials,
  * sends no security headers.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = 8090
SERVER_BANNER = 'LabServer/2.4.1'
POWERED_BY = 'LabCore 1.7 (debug build)'


def build_page(body):
    return (
        '<!DOCTYPE html><html><head><title>VulnLab</title></head><body>'
        + body
        + '</body></html>'
    )


def esc(value):
    return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


class Handler(BaseHTTPRequestHandler):
    server_version = SERVER_BANNER
    sys_version = POWERED_BY
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    # ── helpers ──────────────────────────────────────────────────────────

    def _send(self, body, status=200, ctype='text/html; charset=utf-8', extra=None):
        data = body.encode('utf-8') if isinstance(body, str) else body
        headers = dict(extra or {})
        # Insecure session cookie on every response (flag audit surface)
        headers.setdefault('Set-Cookie', 'session=lab123abc456; Path=/')
        # CORS: reflect any origin + allow credentials (misconfiguration surface)
        origin = self.headers.get('Origin')
        if origin:
            headers.setdefault('Access-Control-Allow-Origin', origin)
            headers.setdefault('Access-Control-Allow-Credentials', 'true')
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _q(self, name, default=''):
        parsed = parse_qs(urlparse(self.path).query)
        vals = parsed.get(name)
        return vals[0] if vals else default

    # ── routes ───────────────────────────────────────────────────────────

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'

        if path == '/':
            self._send(build_page(
                '<h1>VulnLab</h1>'
                '<ul>'
                '<li><a href="/about">About</a></li>'
                '<li><a href="/products?id=1">Products (SQLi sink: id)</a></li>'
                '<li><a href="/search?q=hello">Search (reflection)</a></li>'
                '<li><a href="/echo?q=hello">Echo (reflection)</a></li>'
                '<li><a href="/xss_script?q=hello">Script echo (XSS sink)</a></li>'
                '<li><a href="/sqli?id=1">DB query (SQLi sink)</a></li>'
                '<li><a href="/file?path=notes.txt">File read (LFI sink)</a></li>'
                '<li><a href="/redir?url=/">Redirect (open redirect sink)</a></li>'
                '<li><a href="/options">Methods (TRACE)</a></li>'
                '<li><a href="/setcookie">Cookie page</a></li>'
                '<li><a href="/cors">CORS page</a></li>'
                '<li><a href="/listing/">Directory listing</a></li>'
                '<li><a href="/disclose">Debug endpoint</a></li>'
                '<li><a href="/static/app.js.map">Source map</a></li>'
                '<li><a href="/.env">Environment file</a></li>'
                '</ul>'
                '<form action="/echo" method="get">'
                '<input type="text" name="q" value="labs"><input type="submit" value="Go">'
                '</form>'
            ))

        elif path == '/about':
            self._send(build_page('<p>VulnLab sample app — authorized test target.</p>'))

        elif path == '/products':
            pid = self._q('id', '1')
            self._send(build_page(
                f'<p>Product {esc(pid)} — details</p>'
                f'<p><a href="/products?id={esc(pid)}">refresh</a></p>'
            ))

        elif path == '/search':
            term = self._q('q', '')
            self._send(build_page(
                f'<p>Search results for {term}</p>'
                f'<input type="text" name="q" value="{term}">'
            ))

        elif path == '/echo':
            val = self._q('q', '')
            self._send(build_page(
                f'<p>Echo: {val}</p>'
                f'<input type="text" name="q" value="{val}">'
            ))

        elif path == '/xss_script':
            val = self._q('q', '')
            self._send(build_page(
                f'<script>var search = "{val}"; document.write(search);</script>'
                '<p>rendered</p>'
            ))

        elif path == '/sqli':
            idv = self._q('id', '1')
            lowered = idv.lower()
            if any(x in idv for x in ("'", '"', ';')) or ' or ' in lowered or '--' in idv or 'union' in lowered:
                self._send(build_page(
                    f'<p>DB Error: unrecognized token: "{esc(idv)}"</p>'
                    f'<pre>SELECT name FROM users WHERE id = {esc(idv)}</pre>'
                ), status=500)
            else:
                self._send(build_page(f'<p>Hello admin (id={esc(idv)})</p>'))

        elif path == '/file':
            pathv = self._q('path', 'notes.txt')
            low = pathv.lower()
            if 'etc/passwd' in low or 'root:x' in low or 'boot.ini' in low:
                self._send(
                    'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'
                    'mysql:x:111:116:MySQL Server,,,:/nonexistent:/bin/false\n',
                    ctype='text/plain',
                )
            else:
                self._send(build_page(f'<p>File content of {esc(pathv)}:</p><pre>(empty)</pre>'))

        elif path == '/redir':
            target = self._q('url', '/')
            if target.startswith(('http://', 'https://', '//')):
                self._send('', status=302, ctype='text/html', extra={'Location': target})
            else:
                self._send('', status=302, ctype='text/html', extra={'Location': '/'})

        elif path == '/options':
            self._send(build_page('<p>methods endpoint</p>'))

        elif path == '/listing':
            self._send(build_page(
                '<h1>Index of /files</h1>'
                '<table><tr><th><a href="/listing/">Parent Directory</a></th></tr>'
                '<tr><td><a href="/listing/report.pdf">report.pdf</a></td></tr>'
                '<tr><td><a href="/listing/backup.sql">backup.sql</a></td></tr></table>'
            ))

        elif path == '/disclose':
            self._send(build_page(
                '<pre>Traceback (most recent call last):\n'
                '  File "/srv/app/core.py", line 42, in handle\n'
                '    raise RuntimeError("Debug mode is ON — stack exposed")\n'
                'RuntimeError: Debug mode is ON — stack exposed</pre>'
                '<!-- TODO: remove debug endpoints before launch -->'
            ))

        elif path == '/static/app.js.map':
            self._send('{"version":3,"sources":["src/app.js"],"names":[]}', ctype='application/json')

        elif path == '/.env':
            self._send(
                'DB_HOST=internal-db\nDB_PASSWORD=SuperSecret123\nSECRET_KEY=dev-only-please-rotate\n',
                ctype='text/plain',
            )

        elif path == '/.git/config':
            self._send(
                '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@github.com:acme/app.git\n',
                ctype='text/plain',
            )

        else:
            self._send(build_page('<p>404 not found</p>'), status=404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Allow', 'GET, HEAD, POST, OPTIONS, TRACE')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_TRACE(self):
        body = 'TRACE request received (echo)'.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        # Minimal HEAD support (no body) so probing tools can poll headers
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'
        exists = path in {'', '/', '/about', '/products', '/search', '/echo', '/xss_script',
                          '/sqli', '/file', '/redir', '/options', '/setcookie', '/cors',
                          '/listing', '/disclose', '/static/app.js.map', '/.env', '/.git/config'}
        self.send_response(200 if exists else 404)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path.rstrip('/') == '/login':
            length = int(self.headers.get('Content-Length') or 0)
            data = self.rfile.read(length).decode('utf-8', 'replace')
            self._send(build_page(f'<p>login form processed: {esc(data)}</p>'))
        else:
            self._send(build_page('<p>ok</p>'))


if __name__ == '__main__':
    print(f'VulnLab listening on http://0.0.0.0:{PORT} (AUTHORIZED LOCAL TEST APP ONLY)')
    ThreadingHTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
