"""Read-only Windows firewall dashboard. Python standard library only."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent
LOCK = threading.Lock()
CACHE = None


def collect():
    shell = shutil.which('pwsh') or shutil.which('powershell')
    if not shell:
        raise RuntimeError('PowerShell was not found on PATH.')
    result = subprocess.run(
        [shell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(ROOT / 'collect.ps1')],
        capture_output=True, encoding='utf-8-sig', errors='replace', timeout=180,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'PowerShell collection failed.')
    return json.loads(result.stdout)


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body, content_type='application/json; charset=utf-8'):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)

    def permitted(self):
        host = f'127.0.0.1:{self.server.server_port}'
        origin = self.headers.get('Origin')
        if (self.headers.get('Host') != host or
                (origin and origin != f'http://{host}') or
                self.headers.get('Sec-Fetch-Site') == 'cross-site'):
            self.reply(403, {'error': 'Only the local dashboard origin is accepted.'})
            return False
        return True

    def do_GET(self):
        if not self.permitted():
            return
        files = {'/': ('index.html', 'text/html; charset=utf-8'),
                 '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                 '/services.js': ('services.js', 'text/javascript; charset=utf-8'),
                 '/style.css': ('style.css', 'text/css; charset=utf-8')}
        if self.path == '/api/data':
            self.reply(200, {'data': CACHE})
        elif self.path in files:
            name, mime = files[self.path]
            self.reply(200, (ROOT / name).read_bytes(), mime)
        else:
            self.reply(404, {'error': 'Not found'})

    def do_POST(self):
        global CACHE
        if not self.permitted():
            return
        if self.path != '/api/refresh':
            self.reply(404, {'error': 'Not found'})
            return
        if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Length', '0') != '0':
            self.reply(400, {'error': 'Refresh does not accept a request body.'})
            return
        if not LOCK.acquire(blocking=False):
            self.reply(409, {'error': 'A collection is already running.'})
            return
        try:
            CACHE = collect()
            self.reply(200, {'data': CACHE})
        except Exception as exc:
            self.reply(500, {'error': str(exc)})
        finally:
            LOCK.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    url = f'http://127.0.0.1:{server.server_port}'
    print(f'Firewall dashboard: {url}\nRead-only. Press Ctrl+C to stop.', flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
