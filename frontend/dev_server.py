"""Serve the frontend locally and forward API requests to the backend."""
import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
BACKEND = os.getenv('BACKEND_URL', 'http://127.0.0.1:5000').rstrip('/')


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def proxy(self):
        size = int(self.headers.get('Content-Length', '0'))
        if size > 16 * 1024:
            self.send_error(413)
            return
        body = self.rfile.read(size) if self.command == 'POST' else None
        headers = {key: self.headers[key] for key in ['Content-Type', 'Origin', 'Sec-Fetch-Site'] if key in self.headers}
        upstream = Request(BACKEND + self.path, data=body, headers=headers, method=self.command)
        try:
            response = urlopen(upstream, timeout=60)
        except HTTPError as error:
            response = error
        except URLError:
            self.send_error(502, 'Backend unavailable. Start backend/main.py first.')
            return
        with response:
            content = response.read()
            self.send_response(response.code)
            self.send_header('Content-Type', response.headers.get('Content-Type', 'application/json'))
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'no-store')
            if response.headers.get('Retry-After'):
                self.send_header('Retry-After', response.headers['Retry-After'])
            self.end_headers()
            self.wfile.write(content)

    def do_GET(self):
        if self.path.startswith('/api/'):
            self.proxy()
        else:
            super().do_GET()

    def do_POST(self):
        if self.path.startswith('/api/'):
            self.proxy()
        else:
            self.send_error(404)


if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', 5187), Handler).serve_forever()
