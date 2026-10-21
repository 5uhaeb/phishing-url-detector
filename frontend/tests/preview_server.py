"""Local frontend + real API server for browser integration tests."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from flask import send_from_directory
from werkzeug.serving import make_server
from app import app

app.view_functions['index'] = lambda: send_from_directory(ROOT / 'frontend', 'index.html')
app.add_url_rule('/app.js', 'frontend_script', lambda: send_from_directory(ROOT / 'frontend', 'app.js'))
app.add_url_rule('/style.css', 'frontend_style', lambda: send_from_directory(ROOT / 'static', 'style.css'))

if __name__ == '__main__':
    make_server('127.0.0.1', 5187, app, threaded=True).serve_forever()
