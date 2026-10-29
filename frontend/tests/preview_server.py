"""Start the separate backend and frontend for browser tests."""
import os
import subprocess
import sys
from pathlib import Path
from time import monotonic, sleep
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
environment = dict(os.environ, HOST='127.0.0.1', PORT='5188',
                   FRONTEND_ORIGINS='http://127.0.0.1:5187', BACKEND_URL='http://127.0.0.1:5188', REFRESH_FEEDS='0')
flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
backend = subprocess.Popen([sys.executable, 'main.py'], cwd=ROOT / 'backend', env=environment, creationflags=flags)
try:
    deadline = monotonic() + 60
    while True:
        if backend.poll() is not None:
            raise RuntimeError('Backend exited before it was ready.')
        try:
            with urlopen('http://127.0.0.1:5188/health', timeout=1):
                break
        except URLError:
            if monotonic() >= deadline:
                raise RuntimeError('Backend did not become ready.')
            sleep(.2)
    subprocess.run([sys.executable, 'dev_server.py'], cwd=ROOT / 'frontend', env=environment, check=True)
finally:
    backend.terminate()
    backend.wait(timeout=10)
