"""Measure the real local HTTP prediction path; never contact URL destinations."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from time import perf_counter, sleep

import numpy as np
import requests


def measure(output):
    backend=Path(__file__).resolve().parent
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    environment=dict(os.environ,HOST='127.0.0.1',PORT=str(port),REFRESH_FEEDS='0',MODEL_NAME='xgboost')
    process=subprocess.Popen([sys.executable,str(backend/'main.py')],env=environment,cwd=backend,
        stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    base=f'http://127.0.0.1:{port}'
    try:
        session=requests.Session();session.trust_env=False
        health=None
        for _ in range(100):
            if process.poll() is not None:raise RuntimeError('Local API failed to start')
            try:
                r=session.get(base+'/health',timeout=1)
                if r.status_code==200:health=r.json();break
            except requests.RequestException:pass
            sleep(.1)
        if health is None:raise RuntimeError('Local API startup timeout')
        values=[];internal=[]
        urls=['https://example.com/','https://example.com/account/login?return=%2Fprofile',
              'https://user@example.com/verify','https://xn--fa-hia.de/#login']
        for index in range(18):
            tick=perf_counter();response=session.post(base+'/api/predict',json={'url':urls[index%4],'consent':False},timeout=10)
            response.raise_for_status();result=response.json()
            if index>=2:values.append((perf_counter()-tick)*1000);internal.append(result['latency_ms'])
        result=dict(model=health['model_name'],model_version=health['model_version'],samples=len(values),
            scope='Warm local HTTP API, existing XGBoost, no external threat service; not Render internet latency',
            http_median_ms=float(np.median(values)),http_p95_ms=float(np.percentile(values,95)),
            internal_median_ms=float(np.median(internal)),internal_p95_ms=float(np.percentile(internal,95)))
        output.mkdir(parents=True,exist_ok=True)
        (output/'api_runtime.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
    finally:
        process.terminate()
        try:process.wait(timeout=10)
        except subprocess.TimeoutExpired:process.kill();process.wait()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    measure(parser.parse_args().output)
