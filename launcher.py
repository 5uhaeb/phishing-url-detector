"""Start the local LinkGuard product, including its frontend, on loopback only."""
import argparse
import hashlib
import logging
import os
from pathlib import Path
import subprocess
import sys
from threading import Thread
import venv
import webbrowser

ROOT = Path(__file__).resolve().parent


def environment_ready(use_current=False):
    if sys.version_info[:2] != (3, 13):
        raise RuntimeError('Install Python 3.13, then run START_LINKGUARD.cmd or python launcher.py.')
    if use_current:
        return True
    directory = ROOT/'.venv'
    executable = directory/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
    if Path(sys.executable).resolve() != executable.resolve():
        if not executable.exists():
            print('Preparing the local Python environment...',flush=True)
            venv.EnvBuilder(with_pip=True).create(directory)
        return subprocess.call([str(executable),str(ROOT/'launcher.py'),*sys.argv[1:]])
    requirements = ROOT/'backend/requirements.txt'
    fingerprint = hashlib.sha256(requirements.read_bytes()).hexdigest()
    marker = directory/'.linkguard-requirements'
    if not marker.exists() or marker.read_text() != fingerprint:
        print('Checking dependencies. First setup requires an internet connection.',flush=True)
        subprocess.run([str(executable),'-m','pip','install','--disable-pip-version-check',
                        '--no-input','-r',str(requirements)],check=True)
        marker.write_text(fingerprint)
    return True


def create_local_app(offline=False):
    sys.path.insert(0,str(ROOT/'backend'))
    import main as application
    app=application.app
    mount_frontend(app,ROOT/'frontend')
    if offline:
        application.reputation_client.api_key=''
    return app,application


def mount_frontend(app,frontend):
    from flask import send_from_directory
    app.config['SERVE_LOCAL_FRONTEND']=True
    app.view_functions['index']=lambda:send_from_directory(frontend,'index.html')
    for filename,endpoint in [('app.js','client_script'),('style.css','client_style')]:
        if endpoint not in app.view_functions:
            app.add_url_rule('/'+filename,endpoint,
                             lambda filename=filename:send_from_directory(frontend,filename))
    return app


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline',action='store_true',help='Skip feed refresh and external reputation; setup may still need internet')
    parser.add_argument('--no-browser',action='store_true')
    parser.add_argument('--port',type=int,default=0,help='Local port; 0 selects an available port')
    parser.add_argument('--use-current-env',action='store_true',help='Developer mode: use already installed dependencies')
    args=parser.parse_args()
    if not 0<=args.port<=65535:parser.error('Port must be between 0 and 65535.')
    ready=environment_ready(args.use_current_env)
    if ready is not True:return ready
    logging.basicConfig(level=logging.INFO)
    app,application=create_local_app(args.offline)
    if not args.offline and os.getenv('REFRESH_FEEDS','1')=='1':
        Thread(target=application.refresh_feeds,daemon=True).start()
    from waitress import create_server
    server=create_server(app,host='127.0.0.1',port=args.port,threads=4,
                         max_request_body_size=16*1024,channel_timeout=30)
    address=f'http://127.0.0.1:{server.effective_port}'
    print('\nLinkGuard is ready: '+address,flush=True)
    print('Close this window or press Ctrl+C to stop. Submitted websites are never opened.\n',flush=True)
    if not args.no_browser:webbrowser.open(address)
    try:server.run()
    except KeyboardInterrupt:pass
    finally:server.close()
    return 0


if __name__=='__main__':
    try:sys.exit(main())
    except KeyboardInterrupt:sys.exit(0)
    except (RuntimeError,subprocess.CalledProcessError) as error:
        print('LinkGuard could not start: '+str(error),file=sys.stderr)
        sys.exit(1)
