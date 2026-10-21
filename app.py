"""Run with: python app.py. External reputation checks require per-request consent."""

import os
import logging
import json
from threading import Event, Thread
from pathlib import Path
from time import perf_counter
from urllib.parse import urlsplit

import joblib
from flask import Flask, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from detector import FEATURE_NAMES, analyze
from reputation import ReputationClient, combine_evidence
from feeds import FeedStore

ROOT = Path(__file__).resolve().parent
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024
app.config['MAX_FORM_MEMORY_SIZE'] = 16 * 1024
app.config['MAX_FORM_PARTS'] = 8
app.config['TRUSTED_HOSTS'] = [host.strip() for host in os.getenv(
    'ALLOWED_HOSTS', '127.0.0.1,localhost,[::1]').split(',') if host.strip()]
if os.getenv('RENDER_EXTERNAL_HOSTNAME'):
    app.config['TRUSTED_HOSTS'].append(os.environ['RENDER_EXTERNAL_HOSTNAME'])
# Only exact deployment origins are accepted; never trust every *.vercel.app site.
frontend_origins = {origin.strip().rstrip('/') for origin in
                    os.getenv('FRONTEND_ORIGINS', '').split(',') if origin.strip()}
limiter = Limiter(get_remote_address, app=app, storage_uri=os.getenv('RATELIMIT_STORAGE_URI', 'memory://'),
                  headers_enabled=True, default_limits=[])
analysis_limit = limiter.shared_limit('30 per minute;300 per hour', scope='url-analysis',
                                      methods=['POST'])
reputation_client = ReputationClient()
feed_store = FeedStore()
artifact = None
if (ROOT / 'model.joblib').exists():
    artifact = joblib.load(ROOT / 'model.joblib')
    if artifact.get('features') != list(FEATURE_NAMES):
        raise RuntimeError('Model feature schema changed. Run train.py again.')


@app.after_request
def response_headers(response):
    origin = request.headers.get('Origin')
    if origin in frontend_origins and request.path.startswith('/api/'):
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        response.vary.add('Origin')
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Avoid Origin:null on ordinary form POSTs, while withholding cross-origin referrers.
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
    return response


@app.before_request
def prevent_cross_site_submission():
    if request.method == 'POST':
        origin = request.headers.get('Origin')
        fetch_site = request.headers.get('Sec-Fetch-Site')
        # Old tabs/privacy settings can suppress Origin. Only trust an opaque
        # origin when browser-controlled Fetch Metadata confirms same-origin.
        if origin == 'null':
            invalid_origin = fetch_site != 'same-origin'
        else:
            invalid_origin = bool(origin) and origin_tuple(origin) != origin_tuple(request.host_url)
        allowed_frontend = (request.path.startswith('/api/') and origin in frontend_origins)
        if not allowed_frontend and (fetch_site == 'cross-site' or invalid_origin):
            if request.path == '/api/predict' or request.is_json:
                return jsonify(error='Cross-site submissions are not allowed.'), 403
            return render_template('index.html', result=None, url='', model_ready=artifact is not None,
                                   error='The submission could not be verified. Reload this page and try again.'), 403


def origin_tuple(value):
    try:
        parts = urlsplit(value)
        if (parts.scheme not in ('http', 'https') or not parts.hostname or
                parts.username is not None or parts.password is not None or
                parts.path not in ('', '/') or parts.query or parts.fragment):
            return None
        return parts.scheme, parts.hostname.lower(), parts.port or (443 if parts.scheme == 'https' else 80)
    except ValueError:
        return None


@app.context_processor
def page_state():
    evaluation = read_report('evaluation.json')
    if not artifact or evaluation.get('trained_at') != artifact['trained_at']:
        evaluation = {}
    return dict(reputation_configured=bool(reputation_client.api_key), feed_summary=feed_store.status(),
                evaluation=evaluation)


def read_report(filename):
    try:
        report = json.loads((ROOT / filename).read_text(encoding='utf-8'))
        return report if isinstance(report, dict) else {}
    except (OSError, ValueError):
        return {}


def predict(value, consent=False):
    if artifact is None:
        return None, 'Model unavailable. Run python train.py --download, then restart the app.', 503
    start = perf_counter()
    try:
        result = analyze(value, artifact)
        feed_result = feed_store.lookup(value)
        reputation = reputation_client.lookup(result['url'], consent=consent)
        result = combine_evidence(result, feed_result if feed_result['status'] == 'match' else reputation)
        result['public_feeds'] = feed_result
        result['external_reputation'] = reputation
        if feed_result['status'] == 'match':
            result['verification'] = 'Exact URL reported in a downloaded public phishing feed'
        elif reputation['status'] not in ('match', 'no_match'):
            result['verification'] = ('No exact match in the available public feeds' if feed_result['status'] == 'not_listed'
                                      else 'Public-feed check incomplete or unavailable')
        if feed_result['status'] == 'stale_match' and result['risk'] in ('Low', 'Unknown'):
            result.update(prediction='Needs review', risk='Medium', evidence='Expired feed match; refresh required')
    except ValueError as exc:
        return None, str(exc), 400
    result['latency_ms'] = round((perf_counter() - start) * 1000, 2)
    return result, None, 200


@app.route('/', methods=['GET', 'POST'])
@analysis_limit
def index():
    result, error, status = None, None, 200
    value = request.form.get('url', '') if request.method == 'POST' else ''
    if request.method == 'POST':
        result, error, status = predict(value, request.form.get('consent') == 'yes')
    return render_template('index.html', result=result, error=error, url=value,
                           model_ready=artifact is not None), status


@app.post('/api/predict')
@analysis_limit
def api_predict():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error='Send a JSON object containing url.'), 400
    consent = body.get('consent', False)
    if type(consent) is not bool:
        return jsonify(error='consent must be a JSON boolean, true or false.'), 400
    result, error, status = predict(body.get('url'), consent)
    return jsonify(result if result else {'error': error}), status


@app.get('/api/status')
def api_status():
    return jsonify(model_ready=artifact is not None,
                   reputation_configured=bool(reputation_client.api_key),
                   public_feeds=feed_store.status())


@app.post('/report')
@analysis_limit
def download_report():
    value = request.form.get('url', '')
    result, error, status = predict(value, request.form.get('consent') == 'yes')
    if error:
        return render_template('index.html', result=None, error=error, url=value,
                               model_ready=artifact is not None), status
    response = jsonify(result)
    response.headers['Content-Disposition'] = 'attachment; filename="url-analysis.json"'
    return response


@app.errorhandler(413)
def input_too_large(error):
    message = 'Input is too large. Submit one URL of at most 4,096 characters.'
    if request.path == '/api/predict':
        return jsonify(error=message), 413
    return render_template('index.html', result=None, error=message, url='',
                           model_ready=artifact is not None), 413


@app.get('/health')
def health():
    return jsonify(status='ready' if artifact is not None else 'model_missing',
                   public_feeds=feed_store.status(),
                   reputation='configured' if reputation_client.api_key else 'not_configured',
                   rate_limit_storage='shared' if os.getenv('RATELIMIT_STORAGE_URI', 'memory://') != 'memory://'
                   else 'single_process_memory', production_validated=False), 200 if artifact else 503


@app.get('/evaluation')
def evaluation_report():
    response = jsonify(model=read_report('evaluation.json'),
                       independent_domains=read_report('external-evaluation.json'),
                       paper_context=read_report('benchmark-results.json'))
    response.headers['Content-Disposition'] = 'attachment; filename="evaluation-results.json"'
    return response


@app.errorhandler(429)
def too_many_requests(error):
    message = 'Too many checks. Wait before submitting another URL.'
    if request.path == '/api/predict':
        return jsonify(error=message), 429
    return render_template('index.html', result=None, error=message, url='',
                           model_ready=artifact is not None), 429


if __name__ == '__main__':
    from waitress import serve
    def update_feeds():
        while True:
            try:
                current = feed_store.status()
                # Check twice daily, with no submitted URL sent in these downloads.
                if current['status'] != 'fresh' or any(s['age_hours'] >= 12 for s in current['sources']):
                    feed_store.refresh()
            except Exception:
                logging.getLogger(__name__).error('Feed refresh failed; existing snapshot remains available.')
            Event().wait(12 * 3600)
    Thread(target=update_feeds, name='public-feed-refresh', daemon=True).start()
    serve(app, host=os.getenv('HOST', '127.0.0.1'), port=int(os.getenv('PORT', '5000')), threads=4, max_request_body_size=16 * 1024,
          channel_timeout=30)
