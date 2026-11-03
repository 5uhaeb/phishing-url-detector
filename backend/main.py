"""LinkGuard API. Start with: python main.py"""
import hashlib
import json
import logging
import os
from pathlib import Path
from threading import Event, Thread
from time import perf_counter
from urllib.parse import urlsplit

import joblib
from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException

from detector import FEATURE_NAMES, analyze
from feeds import FeedStore
from reputation import ReputationClient, combine_evidence

ROOT = Path(__file__).resolve().parent
MODEL_NAMES = ('random_forest', 'xgboost', 'lightgbm')
MODEL_NAME = os.getenv('MODEL_NAME', 'xgboost')
if MODEL_NAME not in MODEL_NAMES:
    raise ValueError('MODEL_NAME must be random_forest, xgboost or lightgbm.')

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024
app.config['TRUSTED_HOSTS'] = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1,[::1]').split(',')
if os.getenv('RENDER_EXTERNAL_HOSTNAME'):
    app.config['TRUSTED_HOSTS'].append(os.environ['RENDER_EXTERNAL_HOSTNAME'])
frontend_origins = {value.strip().rstrip('/') for value in os.getenv(
    'FRONTEND_ORIGINS', 'http://localhost:5187,http://127.0.0.1:5187').split(',') if value.strip()}
limiter = Limiter(get_remote_address, app=app, headers_enabled=True, default_limits=[],
                  storage_uri=os.getenv('RATELIMIT_STORAGE_URI', 'memory://'))
os.environ.setdefault('PUBLIC_FEED_KEYS', 'phishing_database')
feed_store = FeedStore()
reputation_client = ReputationClient()


def read_report():
    try:
        return json.loads((ROOT / 'models/evaluation.json').read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}


def load_model():
    path = ROOT / 'models' / f'{MODEL_NAME}.joblib'
    if not path.exists():
        return None
    manifest = json.loads((ROOT / 'models/manifest.json').read_text(encoding='utf-8'))
    if hashlib.sha256(path.read_bytes()).hexdigest() != manifest['models'][MODEL_NAME]['sha256']:
        raise ValueError('Model checksum mismatch.')
    artifact = joblib.load(path)
    if artifact['features'] != list(FEATURE_NAMES) or list(artifact['model'].classes_) != [0, 1]:
        raise ValueError('Model feature schema or class order is invalid.')
    if not 0 <= artifact['threshold'] <= 1.000000000000001 or not 0 <= artifact.get('model_weight', .8) <= 1:
        raise ValueError('Model threshold or weight is invalid.')
    return artifact


artifact = load_model()


def origin_tuple(value):
    try:
        parts = urlsplit(value)
        if (parts.scheme not in ('http', 'https') or not parts.hostname or parts.username is not None
                or parts.password is not None or parts.path not in ('', '/') or parts.query or parts.fragment):
            return None
        return parts.scheme, parts.hostname.lower(), parts.port or (443 if parts.scheme == 'https' else 80)
    except ValueError:
        return None


@app.before_request
def check_origin():
    if request.method == 'POST':
        origin = request.headers.get('Origin')
        site = request.headers.get('Sec-Fetch-Site')
        invalid = site != 'same-origin' if origin == 'null' else bool(origin) and origin_tuple(origin) != origin_tuple(request.host_url)
        if origin not in frontend_origins and (invalid or site == 'cross-site'):
            return jsonify(error='Cross-site submissions are not allowed.'), 403


@app.after_request
def response_headers(response):
    origin = request.headers.get('Origin')
    if origin in frontend_origins and request.path.startswith('/api/'):
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        response.vary.add('Origin')
    response.headers.update({'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
                             'Referrer-Policy': 'same-origin', 'X-Frame-Options': 'DENY',
                             'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'"})
    if app.config.get('SERVE_LOCAL_FRONTEND') and request.path in ('/', '/app.js', '/style.css'):
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    return response


def predict(value, consent=False):
    if artifact is None:
        return {'error': 'Model unavailable. Train the models and restart the backend.'}, 503
    started = perf_counter()
    try:
        result = analyze(value, artifact)
        feed = feed_store.lookup(value)
        reputation = reputation_client.lookup(result['url'], consent=consent)
        evidence = feed if feed['status'] == 'match' else reputation
        result = combine_evidence(result, evidence)
        result.update(public_feeds=feed, external_reputation=reputation)
        if feed['status'] == 'match':
            result['verification'] = 'Exact URL reported in a downloaded public phishing feed'
        elif reputation['status'] not in ('match', 'no_match'):
            result['verification'] = ('No exact match in the available public feeds' if feed['status'] == 'not_listed'
                                      else 'Public-feed check incomplete or unavailable')
        if feed['status'] == 'stale_match' and result['risk'] in ('Low', 'Unknown'):
            result.update(prediction='Needs review', risk='Medium', evidence='Expired feed match; refresh required')
    except ValueError as error:
        return {'error': str(error)}, 400
    result['latency_ms'] = round((perf_counter() - started) * 1000, 2)
    return result, 200


@app.get('/')
def index():
    return jsonify(name='LinkGuard API', health='/health', predict='/api/predict')


@app.post('/api/predict')
@limiter.limit('30 per minute;300 per hour')
def api_predict():
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or type(body.get('consent', False)) is not bool:
        return jsonify(error='Send a JSON object with url and an optional boolean consent.'), 400
    result, status = predict(body.get('url'), body.get('consent', False))
    return jsonify(result), status


@app.get('/api/status')
def api_status():
    return jsonify(model_ready=artifact is not None, reputation_configured=bool(reputation_client.api_key),
                   public_feeds=feed_store.status())


@app.get('/health')
def health():
    return jsonify(status='ready' if artifact else 'model_missing', model_name=artifact['model_name'] if artifact else None,
                   model_version=artifact['trained_at'] if artifact else None, production_validated=False,
                   public_feeds=feed_store.status()), 200 if artifact else 503


@app.get('/api/models')
def api_models():
    report = read_report()
    if not artifact or report.get('trained_at') != artifact['trained_at']:
        return jsonify(error='No evaluation report for the active model.'), 503
    return jsonify(selected_model=MODEL_NAME, model_version=artifact['trained_at'], models=report['models'])


@app.get('/evaluation')
def evaluation():
    report = read_report()
    if not artifact or report.get('trained_at') != artifact['trained_at']:
        return jsonify(error='No evaluation report for the active model.'), 503
    return jsonify(report)


@app.errorhandler(HTTPException)
def http_error(error):
    message = {413: 'Input is too large.', 429: 'Too many checks. Wait before trying again.'}.get(error.code, error.description)
    return jsonify(error=message), error.code


@app.errorhandler(500)
def server_error(error):
    return jsonify(error='Analysis is temporarily unavailable. Please try again.'), 500


def refresh_feeds():
    logger = logging.getLogger(__name__)
    while True:
        started = perf_counter()
        logger.info('Public-feed refresh started')
        try:
            for result in feed_store.refresh():
                logger.info('Public-feed refresh source=%s status=%s indicators=%s elapsed_seconds=%.1f',
                            result['source'], result['status'], result.get('indicator_count', 0),
                            perf_counter()-started)
        except Exception:
            logger.exception('Feed refresh failed; previous snapshot retained.')
        Event().wait(12 * 3600)


if __name__ == '__main__':
    from waitress import serve
    logging.basicConfig(level=logging.INFO)
    if os.getenv('REFRESH_FEEDS', '1') == '1':
        Thread(target=refresh_feeds, daemon=True).start()
    serve(app, host=os.getenv('HOST', '127.0.0.1'), port=int(os.getenv('PORT', '5000')),
          threads=4, max_request_body_size=16 * 1024, channel_timeout=30)
