import json
import logging
import os
import re
import threading
import time
from datetime import datetime

import requests
from flask import Flask, Response, jsonify, request
from jose import JWTError, jwt
from prometheus_client import Counter, Gauge, generate_latest, CollectorRegistry, CONTENT_TYPE_LATEST

app = Flask(__name__)

KEYCLOAK_HOST = os.environ.get('KEYCLOAK_HOST', 'keycloak.local')
REALM = os.environ.get('KEYCLOAK_REALM', 'enterprise-zta')
KEYCLOAK_URL = f'https://{KEYCLOAK_HOST}/realms/{REALM}'
JWKS_URL = f'{KEYCLOAK_URL}/protocol/openid-connect/certs'
INTRO_LOG = '/app/logs/access.log'

metrics_registry = CollectorRegistry()
http_requests_total = Counter('rbac_app_http_requests_total', 'Total HTTP requests', ['path'], registry=metrics_registry)
auth_failures = Counter('rbac_app_auth_failures_total', 'Authentication failures', registry=metrics_registry)
user_roles = Gauge('rbac_app_user_roles', 'Number of roles mapped for authenticated users', ['username'], registry=metrics_registry)

# file logger
logger = logging.getLogger('rbac-app')
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler(INTRO_LOG)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(logging.StreamHandler())

cached_jwks = None
last_jwks = 0

ROLE_MAP = {
    'Admin': ['Admin'],
    'Security Analyst': ['Security Analyst'],
    'Developer': ['Developer'],
    'Guest': ['Guest'],
}


class AuthError(Exception):
    pass


def log_request(message: str):
    logger.info(message)


def fetch_jwks():
    global cached_jwks, last_jwks
    if cached_jwks and (time.time() - last_jwks) < 300:
        return cached_jwks
    resp = requests.get(JWKS_URL, timeout=10, verify=False)
    resp.raise_for_status()
    cached_jwks = resp.json()
    last_jwks = time.time()
    return cached_jwks


def validate_token(authorization_header: str):
    if not authorization_header or not authorization_header.startswith('Bearer '):
        raise AuthError('Authorization header missing or invalid')
    token = authorization_header.split(' ', 1)[1]
    jwks = fetch_jwks()
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get('kid')
    key = next((key for key in jwks['keys'] if key['kid'] == kid), None)
    if not key:
        raise AuthError('Unable to find matching JWK')
    try:
        claims = jwt.decode(token, key, algorithms=['RS256'], audience='rbac-app', issuer=KEYCLOAK_URL)
    except JWTError as error:
        raise AuthError(str(error))
    return claims


def require_roles(required_roles):
    def decorator(fn):
        def wrapper(*args, **kwargs):
            try:
                claims = validate_token(request.headers.get('Authorization'))
            except AuthError as err:
                auth_failures.inc()
                log_request(f'auth_fail: {err}')
                return jsonify({'error': 'Unauthorized', 'message': str(err)}), 401
            grant_roles = claims.get('realm_access', {}).get('roles', [])
            user = claims.get('preferred_username', 'anonymous')
            user_roles.labels(username=user).set(len(grant_roles))
            log_request(f'user={user} roles={grant_roles} path={request.path}')
            for role in required_roles:
                if role in grant_roles or 'Admin' in grant_roles:
                    return fn(*args, **kwargs)
            return jsonify({'error': 'Forbidden', 'message': 'Insufficient role'}), 403
        wrapper.__name__ = fn.__name__
        return wrapper
    return decorator


@app.route('/')
def root():
    http_requests_total.labels(path='/').inc()
    log_request('root accessed')
    return jsonify({
        'service': 'RBAC Demo App',
        'endpoints': ['/dashboard', '/logs', '/storage', '/admin']
    })


@app.route('/dashboard')
@require_roles(['Admin', 'Security Analyst'])
def dashboard():
    http_requests_total.labels(path='/dashboard').inc()
    return jsonify({'message': 'Dashboard access granted'})


@app.route('/logs')
@require_roles(['Admin', 'Security Analyst'])
def logs():
    http_requests_total.labels(path='/logs').inc()
    return jsonify({'message': 'Logs access granted'})


@app.route('/storage')
@require_roles(['Admin', 'Security Analyst', 'Developer', 'Guest'])
def storage():
    http_requests_total.labels(path='/storage').inc()
    return jsonify({'message': 'Storage access granted (limited access for guest)'})


@app.route('/admin')
@require_roles(['Admin'])
def admin_panel():
    http_requests_total.labels(path='/admin').inc()
    return jsonify({'message': 'Admin panel access granted'})


@app.route('/metrics')
def metrics():
    return Response(generate_latest(metrics_registry), mimetype=CONTENT_TYPE_LATEST)


@app.errorhandler(500)
def internal_error(error):
    log_request(f'internal_error: {error}')
    return jsonify({'error': 'Internal server error'}), 500


def ensure_log_folder():
    try:
        os.makedirs(os.path.dirname(INTRO_LOG), exist_ok=True)
    except OSError:
        pass


if __name__ == '__main__':
    ensure_log_folder()
    app.run(host='0.0.0.0', port=5000)
