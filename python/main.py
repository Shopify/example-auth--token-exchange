# python/main.py
import hmac
import os
import time
from pathlib import Path
from urllib.parse import urlparse

import jwt
import requests
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request

load_dotenv()

# [START token-exchange.config]
SHOPIFY_CLIENT_ID = os.environ.get('SHOPIFY_CLIENT_ID')
SHOPIFY_CLIENT_SECRET = os.environ.get('SHOPIFY_CLIENT_SECRET')
REFRESH_TASK_SECRET = os.environ.get('REFRESH_TASK_SECRET')
# [END token-exchange.config]

# The frontend lives at the repo root because it's identical whatever language
# your backend is written in — App Bridge runs in the browser.
PUBLIC_DIR = Path(__file__).resolve().parent.parent / 'public'

app = Flask(__name__, static_folder=str(PUBLIC_DIR), static_url_path='')


# Inject the App Bridge API key (your client ID) into index.html before serving
# it. Serving the file as-is would leave the literal %SHOPIFY_API_KEY%
# placeholder in the page — so App Bridge never initializes.
@app.get('/')
@app.get('/index.html')
def index():
    html = (PUBLIC_DIR / 'index.html').read_text(encoding='utf-8').replace(
        '%SHOPIFY_API_KEY%', SHOPIFY_CLIENT_ID or ''
    )
    return Response(html, mimetype='text/html')


# In-memory token store (use a persistent session store in production)
token_store = {}


# A valid expiring-token response includes expires_in (seconds until the access
# token expires). Return None when it's absent or non-positive: treat the token
# as non-expiring and never refresh it. Storing time.time() instead would make
# the next request refresh a token that has no refresh_token — a permanent 401.
def expires_at_from(expires_in):
    try:
        seconds = int(expires_in)
    except (TypeError, ValueError):
        return None
    return time.time() + seconds if seconds > 0 else None


# [START token-exchange.validate-id-token]
def validate_id_token(id_token):
    payload = jwt.decode(
        id_token,
        SHOPIFY_CLIENT_SECRET,
        algorithms=['HS256'],
        audience=SHOPIFY_CLIENT_ID,
    )

    issuer_host = urlparse(payload['iss']).hostname
    dest_host = urlparse(payload['dest']).hostname
    if issuer_host != dest_host:
        raise ValueError('Token issuer and destination do not match')

    return payload
# [END token-exchange.validate-id-token]


# Background callers (webhooks, scheduled jobs) have no session to produce an
# ID token, so they authenticate with a shared secret that only your own
# backend and schedulers know. It's sent in the `X-Refresh-Secret` header.
def is_authorized_task():
    provided = request.headers.get('X-Refresh-Secret', '')
    if not REFRESH_TASK_SECRET or not provided:
        return False
    # compare_digest is constant-time and handles a length mismatch safely.
    return hmac.compare_digest(provided, REFRESH_TASK_SECRET)


# Exchange the stored offline refresh token for a new offline access token.
# The return value tells the caller how to react:
#   'refreshed'   — stored a new access token
#   'reauthorize' — no refresh token, or Shopify returned 401 (the refresh token
#                   is expired, revoked, replayed outside the retry window, or the
#                   app was uninstalled); the merchant must reinstall
#   'retry'       — a transient failure (network, 5xx, 429); safe to retry later
def refresh_offline_token(shop):
    stored = token_store.get(shop)
    if not stored or not stored.get('refresh_token'):
        return 'reauthorize'

    try:
        response = requests.post(
            f'https://{shop}/admin/oauth/access_token',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data={
                'grant_type': 'refresh_token',
                'client_id': SHOPIFY_CLIENT_ID,
                'client_secret': SHOPIFY_CLIENT_SECRET,
                'refresh_token': stored['refresh_token'],
            },
            timeout=30,
        )
    except requests.RequestException:
        # Network failure or timeout: the refresh token is untouched, so retrying
        # later with the same one is safe.
        return 'retry'

    if response.status_code == 401:
        token_store.pop(shop, None)
        return 'reauthorize'
    if not response.ok:
        return 'retry'

    data = response.json()
    token_store[shop] = {
        'access_token': data['access_token'],
        'refresh_token': data.get('refresh_token'),
        'expires_at': expires_at_from(data.get('expires_in')),
    }
    return 'refreshed'


# [START token-exchange.exchange-offline]
@app.post('/exchange/offline')
def exchange_offline():
    id_token = (request.headers.get('Authorization') or '').removeprefix('Bearer ')
    try:
        payload = validate_id_token(id_token)
    except (jwt.PyJWTError, ValueError, KeyError):
        # Signal App Bridge to fetch a fresh ID token and retry this request once.
        error = jsonify({'error': 'Invalid ID token'})
        error.headers['X-Shopify-Retry-Invalid-Session-Request'] = '1'
        return error, 401

    shop = urlparse(payload['dest']).hostname

    response = requests.post(
        f'https://{shop}/admin/oauth/access_token',
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        data={
            'client_id': SHOPIFY_CLIENT_ID,
            'client_secret': SHOPIFY_CLIENT_SECRET,
            'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token': id_token,
            'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
            'requested_token_type':
                'urn:shopify:params:oauth:token-type:offline-access-token',
            'expiring': '1',
        },
        timeout=30,
    )

    # Shopify returns 400 when the ID token is expired or otherwise invalid. ID
    # tokens live about a minute, so that's a routine client condition, not a server
    # fault — answer it like a local validation failure so App Bridge fetches a fresh
    # token and retries. Returning 502 would say the opposite: don't bother retrying.
    if response.status_code == 400:
        error = jsonify({'error': 'Invalid ID token'})
        error.headers['X-Shopify-Retry-Invalid-Session-Request'] = '1'
        return error, 401

    if not response.ok:
        return jsonify({'error': 'Token exchange failed'}), 502

    data = response.json()

    # Store tokens server-side — never send them to the browser. Track expiry so
    # requests can refresh the offline token before it lapses.
    token_store[shop] = {
        'access_token': data['access_token'],
        'refresh_token': data.get('refresh_token'),
        'expires_at': expires_at_from(data.get('expires_in')),
    }

    return jsonify({'scope': data.get('scope')})
# [END token-exchange.exchange-offline]


# [START token-exchange.exchange-online]
@app.post('/exchange/online')
def exchange_online():
    id_token = (request.headers.get('Authorization') or '').removeprefix('Bearer ')
    try:
        payload = validate_id_token(id_token)
    except (jwt.PyJWTError, ValueError, KeyError):
        # Signal App Bridge to fetch a fresh ID token and retry this request once.
        error = jsonify({'error': 'Invalid ID token'})
        error.headers['X-Shopify-Retry-Invalid-Session-Request'] = '1'
        return error, 401

    shop = urlparse(payload['dest']).hostname

    response = requests.post(
        f'https://{shop}/admin/oauth/access_token',
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        data={
            'client_id': SHOPIFY_CLIENT_ID,
            'client_secret': SHOPIFY_CLIENT_SECRET,
            'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token': id_token,
            'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
            'requested_token_type':
                'urn:shopify:params:oauth:token-type:online-access-token',
        },
        timeout=30,
    )

    # Same as the offline route: a 400 means the ID token is stale, which a fresh
    # one fixes. Don't dress a retryable condition up as a server error.
    if response.status_code == 400:
        error = jsonify({'error': 'Invalid ID token'})
        error.headers['X-Shopify-Retry-Invalid-Session-Request'] = '1'
        return error, 401

    if not response.ok:
        return jsonify({'error': 'Token exchange failed'}), 502

    data = response.json()

    # Online tokens are scoped to the staff member who authorized them, so key
    # them by user (the ID token's `sub`) — not just by shop. Storing under a
    # shop-only key would let one staff member's token overwrite another's.
    # Track expiry so a lapsed token is dropped rather than sent.
    token_store[f'{shop}:online:{payload["sub"]}'] = {
        'access_token': data['access_token'],
        'expires_at': expires_at_from(data.get('expires_in')),
    }

    return jsonify({'scope': data.get('scope')})
# [END token-exchange.exchange-online]


# [START token-exchange.make-request]
# Re-run token exchange for a token Shopify rejected, using the ID token that
# came with the current request. Same request as /exchange/offline and
# /exchange/online, minting whichever kind was rejected. The return value tells
# the caller how to react:
#   'minted'           — stored a new access token
#   'invalid_id_token' — Shopify returned 400; the ID token is stale, and a fresh
#                        one fixes it
#   'failed'           — anything else; retrying with the same inputs won't help
def remint_access_token(id_token, shop, sub, online):
    data = {
        'client_id': SHOPIFY_CLIENT_ID,
        'client_secret': SHOPIFY_CLIENT_SECRET,
        'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
        'subject_token': id_token,
        'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
        'requested_token_type': (
            'urn:shopify:params:oauth:token-type:online-access-token'
            if online
            else 'urn:shopify:params:oauth:token-type:offline-access-token'
        ),
    }
    # `expiring` only applies to offline tokens. An online token already expires
    # with the staff member's session.
    if not online:
        data['expiring'] = '1'

    try:
        response = requests.post(
            f'https://{shop}/admin/oauth/access_token',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data=data,
            timeout=30,
        )
    except requests.RequestException:
        return 'failed'

    if response.status_code == 400:
        return 'invalid_id_token'
    if not response.ok:
        return 'failed'

    body = response.json()

    if online:
        token_store[f'{shop}:online:{sub}'] = {
            'access_token': body['access_token'],
            'expires_at': expires_at_from(body.get('expires_in')),
        }
    else:
        token_store[shop] = {
            'access_token': body['access_token'],
            'refresh_token': body.get('refresh_token'),
            'expires_at': expires_at_from(body.get('expires_in')),
        }

    return 'minted'


@app.get('/api/shop')
def api_shop():
    id_token = (request.headers.get('Authorization') or '').removeprefix('Bearer ')
    try:
        payload = validate_id_token(id_token)
    except (jwt.PyJWTError, ValueError, KeyError):
        # Signal App Bridge to fetch a fresh ID token and retry this request once.
        error = jsonify({'error': 'Invalid ID token'})
        error.headers['X-Shopify-Retry-Invalid-Session-Request'] = '1'
        return error, 401

    shop = urlparse(payload['dest']).hostname
    online_key = f'{shop}:online:{payload["sub"]}'

    # Drop an expired online token so we fall back to the offline token instead of
    # sending a dead credential. Online tokens can't be refreshed — a new one is
    # minted from a fresh ID token via /exchange/online.
    online = token_store.get(online_key)
    if online and online.get('expires_at') is not None and online['expires_at'] <= time.time():
        token_store.pop(online_key, None)

    # Prefer this staff member's online token so the request runs with their
    # permissions; fall back to the shop-wide offline token for shop-level access.
    using_online = online_key in token_store

    # Only the offline token is refreshable (online tokens are re-minted from a
    # fresh ID token via /exchange/online). Refresh it ~60 seconds before it
    # expires — but only when we're about to use it, so a still-valid online token
    # isn't blocked by a failed offline refresh.
    if not using_online:
        offline = token_store.get(shop)
        if (
            offline
            and offline.get('expires_at') is not None
            and time.time() >= offline['expires_at'] - 60
        ):
            result = refresh_offline_token(shop)
            if result == 'reauthorize':
                # No retry header here: the offline refresh token is dead, and a
                # fresh ID token can't revive it. The client must re-run
                # /exchange/offline (or reinstall) rather than retry this request
                # into another 401.
                return jsonify({'error': 'reauthenticate'}), 401
            if result == 'retry':
                return jsonify({'error': 'Token refresh failed, try again'}), 503

    stored = token_store.get(online_key) or token_store.get(shop)
    if not stored:
        return jsonify({'error': 'Not authenticated'}), 401

    def call_admin_api(access_token):
        return requests.post(
            f'https://{shop}/admin/api/2026-04/graphql.json',
            headers={
                'Content-Type': 'application/json',
                'X-Shopify-Access-Token': access_token,
            },
            json={'query': '{ shop { name } }'},
            timeout=30,
        )

    response = call_admin_api(stored['access_token'])

    # Shopify rejected the access token (revoked, or the app's scopes changed).
    # Evict it and mint a replacement with token exchange: this request already
    # carries a validated ID token, so nothing the merchant does is needed.
    #
    # Don't answer this with X-Shopify-Retry-Invalid-Session-Request. That header
    # only makes App Bridge fetch a fresh *ID* token and replay this request — it
    # never re-runs the exchange, so the replay would find no stored token and fail
    # with "Not authenticated". It's the right answer for a rejected ID token, and
    # the wrong one for a rejected access token.
    if response.status_code == 401:
        evict_key = online_key if using_online else shop
        token_store.pop(evict_key, None)

        result = remint_access_token(id_token, shop, payload['sub'], using_online)

        # Only now is the retry header correct: the ID token itself is stale, and a
        # fresh one lets the replayed request mint a token successfully.
        if result == 'invalid_id_token':
            error = jsonify({'error': 'Invalid ID token'})
            error.headers['X-Shopify-Retry-Invalid-Session-Request'] = '1'
            return error, 401
        if result != 'minted':
            return jsonify({'error': 'Token exchange failed'}), 502

        response = call_admin_api(token_store[evict_key]['access_token'])

        # Retry once, not in a loop. A freshly minted token that's also rejected
        # means something is wrong beyond a stale credential, so stop and tell the
        # merchant to reauthorize rather than mint tokens indefinitely.
        if response.status_code == 401:
            token_store.pop(evict_key, None)
            return jsonify({'error': 'reauthenticate'}), 401

    # Forward Shopify's status. Answering a rate limit or an outage with a 200 and
    # an error body in it would tell the client the request succeeded.
    return jsonify(response.json()), response.status_code
# [END token-exchange.make-request]


# [START token-exchange.refresh]
@app.post('/refresh')
def refresh():
    # This endpoint mints a new access token, so authenticate the caller first.
    # Background callers (webhooks, scheduled jobs) have no session to produce an
    # ID token, so they send a shared secret in the `X-Refresh-Secret` header.
    if not is_authorized_task():
        return jsonify({'error': 'Unauthorized'}), 401

    # Background callers supply the shop domain directly, since they have no
    # active session to derive it from an ID token. silent=True returns None
    # instead of raising when the body is missing or isn't JSON, so a malformed
    # request gets the documented 400 rather than a 500.
    body = request.get_json(silent=True) or {}
    shop = body.get('shop')
    if not shop:
        return jsonify({'error': 'Missing shop'}), 400

    # A 401 is terminal (expired, revoked, replayed outside the retry window, or
    # the app was uninstalled): re-authenticate the next time a merchant opens the
    # app. Other failures (network, 5xx, 429) are transient and safe to retry.
    result = refresh_offline_token(shop)
    if result == 'reauthorize':
        return jsonify({'error': 'reauthenticate'}), 401
    if result == 'retry':
        return jsonify({'error': 'Token refresh failed'}), 502

    return jsonify({'success': True})
# [END token-exchange.refresh]


# The routes above let a transport failure or timeout propagate. The request never
# reached Shopify, so nothing was consumed and the caller can try again: 503 says
# that, while the traceback Flask would otherwise return says the app is broken.
@app.errorhandler(requests.RequestException)
def handle_shopify_unreachable(_error):
    return jsonify({'error': 'Could not reach Shopify, try again'}), 503


if __name__ == '__main__':
    # Flask's development server. Use a production WSGI server (gunicorn, uWSGI)
    # when you deploy.
    app.run(port=3000)
