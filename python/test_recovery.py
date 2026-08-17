# Recovery tests for the Python token-exchange sample.
#
# Every scenario injects a failure — a revoked access token, a dead refresh
# token, a stale ID token — and then asserts what the app ends up doing about
# it, by driving the whole loop against a fake Shopify. That matters because
# this sample once answered a rejected access token with a 401 and the
# X-Shopify-Retry-Invalid-Session-Request header, which looks correct one
# response at a time: App Bridge fetches a fresh ID token and replays the
# request, which then finds no stored token and fails again. Only an assertion
# that the merchant's request succeeds can tell those two apart.
#
# The Node.js port has the same scenarios in the same order, so a defect in one
# language shows up as a diff between the two suites.
#
# Run with: python test_recovery.py

import json
import os
import time
from urllib.parse import urlparse

import jwt

CLIENT_ID = 'test-client-id'
# At least 32 bytes, like a real client secret: PyJWT warns below that for HS256.
CLIENT_SECRET = 'test-client-secret-0123456789abcdef'
USER_SUB = '4242'

# Set credentials before importing the app: it reads os.environ at import time,
# and load_dotenv doesn't overwrite variables that are already set, so a
# developer's real python/.env can't leak into a test run.
os.environ['SHOPIFY_CLIENT_ID'] = CLIENT_ID
os.environ['SHOPIFY_CLIENT_SECRET'] = CLIENT_SECRET
os.environ['REFRESH_TASK_SECRET'] = 'test-refresh-secret'

import main  # noqa: E402


# ---------------------------------------------------------------------------
# A fake Shopify, so failures can be injected on demand
# ---------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, body, status_code=200):
        self._body = body
        self.status_code = status_code

    @property
    def ok(self):
        return 200 <= self.status_code < 300

    def json(self):
        return self._body


class FakeShopify:
    def __init__(self):
        self.reset()

    def reset(self):
        # Access tokens Shopify still accepts. Removing one simulates a revoked
        # token or an app whose access scopes changed.
        self.live_access_tokens = set()
        self.live_refresh_tokens = set()
        # When False, a token exchange still succeeds but returns a token
        # Shopify rejects: the "recovery didn't help" case.
        self.minted_tokens_work = True
        # Status for the token endpoint. 400 means the ID token is stale.
        self.exchange_status = 200
        # Status for the GraphQL Admin API when the token is accepted.
        self.api_status = 200
        self.expires_in = 86_400
        self.minted = []
        self.calls = []

    def mint_access_token(self, kind):
        token = f'{kind}-{len(self.minted) + 1}'
        self.minted.append({'kind': kind, 'token': token})
        if self.minted_tokens_work:
            self.live_access_tokens.add(token)
        return token

    def mint_refresh_token(self):
        token = f'refresh-{len(self.minted)}'
        self.live_refresh_tokens.add(token)
        return token

    def calls_of_type(self, call_type):
        return [call for call in self.calls if call['type'] == call_type]

    # Stands in for requests.post. The sample only ever POSTs, to the token
    # endpoint and to the GraphQL Admin API.
    def post(self, url, headers=None, data=None, json=None, timeout=None):
        path = urlparse(url).path

        if path == '/admin/oauth/access_token':
            form = {key: value for key, value in (data or {}).items()}
            grant_type = form['grant_type']

            if grant_type.endswith('token-exchange'):
                online = 'online' in form['requested_token_type']
                self.calls.append(
                    {
                        'type': 'exchange',
                        'online': online,
                        'expiring': form.get('expiring'),
                        'subject_token': form['subject_token'],
                    }
                )

                if self.exchange_status != 200:
                    return FakeResponse(
                        {'error': 'invalid_subject_token'}, self.exchange_status
                    )

                body = {
                    'access_token': self.mint_access_token(
                        'online' if online else 'offline'
                    ),
                    'scope': 'read_products',
                    'expires_in': self.expires_in,
                }
                if not online:
                    body['refresh_token'] = self.mint_refresh_token()
                    body['refresh_token_expires_in'] = 7_776_000
                return FakeResponse(body)

            if grant_type == 'refresh_token':
                self.calls.append(
                    {'type': 'refresh', 'refresh_token': form['refresh_token']}
                )
                if form['refresh_token'] not in self.live_refresh_tokens:
                    return FakeResponse({'error': 'invalid_grant'}, 401)
                # A refresh token is single use.
                self.live_refresh_tokens.discard(form['refresh_token'])
                return FakeResponse(
                    {
                        'access_token': self.mint_access_token('offline'),
                        'refresh_token': self.mint_refresh_token(),
                        'expires_in': self.expires_in,
                    }
                )

            raise AssertionError(f'Unexpected grant_type: {grant_type}')

        if path.startswith('/admin/api/'):
            token = headers['X-Shopify-Access-Token']
            self.calls.append({'type': 'graphql', 'token': token})
            if token not in self.live_access_tokens:
                return FakeResponse(
                    {'errors': [{'message': 'Invalid API key or access token'}]}, 401
                )
            if self.api_status != 200:
                return FakeResponse(
                    {'errors': [{'message': 'Throttled'}]}, self.api_status
                )
            return FakeResponse({'data': {'shop': {'name': 'Test Shop'}}})

        raise AssertionError(f'Unexpected request: {url}')


shopify = FakeShopify()
main.requests.post = shopify.post


# ---------------------------------------------------------------------------
# Driving the app
# ---------------------------------------------------------------------------

client = main.app.test_client()

# The token store is keyed by shop, so giving every scenario its own shop
# isolates it without needing a reset hook in the sample.
_shop_counter = 0


def fresh_shop():
    global _shop_counter
    _shop_counter += 1
    return f'recovery-{_shop_counter}.myshopify.com'


def id_token_for(shop):
    now = int(time.time())
    return jwt.encode(
        {
            'iss': f'https://{shop}/admin',
            'dest': f'https://{shop}',
            'aud': CLIENT_ID,
            'sub': USER_SUB,
            'exp': now + 60,
            'nbf': now - 10,
        },
        CLIENT_SECRET,
        algorithm='HS256',
    )


class Result:
    def __init__(self, response):
        self.status = response.status_code
        self.retry_header = response.headers.get(
            'X-Shopify-Retry-Invalid-Session-Request'
        )
        self.body = json.loads(response.get_data(as_text=True))


def call(method, path, shop):
    response = client.open(
        path,
        method=method,
        headers={'Authorization': f'Bearer {id_token_for(shop)}'},
    )
    return Result(response)


SCENARIOS = []


def scenario(name):
    def register(run):
        SCENARIOS.append((name, run))
        return run

    return register


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------


@scenario(
    'a revoked offline access token is replaced without the merchant doing anything'
)
def revoked_offline_token_recovers():
    shop = fresh_shop()
    assert call('POST', '/exchange/offline', shop).status == 200
    offline = shopify.minted[0]

    # Shopify revokes the token mid-session.
    shopify.live_access_tokens.discard(offline['token'])

    result = call('GET', '/api/shop', shop)

    # The whole point: the request the merchant made succeeds.
    assert result.status == 200, result.status
    assert result.body == {'data': {'shop': {'name': 'Test Shop'}}}, result.body

    exchanges = shopify.calls_of_type('exchange')
    assert len(exchanges) == 2, 'the app should re-run token exchange'
    assert exchanges[1]['online'] is False
    assert exchanges[1]['expiring'] == '1'

    graphql = shopify.calls_of_type('graphql')
    assert len(graphql) == 2
    assert graphql[1]['token'] != offline['token'], (
        'the retry should use the newly minted token'
    )


@scenario('a revoked online access token is replaced with another online token')
def revoked_online_token_recovers_as_online():
    shop = fresh_shop()
    assert call('POST', '/exchange/offline', shop).status == 200
    assert call('POST', '/exchange/online', shop).status == 200
    offline, online = shopify.minted[0], shopify.minted[1]

    # Only this staff member's online token is revoked.
    shopify.live_access_tokens.discard(online['token'])

    result = call('GET', '/api/shop', shop)
    assert result.status == 200, result.status

    exchanges = shopify.calls_of_type('exchange')
    assert len(exchanges) == 3
    assert exchanges[2]['online'] is True, (
        'recovery should re-mint the kind of token that was rejected'
    )
    assert exchanges[2]['expiring'] is None, 'expiring applies only to offline tokens'

    # The shop-wide offline token is untouched: eviction is keyed by staff member.
    assert offline['token'] in shopify.live_access_tokens


@scenario('a replacement token that Shopify also rejects stops after one retry')
def replacement_token_also_rejected():
    shop = fresh_shop()
    assert call('POST', '/exchange/offline', shop).status == 200

    # Nothing this app can mint will work now.
    shopify.live_access_tokens.clear()
    shopify.minted_tokens_work = False

    result = call('GET', '/api/shop', shop)

    assert result.status == 401, result.status
    assert result.body == {'error': 'reauthenticate'}, result.body
    assert result.retry_header is None, (
        'a fresh ID token cannot fix this, so do not ask App Bridge for one'
    )

    assert len(shopify.calls_of_type('exchange')) == 2, (
        'exactly one recovery attempt, not a loop'
    )
    assert len(shopify.calls_of_type('graphql')) == 2


@scenario('a stale ID token during recovery asks App Bridge for a fresh one')
def stale_id_token_during_recovery():
    shop = fresh_shop()
    assert call('POST', '/exchange/offline', shop).status == 200
    shopify.live_access_tokens.clear()
    shopify.exchange_status = 400

    result = call('GET', '/api/shop', shop)

    assert result.status == 401, result.status
    assert result.body == {'error': 'Invalid ID token'}, result.body
    assert result.retry_header == '1', (
        'here a fresh ID token does fix it, so the retry header belongs'
    )


@scenario('a failing token endpoint during recovery is reported as a server error')
def failing_token_endpoint_during_recovery():
    shop = fresh_shop()
    assert call('POST', '/exchange/offline', shop).status == 200
    shopify.live_access_tokens.clear()
    shopify.exchange_status = 500

    result = call('GET', '/api/shop', shop)

    assert result.status == 502, result.status
    assert result.body == {'error': 'Token exchange failed'}, result.body
    assert result.retry_header is None


@scenario('an offline token close to expiry is refreshed before the API call')
def near_expiry_offline_token_refreshes():
    shop = fresh_shop()
    shopify.expires_in = 30
    assert call('POST', '/exchange/offline', shop).status == 200

    result = call('GET', '/api/shop', shop)
    assert result.status == 200, result.status

    assert len(shopify.calls_of_type('refresh')) == 1
    assert len(shopify.calls_of_type('exchange')) == 1, (
        'the refresh token did the job, so no token exchange was needed'
    )

    graphql = shopify.calls_of_type('graphql')
    assert len(graphql) == 1, 'the refreshed token should work first time'
    assert graphql[0]['token'] == shopify.minted[-1]['token']


@scenario('a dead refresh token tells the client to reauthenticate, with no retry header')
def dead_refresh_token():
    shop = fresh_shop()
    shopify.expires_in = 30
    assert call('POST', '/exchange/offline', shop).status == 200

    # The refresh token is expired, revoked, or the app was uninstalled.
    shopify.live_refresh_tokens.clear()

    result = call('GET', '/api/shop', shop)

    assert result.status == 401, result.status
    assert result.body == {'error': 'reauthenticate'}, result.body
    assert result.retry_header is None
    assert len(shopify.calls_of_type('graphql')) == 0, (
        'do not send a token the app already knows is dead'
    )


@scenario('an error status from Shopify is forwarded, not reported as success')
def error_status_is_forwarded():
    shop = fresh_shop()
    assert call('POST', '/exchange/offline', shop).status == 200

    # The token is fine; the request is throttled.
    shopify.api_status = 429

    result = call('GET', '/api/shop', shop)

    assert result.status == 429, 'a throttled request is not a successful one'
    assert len(shopify.calls_of_type('exchange')) == 1, (
        'a rate limit is not a credential problem, so do not re-mint'
    )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run():
    failures = 0
    for name, scenario_fn in SCENARIOS:
        shopify.reset()
        try:
            scenario_fn()
            print(f'  ok    {name}')
        except AssertionError as error:
            failures += 1
            print(f'  FAIL  {name}')
            print(f'        {error}')

    print(f'\n{len(SCENARIOS) - failures}/{len(SCENARIOS)} recovery scenarios passed')
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(run())
