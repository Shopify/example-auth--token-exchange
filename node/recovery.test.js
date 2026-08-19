// Recovery tests for the Node.js token-exchange sample.
//
// Every scenario injects a failure — a revoked access token, a dead refresh
// token, a stale ID token — and then asserts what the app ends up doing about
// it, by driving the whole loop against a fake Shopify. That matters because
// this sample once answered a rejected access token with a 401 and the
// X-Shopify-Retry-Invalid-Session-Request header, which looks correct one
// response at a time: App Bridge fetches a fresh ID token and replays the
// request, which then finds no stored token and fails again. Only an assertion
// that the merchant's request succeeds can tell those two apart.
//
// The Python port has the same scenarios in the same order, so a defect in one
// language shows up as a diff between the two suites.
//
// Run with: npm test

import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';

const CLIENT_ID = 'test-client-id';
// At least 32 bytes, like a real client secret.
const CLIENT_SECRET = 'test-client-secret-0123456789abcdef';
const USER_SUB = '4242';
const BASE = 'http://127.0.0.1:3000';

// The test drives the app over HTTP, so keep a handle on the real fetch before
// the fake replaces the global one.
const realFetch = globalThis.fetch;

// Set credentials before importing the app: it reads process.env at import time,
// and dotenv doesn't overwrite variables that are already set, so a developer's
// real node/.env can't leak into a test run.
process.env.SHOPIFY_CLIENT_ID = CLIENT_ID;
process.env.SHOPIFY_CLIENT_SECRET = CLIENT_SECRET;
process.env.REFRESH_TASK_SECRET = 'test-refresh-secret';

// ---------------------------------------------------------------------------
// A fake Shopify, so failures can be injected on demand
// ---------------------------------------------------------------------------

const shopify = {
  // Access tokens Shopify still accepts. Removing one simulates a revoked token
  // or an app whose access scopes changed.
  liveAccessTokens: new Set(),
  liveRefreshTokens: new Set(),
  // When false, a token exchange still succeeds but returns a token Shopify
  // rejects: the "recovery didn't help" case.
  mintedTokensWork: true,
  // Status for the token endpoint. 400 means the ID token is stale.
  exchangeStatus: 200,
  // Status for the refresh grant. 429 and 5xx are transient; any other non-OK
  // status is not, and must not be retried.
  refreshStatus: 200,
  // Status for the GraphQL Admin API when the token is accepted.
  apiStatus: 200,
  expiresIn: 86_400,
  minted: [],
  calls: [],
};

function resetShopify() {
  shopify.liveAccessTokens.clear();
  shopify.liveRefreshTokens.clear();
  shopify.mintedTokensWork = true;
  shopify.exchangeStatus = 200;
  shopify.refreshStatus = 200;
  shopify.apiStatus = 200;
  shopify.expiresIn = 86_400;
  shopify.minted = [];
  shopify.calls = [];
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {'Content-Type': 'application/json'},
  });
}

function mintAccessToken(kind) {
  const token = `${kind}-${shopify.minted.length + 1}`;
  shopify.minted.push({kind, token});
  if (shopify.mintedTokensWork) shopify.liveAccessTokens.add(token);
  return token;
}

function mintRefreshToken() {
  const token = `refresh-${shopify.minted.length}`;
  shopify.liveRefreshTokens.add(token);
  return token;
}

globalThis.fetch = async (url, options = {}) => {
  const {pathname} = new URL(url);

  if (pathname === '/admin/oauth/access_token') {
    const form = Object.fromEntries(new URLSearchParams(String(options.body)));

    if (form.grant_type.endsWith('token-exchange')) {
      const online = form.requested_token_type.includes('online');
      shopify.calls.push({
        type: 'exchange',
        online,
        expiring: form.expiring,
        subjectToken: form.subject_token,
      });

      if (shopify.exchangeStatus !== 200) {
        return json({error: 'invalid_subject_token'}, shopify.exchangeStatus);
      }

      const body = {
        access_token: mintAccessToken(online ? 'online' : 'offline'),
        scope: 'read_products',
        expires_in: shopify.expiresIn,
      };
      if (!online) {
        body.refresh_token = mintRefreshToken();
        body.refresh_token_expires_in = 7_776_000;
      }
      return json(body);
    }

    if (form.grant_type === 'refresh_token') {
      shopify.calls.push({type: 'refresh', refreshToken: form.refresh_token});
      if (shopify.refreshStatus !== 200) {
        return json({error: 'invalid_request'}, shopify.refreshStatus);
      }
      if (!shopify.liveRefreshTokens.has(form.refresh_token)) {
        return json({error: 'invalid_grant'}, 401);
      }
      // A refresh token is single use.
      shopify.liveRefreshTokens.delete(form.refresh_token);
      return json({
        access_token: mintAccessToken('offline'),
        refresh_token: mintRefreshToken(),
        expires_in: shopify.expiresIn,
      });
    }

    throw new Error(`Unexpected grant_type: ${form.grant_type}`);
  }

  if (pathname.startsWith('/admin/api/')) {
    const token = options.headers['X-Shopify-Access-Token'];
    shopify.calls.push({type: 'graphql', token});
    if (!shopify.liveAccessTokens.has(token)) {
      return json({errors: [{message: 'Invalid API key or access token'}]}, 401);
    }
    if (shopify.apiStatus !== 200) {
      return json({errors: [{message: 'Throttled'}]}, shopify.apiStatus);
    }
    return json({data: {shop: {name: 'Test Shop'}}});
  }

  throw new Error(`Unexpected request: ${url}`);
};

// ---------------------------------------------------------------------------
// Driving the app
// ---------------------------------------------------------------------------

// The token store is keyed by shop, so giving every scenario its own shop
// isolates it without needing a reset hook in the sample.
let shopCounter = 0;
function freshShop() {
  return `recovery-${++shopCounter}.myshopify.com`;
}

// `sub` identifies the staff member. Override it to act as a second user in the
// same shop, which is how the per-user authorization scenarios are written.
function idTokenFor(shop, sub = USER_SUB) {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      iss: `https://${shop}/admin`,
      dest: `https://${shop}`,
      aud: CLIENT_ID,
      sub,
      exp: now + 60,
      nbf: now - 10,
    },
    CLIENT_SECRET,
  );
}

async function call(method, path, shop, sub = USER_SUB) {
  const response = await realFetch(`${BASE}${path}`, {
    method,
    headers: {Authorization: `Bearer ${idTokenFor(shop, sub)}`},
  });
  return {
    status: response.status,
    retryHeader: response.headers.get('X-Shopify-Retry-Invalid-Session-Request'),
    body: await response.json(),
  };
}

// POST /refresh is the background-job entry point, so it authenticates with the
// shared secret and takes the shop in the body rather than from an ID token.
async function callRefresh(shop) {
  const response = await realFetch(`${BASE}/refresh`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Refresh-Secret': 'test-refresh-secret',
    },
    body: JSON.stringify({shop}),
  });
  return {status: response.status, body: await response.json()};
}

function callsOfType(type) {
  return shopify.calls.filter((entry) => entry.type === type);
}

const scenarios = [];
function scenario(name, run) {
  scenarios.push({name, run});
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

scenario(
  'a revoked offline access token is replaced without the merchant doing anything',
  async () => {
    const shop = freshShop();
    assert.equal((await call('POST', '/exchange/offline', shop)).status, 200);
    const [offline] = shopify.minted;

    // Shopify revokes the token mid-session.
    shopify.liveAccessTokens.delete(offline.token);

    const result = await call('GET', '/api/shop', shop);

    // The whole point: the request the merchant made succeeds.
    assert.equal(result.status, 200);
    assert.deepEqual(result.body, {data: {shop: {name: 'Test Shop'}}});

    const exchanges = callsOfType('exchange');
    assert.equal(exchanges.length, 2, 'the app should re-run token exchange');
    assert.equal(exchanges[1].online, false);
    assert.equal(exchanges[1].expiring, '1');

    const graphql = callsOfType('graphql');
    assert.equal(graphql.length, 2);
    assert.notEqual(
      graphql[1].token,
      offline.token,
      'the retry should use the newly minted token',
    );
  },
);

scenario(
  'a revoked online access token is replaced with another online token',
  async () => {
    const shop = freshShop();
    assert.equal((await call('POST', '/exchange/offline', shop)).status, 200);
    assert.equal((await call('POST', '/exchange/online', shop)).status, 200);
    const [offline, online] = shopify.minted;

    // Only this staff member's online token is revoked.
    shopify.liveAccessTokens.delete(online.token);

    const result = await call('GET', '/api/shop', shop);
    assert.equal(result.status, 200);

    const exchanges = callsOfType('exchange');
    assert.equal(exchanges.length, 3);
    assert.equal(
      exchanges[2].online,
      true,
      'recovery should re-mint the kind of token that was rejected',
    );
    assert.equal(
      exchanges[2].expiring,
      undefined,
      'expiring applies only to offline tokens',
    );

    // The shop-wide offline token is untouched: eviction is keyed by staff member.
    assert.ok(shopify.liveAccessTokens.has(offline.token));
  },
);

scenario(
  'a second staff member gets their own online token, never the offline one',
  async () => {
    const shop = freshShop();
    assert.equal((await call('POST', '/exchange/offline', shop)).status, 200);
    assert.equal((await call('POST', '/exchange/online', shop)).status, 200);
    const [offline] = shopify.minted;

    // A different staff member opens the app. They have a valid ID token and no
    // online token of their own, which is the condition the old
    // `tokenStore[onlineKey] ?? tokenStore[shop]` fallback resolved by handing
    // them the shop-wide offline token and its full app scopes.
    const OTHER_SUB = '9999';
    const result = await call('GET', '/api/shop', shop, OTHER_SUB);
    assert.equal(result.status, 200);

    const exchanges = callsOfType('exchange');
    assert.equal(exchanges.length, 3, 'the app should mint a token for this user');
    assert.equal(
      exchanges[2].online,
      true,
      'a per-user app must mint an online token, not reuse the offline one',
    );

    const graphql = callsOfType('graphql');
    assert.equal(graphql.length, 1);
    assert.notEqual(
      graphql[0].token,
      offline.token,
      "the second staff member's request must not go out under the offline token",
    );
    assert.equal(
      graphql[0].token,
      shopify.minted.at(-1).token,
      'it should use the token just minted for this staff member',
    );
  },
);

scenario(
  'a replacement token that Shopify also rejects stops after one retry',
  async () => {
    const shop = freshShop();
    assert.equal((await call('POST', '/exchange/offline', shop)).status, 200);

    // Nothing this app can mint will work now.
    shopify.liveAccessTokens.clear();
    shopify.mintedTokensWork = false;

    const result = await call('GET', '/api/shop', shop);

    assert.equal(result.status, 401);
    assert.deepEqual(result.body, {error: 'reauthenticate'});
    assert.equal(
      result.retryHeader,
      null,
      'a fresh ID token cannot fix this, so do not ask App Bridge for one',
    );

    assert.equal(
      callsOfType('exchange').length,
      2,
      'exactly one recovery attempt, not a loop',
    );
    assert.equal(callsOfType('graphql').length, 2);
  },
);

scenario(
  'a stale ID token during recovery asks App Bridge for a fresh one',
  async () => {
    const shop = freshShop();
    assert.equal((await call('POST', '/exchange/offline', shop)).status, 200);
    shopify.liveAccessTokens.clear();
    shopify.exchangeStatus = 400;

    const result = await call('GET', '/api/shop', shop);

    assert.equal(result.status, 401);
    assert.deepEqual(result.body, {error: 'Invalid ID token'});
    assert.equal(
      result.retryHeader,
      '1',
      'here a fresh ID token does fix it, so the retry header belongs',
    );
  },
);

scenario(
  'a failing token endpoint during recovery is reported as a server error',
  async () => {
    const shop = freshShop();
    assert.equal((await call('POST', '/exchange/offline', shop)).status, 200);
    shopify.liveAccessTokens.clear();
    shopify.exchangeStatus = 500;

    const result = await call('GET', '/api/shop', shop);

    assert.equal(result.status, 502);
    assert.deepEqual(result.body, {error: 'Token exchange failed'});
    assert.equal(result.retryHeader, null);
  },
);

scenario(
  'an offline token close to expiry is refreshed before the API call',
  async () => {
    const shop = freshShop();
    shopify.expiresIn = 30;
    assert.equal((await call('POST', '/exchange/offline', shop)).status, 200);

    const result = await call('GET', '/api/shop', shop);
    assert.equal(result.status, 200);

    assert.equal(callsOfType('refresh').length, 1);
    assert.equal(
      callsOfType('exchange').length,
      1,
      'the refresh token did the job, so no token exchange was needed',
    );

    const graphql = callsOfType('graphql');
    assert.equal(graphql.length, 1, 'the refreshed token should work first time');
    assert.equal(graphql[0].token, shopify.minted.at(-1).token);
  },
);

scenario(
  'a dead refresh token tells the client to reauthenticate, with no retry header',
  async () => {
    const shop = freshShop();
    shopify.expiresIn = 30;
    assert.equal((await call('POST', '/exchange/offline', shop)).status, 200);

    // The refresh token is expired, revoked, or the app was uninstalled.
    shopify.liveRefreshTokens.clear();

    const result = await call('GET', '/api/shop', shop);

    assert.equal(result.status, 401);
    assert.deepEqual(result.body, {error: 'reauthenticate'});
    assert.equal(result.retryHeader, null);
    assert.equal(
      callsOfType('graphql').length,
      0,
      'do not send a token the app already knows is dead',
    );
  },
);

scenario(
  'an error status from Shopify is forwarded, not reported as success',
  async () => {
    const shop = freshShop();
    assert.equal((await call('POST', '/exchange/offline', shop)).status, 200);

    // The token is fine; the request is throttled.
    shopify.apiStatus = 429;

    const result = await call('GET', '/api/shop', shop);

    assert.equal(result.status, 429, 'a throttled request is not a successful one');
    assert.equal(
      callsOfType('exchange').length,
      1,
      'a rate limit is not a credential problem, so do not re-mint',
    );
  },
);

scenario(
  'a non-transient refresh failure at expiry is surfaced, not retried',
  async () => {
    const shop = freshShop();
    shopify.expiresIn = 30;
    assert.equal((await call('POST', '/exchange/offline', shop)).status, 200);

    // A malformed request or bad client credentials. Unlike a 5xx, waiting
    // changes nothing: the identical request returns the identical response.
    shopify.refreshStatus = 400;

    const result = await call('GET', '/api/shop', shop);

    assert.equal(
      result.status,
      502,
      'a 400 from the token endpoint is not a "try again later" condition',
    );
    assert.deepEqual(result.body, {error: 'Token refresh rejected'});
    assert.equal(
      callsOfType('graphql').length,
      0,
      'the refresh failed, so the about-to-expire token must not go out',
    );

    // The same route still treats a server fault as retryable, so the narrowing
    // didn't collapse the two cases into one.
    shopify.refreshStatus = 503;
    const transient = await call('GET', '/api/shop', shop);
    assert.equal(transient.status, 503);
    assert.deepEqual(transient.body, {error: 'Token refresh failed, try again'});
  },
);

scenario(
  'POST /refresh separates a non-transient failure from a retryable one',
  async () => {
    const shop = freshShop();
    assert.equal((await call('POST', '/exchange/offline', shop)).status, 200);

    // Bad client credentials or a malformed request. A background job reading
    // "try again" here would retry on every run, forever.
    shopify.refreshStatus = 400;
    const rejected = await callRefresh(shop);
    assert.notEqual(rejected.status, 200, 'a rejected refresh is not a success');
    assert.deepEqual(rejected.body, {error: 'Token refresh rejected'});

    // A server fault is still transient, so the caller is told to come back.
    shopify.refreshStatus = 503;
    const transient = await callRefresh(shop);
    assert.deepEqual(transient.body, {error: 'Token refresh failed'});
  },
);

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

// index.js calls app.listen() at import and exports no handle to close, so this
// file runs the scenarios itself and exits explicitly rather than leaving a
// listener holding the event loop open.
await import('./index.js');
await waitForServer();

let failures = 0;
for (const {name, run} of scenarios) {
  resetShopify();
  try {
    await run();
    console.log(`  ok    ${name}`);
  } catch (error) {
    failures += 1;
    console.error(`  FAIL  ${name}`);
    console.error(`        ${error.message.split('\n').join('\n        ')}`);
  }
}

console.log(
  `\n${scenarios.length - failures}/${scenarios.length} recovery scenarios passed`,
);
process.exit(failures > 0 ? 1 : 0);

async function waitForServer() {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      await realFetch(BASE, {method: 'GET'});
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  throw new Error(`Server never came up on ${BASE}`);
}
