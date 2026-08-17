import 'dotenv/config';
import express from 'express';
import path from 'path';
import {readFileSync} from 'fs';
import {fileURLToPath} from 'url';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json());

// [START token-exchange.config]
const {SHOPIFY_CLIENT_ID, SHOPIFY_CLIENT_SECRET, REFRESH_TASK_SECRET} =
  process.env;
// [END token-exchange.config]

// Inject the App Bridge API key (your client ID) into index.html before serving
// it. express.static would return the file verbatim, leaving the literal
// %SHOPIFY_API_KEY% placeholder in the page — so App Bridge never initializes.
app.get(['/', '/index.html'], (req, res) => {
  const html = readFileSync(
    path.join(__dirname, '..', 'public', 'index.html'),
    'utf8',
  ).replace('%SHOPIFY_API_KEY%', SHOPIFY_CLIENT_ID);
  res.type('html').send(html);
});

app.use(express.static(path.join(__dirname, '..', 'public')));

// In-memory token store (use a persistent session store in production)
const tokenStore = {};

// A valid expiring-token response includes expires_in (seconds until the access
// token expires). Return null when it's absent or non-positive: treat the token
// as non-expiring and never refresh it. Storing Date.now() instead would make
// the next request refresh a token that has no refresh_token — a permanent 401.
function expiresAtFrom(expiresIn) {
  const seconds = Number(expiresIn);
  return seconds > 0 ? Date.now() + seconds * 1000 : null;
}

// Node's fetch has no timeout, so a stalled connection to Shopify would hang a
// request until the client gives up. Give every call a deadline, and tag transport
// failures so callers can tell "Shopify said no" from "we never reached Shopify".
// fetch rejects only on a transport failure or this timeout: every HTTP status,
// including 5xx, resolves and is the caller's to handle.
const SHOPIFY_TIMEOUT_MS = 30_000;

class ShopifyUnreachable extends Error {}

async function shopifyFetch(url, options) {
  try {
    return await fetch(url, {
      ...options,
      signal: AbortSignal.timeout(SHOPIFY_TIMEOUT_MS),
    });
  } catch (cause) {
    throw new ShopifyUnreachable(`Could not reach ${new URL(url).hostname}`, {
      cause,
    });
  }
}

// [START token-exchange.validate-id-token]
function validateIdToken(idToken) {
  const payload = jwt.verify(idToken, SHOPIFY_CLIENT_SECRET, {
    algorithms: ['HS256'],
    audience: SHOPIFY_CLIENT_ID,
  });

  const issuerHost = new URL(payload.iss).hostname;
  const destHost = new URL(payload.dest).hostname;
  if (issuerHost !== destHost) {
    throw new Error('Token issuer and destination do not match');
  }

  return payload;
}
// [END token-exchange.validate-id-token]

// Background callers (webhooks, scheduled jobs) have no session to produce an
// ID token, so they authenticate with a shared secret that only your own
// backend and schedulers know. It's sent in the `X-Refresh-Secret` header.
function isAuthorizedTask(req) {
  const provided = req.get('X-Refresh-Secret') ?? '';
  if (!REFRESH_TASK_SECRET || !provided) return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(REFRESH_TASK_SECRET);
  // timingSafeEqual throws on length mismatch, so check length first.
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Exchange the stored offline refresh token for a new offline access token.
// The return value tells the caller how to react:
//   'refreshed'   — stored a new access token
//   'reauthorize' — no refresh token, or Shopify returned 401 (the refresh token
//                   is expired, revoked, replayed outside the retry window, or the
//                   app was uninstalled); the merchant must reinstall
//   'retry'       — a transient failure (network, 5xx, 429); safe to retry later
async function refreshOfflineToken(shop) {
  const stored = tokenStore[shop];
  if (!stored?.refresh_token) return 'reauthorize';

  let response;
  try {
    response = await shopifyFetch(`https://${shop}/admin/oauth/access_token`, {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET,
        refresh_token: stored.refresh_token,
      }),
    });
  } catch (error) {
    // Only a transport failure or timeout becomes 'retry': the request never
    // reached Shopify, so the refresh token is untouched and a later attempt is
    // safe. Anything else is a bug in this code — let it surface.
    if (!(error instanceof ShopifyUnreachable)) throw error;
    return 'retry';
  }

  if (response.status === 401) {
    delete tokenStore[shop];
    return 'reauthorize';
  }
  if (!response.ok) return 'retry';

  const {access_token, refresh_token, expires_in} = await response.json();
  tokenStore[shop] = {
    access_token,
    refresh_token,
    expires_at: expiresAtFrom(expires_in),
  };
  return 'refreshed';
}

// [START token-exchange.exchange-offline]
app.post('/exchange/offline', async (req, res) => {
  const idToken = req.headers.authorization?.replace('Bearer ', '');
  let payload;
  try {
    payload = validateIdToken(idToken);
  } catch {
    // Signal App Bridge to fetch a fresh ID token and retry this request once.
    res.set('X-Shopify-Retry-Invalid-Session-Request', '1');
    return res.status(401).json({error: 'Invalid ID token'});
  }

  const shop = new URL(payload.dest).hostname;

  const response = await shopifyFetch(
    `https://${shop}/admin/oauth/access_token`,
    {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: new URLSearchParams({
        client_id: SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET,
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token: idToken,
        subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
        requested_token_type:
          'urn:shopify:params:oauth:token-type:offline-access-token',
        expiring: '1',
      }),
    },
  );

  // Shopify returns 400 when the ID token is expired or otherwise invalid. ID
  // tokens live about a minute, so that's a routine client condition, not a server
  // fault — answer it like a local validation failure so App Bridge fetches a fresh
  // token and retries. Returning 502 would say the opposite: don't bother retrying.
  if (response.status === 400) {
    res.set('X-Shopify-Retry-Invalid-Session-Request', '1');
    return res.status(401).json({error: 'Invalid ID token'});
  }

  if (!response.ok) {
    return res.status(502).json({error: 'Token exchange failed'});
  }

  const {access_token, refresh_token, scope, expires_in} = await response.json();

  // Store tokens server-side — never send them to the browser. Track expiry so
  // requests can refresh the offline token before it lapses.
  tokenStore[shop] = {
    access_token,
    refresh_token,
    expires_at: expiresAtFrom(expires_in),
  };

  res.json({scope});
});
// [END token-exchange.exchange-offline]

// [START token-exchange.exchange-online]
app.post('/exchange/online', async (req, res) => {
  const idToken = req.headers.authorization?.replace('Bearer ', '');
  let payload;
  try {
    payload = validateIdToken(idToken);
  } catch {
    // Signal App Bridge to fetch a fresh ID token and retry this request once.
    res.set('X-Shopify-Retry-Invalid-Session-Request', '1');
    return res.status(401).json({error: 'Invalid ID token'});
  }

  const shop = new URL(payload.dest).hostname;

  const response = await shopifyFetch(
    `https://${shop}/admin/oauth/access_token`,
    {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: new URLSearchParams({
        client_id: SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET,
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token: idToken,
        subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
        requested_token_type:
          'urn:shopify:params:oauth:token-type:online-access-token',
      }),
    },
  );

  // Same as the offline route: a 400 means the ID token is stale, which a fresh
  // one fixes. Don't dress a retryable condition up as a server error.
  if (response.status === 400) {
    res.set('X-Shopify-Retry-Invalid-Session-Request', '1');
    return res.status(401).json({error: 'Invalid ID token'});
  }

  if (!response.ok) {
    return res.status(502).json({error: 'Token exchange failed'});
  }

  const {access_token, scope, expires_in} = await response.json();

  // Online tokens are scoped to the staff member who authorized them, so key
  // them by user (the ID token's `sub`) — not just by shop. Storing under a
  // shop-only key would let one staff member's token overwrite another's.
  // Track expiry so a lapsed token is dropped rather than sent.
  tokenStore[`${shop}:online:${payload.sub}`] = {
    access_token,
    expires_at: expiresAtFrom(expires_in),
  };

  res.json({scope});
});
// [END token-exchange.exchange-online]

// [START token-exchange.make-request]
// Re-run token exchange for a token Shopify rejected, using the ID token that
// came with the current request. Same request as /exchange/offline and
// /exchange/online, minting whichever kind was rejected. The return value tells
// the caller how to react:
//   'minted'           — stored a new access token
//   'invalid_id_token' — Shopify returned 400; the ID token is stale, and a fresh
//                        one fixes it
//   'failed'           — anything else; retrying with the same inputs won't help
async function remintAccessToken({idToken, shop, sub, online}) {
  const response = await shopifyFetch(
    `https://${shop}/admin/oauth/access_token`,
    {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: new URLSearchParams({
        client_id: SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET,
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token: idToken,
        subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
        requested_token_type: online
          ? 'urn:shopify:params:oauth:token-type:online-access-token'
          : 'urn:shopify:params:oauth:token-type:offline-access-token',
        // `expiring` only applies to offline tokens. An online token already
        // expires with the staff member's session.
        ...(online ? {} : {expiring: '1'}),
      }),
    },
  );

  if (response.status === 400) return 'invalid_id_token';
  if (!response.ok) return 'failed';

  const {access_token, refresh_token, expires_in} = await response.json();

  if (online) {
    tokenStore[`${shop}:online:${sub}`] = {
      access_token,
      expires_at: expiresAtFrom(expires_in),
    };
  } else {
    tokenStore[shop] = {
      access_token,
      refresh_token,
      expires_at: expiresAtFrom(expires_in),
    };
  }

  return 'minted';
}

app.get('/api/shop', async (req, res) => {
  const idToken = req.headers.authorization?.replace('Bearer ', '');
  let payload;
  try {
    payload = validateIdToken(idToken);
  } catch {
    // Signal App Bridge to fetch a fresh ID token and retry this request once.
    res.set('X-Shopify-Retry-Invalid-Session-Request', '1');
    return res.status(401).json({error: 'Invalid ID token'});
  }

  const shop = new URL(payload.dest).hostname;
  const onlineKey = `${shop}:online:${payload.sub}`;

  // Drop an expired online token so we fall back to the offline token instead of
  // sending a dead credential. Online tokens can't be refreshed — a new one is
  // minted from a fresh ID token via /exchange/online.
  const online = tokenStore[onlineKey];
  if (online?.expires_at && online.expires_at <= Date.now()) {
    delete tokenStore[onlineKey];
  }

  // Prefer this staff member's online token so the request runs with their
  // permissions; fall back to the shop-wide offline token for shop-level access.
  const usingOnline = Boolean(tokenStore[onlineKey]);

  // Only the offline token is refreshable (online tokens are re-minted from a
  // fresh ID token via /exchange/online). Refresh it ~60 seconds before it
  // expires — but only when we're about to use it, so a still-valid online token
  // isn't blocked by a failed offline refresh.
  if (!usingOnline) {
    const offline = tokenStore[shop];
    if (offline?.expires_at && Date.now() >= offline.expires_at - 60 * 1000) {
      const result = await refreshOfflineToken(shop);
      if (result === 'reauthorize') {
        // No retry header here: the offline refresh token is dead, and a fresh
        // ID token can't revive it. The client must re-run /exchange/offline
        // (or reinstall) rather than retry this request into another 401.
        return res.status(401).json({error: 'reauthenticate'});
      }
      if (result === 'retry') {
        return res.status(503).json({error: 'Token refresh failed, try again'});
      }
    }
  }

  const stored = tokenStore[onlineKey] ?? tokenStore[shop];
  if (!stored) return res.status(401).json({error: 'Not authenticated'});

  const callAdminApi = (accessToken) =>
    shopifyFetch(`https://${shop}/admin/api/2026-04/graphql.json`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': accessToken,
      },
      body: JSON.stringify({query: '{ shop { name } }'}),
    });

  let response = await callAdminApi(stored.access_token);

  // Shopify rejected the access token (revoked, or the app's scopes changed).
  // Evict it and mint a replacement with token exchange: this request already
  // carries a validated ID token, so nothing the merchant does is needed.
  //
  // Don't answer this with X-Shopify-Retry-Invalid-Session-Request. That header
  // only makes App Bridge fetch a fresh *ID* token and replay this request — it
  // never re-runs the exchange, so the replay would find no stored token and fail
  // with "Not authenticated". It's the right answer for a rejected ID token, and
  // the wrong one for a rejected access token.
  if (response.status === 401) {
    const evictKey = usingOnline ? onlineKey : shop;
    delete tokenStore[evictKey];

    const result = await remintAccessToken({
      idToken,
      shop,
      sub: payload.sub,
      online: usingOnline,
    });

    // Only now is the retry header correct: the ID token itself is stale, and a
    // fresh one lets the replayed request mint a token successfully.
    if (result === 'invalid_id_token') {
      res.set('X-Shopify-Retry-Invalid-Session-Request', '1');
      return res.status(401).json({error: 'Invalid ID token'});
    }
    if (result !== 'minted') {
      return res.status(502).json({error: 'Token exchange failed'});
    }

    response = await callAdminApi(tokenStore[evictKey].access_token);

    // Retry once, not in a loop. A freshly minted token that's also rejected
    // means something is wrong beyond a stale credential, so stop and tell the
    // merchant to reauthorize rather than mint tokens indefinitely.
    if (response.status === 401) {
      delete tokenStore[evictKey];
      return res.status(401).json({error: 'reauthenticate'});
    }
  }

  // Forward Shopify's status. Answering a rate limit or an outage with a 200 and
  // an error body in it would tell the client the request succeeded.
  res.status(response.status).json(await response.json());
});
// [END token-exchange.make-request]

// [START token-exchange.refresh]
app.post('/refresh', async (req, res) => {
  // This endpoint mints a new access token, so authenticate the caller first.
  // Background callers (webhooks, scheduled jobs) have no session to produce an
  // ID token, so they send a shared secret in the `X-Refresh-Secret` header.
  if (!isAuthorizedTask(req)) {
    return res.status(401).json({error: 'Unauthorized'});
  }

  // Background callers supply the shop domain directly, since they have no
  // active session to derive it from an ID token. Defaulting to {} keeps a
  // request with no body — or the wrong content type — on the documented 400
  // path: Express 5 leaves req.body undefined when nothing was parsed, so
  // destructuring it directly would throw and return 500.
  const {shop} = req.body ?? {};
  if (!shop) return res.status(400).json({error: 'Missing shop'});

  // A 401 is terminal (expired, revoked, replayed outside the retry window, or
  // the app was uninstalled): re-authenticate the next time a merchant opens the
  // app. Other failures (network, 5xx, 429) are transient and safe to retry.
  const result = await refreshOfflineToken(shop);
  if (result === 'reauthorize') {
    return res.status(401).json({error: 'reauthenticate'});
  }
  if (result === 'retry') {
    return res.status(502).json({error: 'Token refresh failed'});
  }

  res.json({success: true});
});
// [END token-exchange.refresh]

// express.json() throws on a malformed body, and Express's default error handler
// answers with an HTML page containing a stack trace and absolute file paths. This
// is a JSON API, so answer in JSON. Match only parse failures: anything else should
// keep surfacing loudly rather than be swallowed here.
app.use((err, req, res, next) => {
  if (err?.type === 'entity.parse.failed') {
    return res.status(400).json({error: 'Malformed JSON body'});
  }
  // The request never reached Shopify, so nothing was consumed and the caller can
  // try again. 503 says that; the stack trace Express would otherwise return says
  // the app is broken.
  if (err instanceof ShopifyUnreachable) {
    return res.status(503).json({error: 'Could not reach Shopify, try again'});
  }
  next(err);
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
