import 'dotenv/config';
import express from 'express';
import path from 'path';
import {fileURLToPath} from 'url';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import {readFileSync} from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json());

// Inject the client ID (App Bridge API key) into index.html before serving it.
// express.static would return the file verbatim, leaving the placeholder in place.
app.get(['/', '/index.html'], (req, res) => {
  const html = readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8')
    .replace('%SHOPIFY_API_KEY%', process.env.SHOPIFY_CLIENT_ID);
  res.type('html').send(html);
});

app.use(express.static(path.join(__dirname, 'public')));

// [START token-exchange.config]
const {SHOPIFY_CLIENT_ID, SHOPIFY_CLIENT_SECRET, REFRESH_TASK_SECRET} =
  process.env;
// [END token-exchange.config]

// In-memory token store (use a persistent session store in production)
const tokenStore = {};

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

  const response = await fetch(
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

  if (!response.ok) {
    return res.status(502).json({error: 'Token exchange failed'});
  }

  const {access_token, refresh_token, scope} = await response.json();

  // Store tokens server-side — never send them to the browser
  tokenStore[shop] = {access_token, refresh_token};

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

  const response = await fetch(
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

  if (!response.ok) {
    return res.status(502).json({error: 'Token exchange failed'});
  }

  const {access_token, scope, expires_in} = await response.json();

  // Online tokens are scoped to the staff member who authorized them, so key
  // them by user (the ID token's `sub`) — not just by shop. Storing under a
  // shop-only key would let one staff member's token overwrite another's.
  // Track when it expires so we don't keep sending a dead token.
  tokenStore[`${shop}:online:${payload.sub}`] = {
    access_token,
    expires_at: Date.now() + expires_in * 1000,
  };

  res.json({scope});
});
// [END token-exchange.exchange-online]

// [START token-exchange.make-request]
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

  // Drop an expired online token so we fall back instead of sending a dead one.
  const onlineKey = `${shop}:online:${payload.sub}`;
  const online = tokenStore[onlineKey];
  if (online?.expires_at && online.expires_at <= Date.now()) {
    delete tokenStore[onlineKey];
  }

  // Prefer this staff member's online token so the request runs with their
  // permissions; fall back to the shop-wide offline token for shop-level access.
  const stored = tokenStore[onlineKey] ?? tokenStore[shop];
  if (!stored) return res.status(401).json({error: 'Not authenticated'});

  const response = await fetch(
    `https://${shop}/admin/api/2026-04/graphql.json`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': stored.access_token,
      },
      body: JSON.stringify({query: '{ shop { name } }'}),
    },
  );

  // If Shopify rejects the token, evict it and ask the client to retry with a
  // fresh ID token rather than looping on a bad credential.
  if (response.status === 401) {
    delete tokenStore[onlineKey];
    res.set('X-Shopify-Retry-Invalid-Session-Request', '1');
    return res.status(401).json({error: 'Token rejected'});
  }

  res.json(await response.json());
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
  // active session to derive it from an ID token.
  const {shop} = req.body;
  if (!shop) return res.status(400).json({error: 'Missing shop'});

  const stored = tokenStore[shop];
  if (!stored?.refresh_token) return res.status(401).json({error: 'No refresh token'});

  const response = await fetch(
    `https://${shop}/admin/oauth/access_token`,
    {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET,
        refresh_token: stored.refresh_token,
      }),
    },
  );

  if (!response.ok) {
    return res.status(502).json({error: 'Token refresh failed'});
  }

  const {access_token, refresh_token} = await response.json();
  tokenStore[shop] = {access_token, refresh_token};

  res.json({success: true});
});
// [END token-exchange.refresh]

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
