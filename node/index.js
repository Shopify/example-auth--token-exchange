import 'dotenv/config';
import express from 'express';
import path from 'path';
import {fileURLToPath} from 'url';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// [START token-exchange.config]
const {SHOPIFY_CLIENT_ID, SHOPIFY_CLIENT_SECRET, SHOPIFY_SHOP, REFRESH_TASK_SECRET} =
  process.env;
// [END token-exchange.config]

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

// [START token-exchange.authorize-task]
// Background callers (webhooks, scheduled jobs) have no session to produce an
// ID token, so they authenticate with a shared secret that only your own
// backend and schedulers know. Sent as the `X-Refresh-Secret` header.
function isAuthorizedTask(req) {
  const provided = req.get('X-Refresh-Secret') ?? '';
  if (!REFRESH_TASK_SECRET || !provided) return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(REFRESH_TASK_SECRET);
  // timingSafeEqual throws on length mismatch, so check length first.
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
// [END token-exchange.authorize-task]

// [START token-exchange.exchange-offline]
app.post('/exchange/offline', async (req, res) => {
  const idToken = req.headers.authorization?.replace('Bearer ', '');
  try {
    validateIdToken(idToken);
  } catch {
    return res.status(401).json({error: 'Invalid ID token'});
  }

  const response = await fetch(
    `https://${SHOPIFY_SHOP}.myshopify.com/admin/oauth/access_token`,
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

  res.json(await response.json());
});
// [END token-exchange.exchange-offline]

// [START token-exchange.exchange-online]
app.post('/exchange/online', async (req, res) => {
  const idToken = req.headers.authorization?.replace('Bearer ', '');
  try {
    validateIdToken(idToken);
  } catch {
    return res.status(401).json({error: 'Invalid ID token'});
  }

  const response = await fetch(
    `https://${SHOPIFY_SHOP}.myshopify.com/admin/oauth/access_token`,
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

  res.json(await response.json());
});
// [END token-exchange.exchange-online]

// [START token-exchange.make-request]
app.get('/api/shop', async (req, res) => {
  const accessToken = req.headers['x-access-token'];

  const response = await fetch(
    `https://${SHOPIFY_SHOP}.myshopify.com/admin/api/2026-04/graphql.json`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': accessToken,
      },
      body: JSON.stringify({query: '{ shop { name } }'}),
    },
  );

  res.json(await response.json());
});
// [END token-exchange.make-request]

// [START token-exchange.refresh]
app.post('/refresh', async (req, res) => {
  // This endpoint mints a new access token, so authenticate the caller before
  // doing anything. Background callers can't provide an ID token, so they send
  // the shared secret instead.
  if (!isAuthorizedTask(req)) {
    return res.status(401).json({error: 'Unauthorized'});
  }

  const {refresh_token} = req.body;
  if (!refresh_token) {
    return res.status(400).json({error: 'Missing refresh_token'});
  }

  const response = await fetch(
    `https://${SHOPIFY_SHOP}.myshopify.com/admin/oauth/access_token`,
    {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET,
        refresh_token,
      }),
    },
  );

  res.json(await response.json());
});
// [END token-exchange.refresh]

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
