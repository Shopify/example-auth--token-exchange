# Getting access tokens without the template

Tutorial for getting an access token for apps not using the Shopify app template library.

**Tutorial:** [Get access tokens without the template](https://shopify.dev/docs/apps/build/authentication-authorization/get-access-tokens-tutorial)

## Languages

- `node/` — Node.js example
- `python/` — Python example (Flask)
- `curl/` — cURL/Bash example

The frontend in `public/` is shared. App Bridge runs in the browser, so
`shopify.idToken()` is JavaScript whatever language your backend is written in.

## Setup

The steps below set up a server. The cURL example needs no install — edit the values at the top of `curl/example.sh` and run it.

**Node.js**

1. `cd node`
2. Copy `.env.example` to `.env` and add your credentials
3. Run `npm install` to install dependencies
4. Start the server with `npm start`
5. Open the app in your dev store

**Python** (3.9 or later)

1. `cd python`
2. Copy `.env.example` to `.env` and add your credentials
3. Create a virtual environment and install dependencies:
   ```sh
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   ```
4. Start the server with `python main.py`
5. Open the app in your dev store

Both servers listen on port 3000 and serve the same frontend from `public/`, so run one at a time.

## Environment variables

Set these in `node/.env` or `python/.env`:

- `SHOPIFY_CLIENT_ID` — your app's client ID from the Dev Dashboard
- `SHOPIFY_CLIENT_SECRET` — your app's client secret from the Dev Dashboard
- `REFRESH_TASK_SECRET` — shared secret that authorizes background calls to `POST /refresh`; generate a long random value, for example `openssl rand -hex 32`

The sample derives the shop from the validated ID token, so you don't set a shop domain in `.env`.

`POST /refresh` mints a new access token, so it isn't publicly callable. Background callers (schedulers, webhooks) must send `REFRESH_TASK_SECRET` in the `X-Refresh-Secret` header.

## Note

This repository backs the tutorial linked above and exists for documentation purposes. We don't accept feature pull requests, but automated dependency and security updates (for example, Dependabot) are merged as needed. If something in the sample looks wrong, please open an issue.
