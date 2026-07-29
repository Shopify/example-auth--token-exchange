# Getting access tokens without the template

Tutorial for getting an access token for apps not using the Shopify app template library.

**Tutorial:** [Get access tokens without the template](https://shopify.dev/docs/apps/build/authentication-authorization/get-access-tokens-tutorial)

## Languages

- `node/` — Node.js example
- `curl/` — cURL/Bash example

## Setup

The steps below set up the Node.js example. The cURL example needs no install — edit the values at the top of `curl/example.sh` and run it.

1. `cd node`
2. Copy `.env.example` to `.env` and add your credentials
3. Run `npm install` to install dependencies
4. Start the server with `npm start`
5. Open the app in your dev store

## Environment variables

Set these in `node/.env`:

- `SHOPIFY_CLIENT_ID` — your app's client ID from the Dev Dashboard
- `SHOPIFY_CLIENT_SECRET` — your app's client secret from the Dev Dashboard
- `REFRESH_TASK_SECRET` — shared secret that authorizes background calls to `POST /refresh`; generate a long random value, for example `openssl rand -hex 32`

The sample derives the shop from the validated ID token, so you don't set a shop domain in `.env`.

`POST /refresh` mints a new access token, so it isn't publicly callable. Background callers (schedulers, webhooks) must send `REFRESH_TASK_SECRET` in the `X-Refresh-Secret` header.

## Note

This repository backs the tutorial linked above and exists for documentation purposes. We don't accept feature pull requests, but automated dependency and security updates (for example, Dependabot) are merged as needed. If something in the sample looks wrong, please open an issue.
