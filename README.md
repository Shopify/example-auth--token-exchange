# Getting access tokens without the template
Tutorial for getting an access token for apps not using the Shopify app template library.

**Tutorial:** [Get access tokens without the template](https://shopify.dev/docs/apps/build/authentication-authorization/get-access-tokens-tutorial)

## Languages

- `node/` — Node.js example
- `curl/` — cURL/Bash example

## Setup

1. Copy `.env.example` to `.env` and add your credentials
2. Run `npm install` to install dependencies
3. Start the server with `node index.js`
4. Open the app in your dev store

## Environment variables

Set these in your `.env`:

- `SHOPIFY_CLIENT_ID` — your app's client ID from the Dev Dashboard
- `SHOPIFY_CLIENT_SECRET` — your app's client secret from the Dev Dashboard
- `SHOPIFY_SHOP` — the dev store the sample runs against, without `.myshopify.com`
- `REFRESH_TASK_SECRET` — shared secret that authorizes background calls to `POST /refresh`; generate a long random value, for example `openssl rand -hex 32`

`POST /refresh` mints a new access token, so it isn't publicly callable. Background callers (schedulers, webhooks) must send `REFRESH_TASK_SECRET` in the `X-Refresh-Secret` header.


## Note

This repository is for documentation purposes. Issues and pull requests are not accepted.
