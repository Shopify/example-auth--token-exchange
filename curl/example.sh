#!/bin/bash

# Replace these with your values
SHOP="your-store"
CLIENT_ID="your-client-id"
CLIENT_SECRET="your-client-secret"
ID_TOKEN="your-id-token"  # Get this from App Bridge: shopify.idToken()

# [START token-exchange.exchange-offline]
curl -X POST \
  "https://${SHOP}.myshopify.com/admin/oauth/access_token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Accept: application/json' \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  -d "subject_token=${ID_TOKEN}" \
  -d 'subject_token_type=urn:ietf:params:oauth:token-type:id_token' \
  -d 'requested_token_type=urn:shopify:params:oauth:token-type:offline-access-token' \
  -d 'expiring=1'
# [END token-exchange.exchange-offline]

# [START token-exchange.exchange-online]
curl -X POST \
  "https://${SHOP}.myshopify.com/admin/oauth/access_token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Accept: application/json' \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  -d "subject_token=${ID_TOKEN}" \
  -d 'subject_token_type=urn:ietf:params:oauth:token-type:id_token' \
  -d 'requested_token_type=urn:shopify:params:oauth:token-type:online-access-token'
# [END token-exchange.exchange-online]

# [START token-exchange.make-request]
ACCESS_TOKEN="your-access-token"

curl -X POST \
  "https://${SHOP}.myshopify.com/admin/api/2025-01/graphql.json" \
  -H 'Content-Type: application/json' \
  -H "X-Shopify-Access-Token: ${ACCESS_TOKEN}" \
  -d '{"query": "{ shop { name } }"}'
# [END token-exchange.make-request]

# [START token-exchange.refresh]
REFRESH_TOKEN="your-refresh-token"

curl -X POST \
  "https://${SHOP}.myshopify.com/admin/oauth/access_token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=refresh_token' \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "refresh_token=${REFRESH_TOKEN}"
# [END token-exchange.refresh]
