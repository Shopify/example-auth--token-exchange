// [START token-exchange.get-id-token]
const idToken = await shopify.idToken();
// [END token-exchange.get-id-token]

// [START token-exchange.send-to-backend]
const response = await fetch('/exchange/offline', {
  method: 'POST',
  headers: {
    Authorization: `Bearer ${idToken}`,
  },
});
// [END token-exchange.send-to-backend]
