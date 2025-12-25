# Starlink API v2 migration notes

This project now targets Starlink API v2 under the new base `https://starlink.com/api/public` while keeping v1 support intact.

## What changed
- V2 base URL: defaults to `https://starlink.com/api/public` (configurable via `STARLINK_BASE_URL_V2`).
- Per-account auth: V2 service accounts are bound to a single Starlink account. Tokens are cached per account key.
- Paths no longer include `/accounts/{accountNumber}`. Updated upstream paths:
  - Account info: `GET /v2/account`
  - Products: `GET /v2/products`
  - Addresses: `POST /v2/addresses`, `GET /v2/addresses`, `GET /v2/addresses/{addressReferenceId}`
  - Service lines: `GET /v2/service-lines`, `POST /v2/service-lines`, `PUT /v2/service-lines/{serviceLineNumber}/nickname`
  - User terminals (account-level): `GET /v2/user-terminals`, `POST /v2/user-terminals` (body `{ deviceId }`), `DELETE /v2/user-terminals/{deviceId}`
  - Attach to service line: `POST /v2/service-lines/{serviceLineNumber}/user-terminals` (body `{ deviceId }`)
- Express v2 routes still accept `:account` or `?account=` only to choose credentials; the upstream v2 calls use token scoping, not URL prefixes.

## Configuration
Set per-account credentials using one of:
```
STARLINK_V2_CREDENTIALS='{
  "ACC-111": {"clientId":"<id1>","clientSecret":"<secret1>"},
  "ACC-222": {"clientId":"<id2>","clientSecret":"<secret2>"}
}'
# Optional default fallback if no account entry is found:
V2_CLIENT_ID=<id>
V2_CLIENT_SECRET=<secret>
```
Legacy v1 vars remain (`STARLINK_BASE_URL`, `CLIENT_ID`, `CLIENT_SECRET`).

## How to test (manual)
1) Ensure env vars above are set and start the server: `node index.js` (or your usual start command).
2) Fetch account info for a given account credential:
```
curl "http://localhost:3000/api/v2/account?account=ACC-111"
```
3) List products with the same account:
```
curl "http://localhost:3000/api/v2/accounts/ACC-111/products"
```
4) (Optional) Validate kit/attach flow: call `/api/v2/accounts/ACC-111/validate-kit/<KIT>` or run the activation flow `/api/v2/activate` with the same `accountNumber` that matches a configured credential.

On 401s, the code clears the cached token for that account and retries with fresh credentials.
