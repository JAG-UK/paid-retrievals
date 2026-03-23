# Lotus signing quickstart

The client now signs each paid `X-Payment-Header` with a Filecoin wallet address.

## Client

```bash
retrieval-client fetch \
  --sp-base-url http://127.0.0.1:8787 \
  --client f1yourwalletaddress \
  --cid bafy... \
  --lotus-binary lotus
```

For each CID in phase 2, the client:

- builds a canonical message from `deal_uuid`, `cid`, `client`, `method`, `path`, `host`, `nonce`, and `expires_unix`;
- calls `lotus wallet sign <client> <hex(message)>`;
- sends the signature + metadata in `X-Payment-Header`.

## SP proxy

Run with Lotus verification enabled (default binary: `lotus`):

```bash
sp-proxy --listen :8787 --db ./sp-proxy.db --lotus-binary lotus
```

On paid requests, the proxy:

- decodes and validates header shape and expiry;
- verifies `client` matches the quoted deal;
- verifies signature with `lotus wallet verify <client> <hex(message)> <sig>`;
- consumes nonce once (replay-protection);
- returns the CAR payload.
