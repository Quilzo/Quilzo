# Checking the passkey routes with a real browser

`internal/webauthn` is tested against an authenticator simulated from the
specification, driven through the real handlers. That verifies the server, and
says nothing about the half that runs in somebody's browser:

- whether the inline script executes at all under a nonce-scoped policy;
- whether what `navigator.credentials` produces is what the server expects;
- whether a real authenticator agrees with a reading of the spec.

Chrome answers all three. Its DevTools Protocol has a virtual authenticator —
the real WebAuthn implementation with a software key behind it — which is the
tool this exact situation was built for.

```
quilzo auth grant you admin
quilzo token issue you --principal you --role admin   # keep the token
QUILZO_TOKEN=$TOKEN quilzo serve --addr 127.0.0.1:8802 &

node scripts/passkey/browsercheck.mjs http://localhost:8802 $TOKEN
```

It registers a credential, clears the session, signs back in with the passkey
alone, and checks the minted session actually authenticates.

**Use `localhost`, not `127.0.0.1`.** That is not a preference; it is the first
thing this found.

## What it caught

Two faults that no amount of reading produced, both of which looked like
nothing was wrong:

- **An address is not a relying party.** `http://127.0.0.1` *is* a secure
  context, so the HTTPS check passed, the screen offered the button, and Chrome
  answered `This is an invalid domain` from inside `navigator.credentials` —
  where the server never sees it and the page appears to do nothing. The
  specification says a relying party id is a valid domain string; it does not
  say what a browser does when handed an address.
- **A replaced policy drops what it does not mention.** The passkey screens set
  their own Content-Security-Policy and omitted `manifest-src`, so the web
  manifest was blocked on exactly those two pages: the admin stayed installable
  everywhere else and quietly stopped being installable there.

No dependencies. Node has had a global `WebSocket` and `fetch` for some time,
and the protocol is JSON over one socket.
