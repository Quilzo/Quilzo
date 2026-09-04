// Driving a real browser at the passkey routes.
//
// internal/webauthn is tested against an authenticator simulated from the
// specification, through the real handlers. That verifies the server and says
// nothing about the half that runs in somebody's browser: whether the inline
// script executes under a nonce-scoped policy, whether what
// navigator.credentials produces is what the server expects, and whether a
// real authenticator agrees with a reading of the spec.
//
// Chrome answers all three. Its DevTools Protocol has a virtual authenticator
// -- the real WebAuthn implementation with a software key behind it -- which
// is the tool this exact situation was built for.
//
// No dependencies: Node has had a global WebSocket and fetch for some time,
// and the protocol is JSON over one socket.
//
//   node scripts/passkey/browsercheck.mjs http://127.0.0.1:PORT SESSION_TOKEN

const [base, token] = process.argv.slice(2);
if (!base || !token) {
  console.error("usage: browsercheck.mjs <base-url> <session-token>");
  process.exit(2);
}

const DEBUG_PORT = 9333;
const { spawn } = await import("node:child_process");

const chrome = spawn("/usr/bin/chromium", [
  "--headless=new",
  `--remote-debugging-port=${DEBUG_PORT}`,
  "--no-sandbox",
  "--disable-gpu",
  "--user-data-dir=/tmp/claude-1000/passkey-chrome-profile",
  "about:blank",
], { stdio: ["ignore", "ignore", "pipe"] });

let failed = false;
const fail = (why) => { console.log(`FAIL  ${why}`); failed = true; };
const pass = (what) => console.log(`ok    ${what}`);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Wait for the debugger to come up.
let targets = null;
for (let i = 0; i < 60 && !targets; i++) {
  await sleep(250);
  try {
    const r = await fetch(`http://127.0.0.1:${DEBUG_PORT}/json/list`);
    targets = await r.json();
  } catch { /* not up yet */ }
}
if (!targets) {
  console.error("chromium did not start a debugger");
  chrome.kill();
  process.exit(2);
}

const page = targets.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));

let nextId = 1;
const waiting = new Map();
const events = [];
ws.addEventListener("message", (e) => {
  const msg = JSON.parse(e.data);
  if (msg.id && waiting.has(msg.id)) {
    const { resolve, reject } = waiting.get(msg.id);
    waiting.delete(msg.id);
    msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
  } else if (msg.method) {
    events.push(msg);
  }
});
const send = (method, params = {}) =>
  new Promise((resolve, reject) => {
    const id = nextId++;
    waiting.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });

async function main() {
  await send("Page.enable");
  await send("Runtime.enable");
  await send("Network.enable");
  await send("Log.enable");

  // The session, set directly rather than by driving the sign-in form: this
  // is a test of the passkey routes, not of the token form.
  const url = new URL(base);
  await send("Network.setCookie", {
    name: "quilzo_token", value: token,
    domain: url.hostname, path: "/", httpOnly: true,
  });

  // A real authenticator, in software. Resident keys because sign-in offers
  // no username: the credential has to say who it belongs to.
  await send("WebAuthn.enable");
  const { authenticatorId } = await send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2", transport: "internal",
      hasResidentKey: true, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true,
    },
  });
  pass(`virtual authenticator ${authenticatorId.slice(0, 8)}…`);

  const go = async (path) => {
    await send("Page.navigate", { url: base + path });
    await sleep(900);
  };
  const evaluate = async (expression) => {
    const r = await send("Runtime.evaluate", {
      expression, awaitPromise: true, returnByValue: true,
    });
    if (r.exceptionDetails) {
      throw new Error(r.exceptionDetails.exception?.description || "threw");
    }
    return r.result.value;
  };

  // -- registration --------------------------------------------------------
  await go("/passkeys");

  const scriptRan = await evaluate(
    `typeof document.getElementById('add') === 'object' &&
     document.getElementById('add') !== null`);
  if (!scriptRan) {
    fail("the passkeys screen has no add button; not signed in?");
    return;
  }

  // The policy blocks everything but the nonced block. If the script did not
  // run, no listener is attached and the click does nothing -- which is
  // exactly the silent failure this whole check exists to rule out.
  await evaluate(`document.getElementById('label').value = 'a virtual key';
                  document.getElementById('add').click(); true`);
  await sleep(2500);

  const registerMessage = await evaluate(
    `document.getElementById('msg') ? document.getElementById('msg').textContent : ''`);
  const credentials = await send("WebAuthn.getCredentials", { authenticatorId });
  if (credentials.credentials.length === 0) {
    fail(`no credential was created (page said: ${JSON.stringify(registerMessage)})`);
    const blocked = events.filter((e) =>
      e.method === "Log.entryAdded" &&
      /Content Security Policy/i.test(e.params.entry.text || ""));
    if (blocked.length) {
      fail("the policy blocked the script: " + blocked[0].params.entry.text);
    }
    return;
  }
  pass(`a real authenticator registered a credential ` +
       `(${credentials.credentials.length} on the device)`);
  if (!credentials.credentials[0].isResidentCredential) {
    fail("the credential is not discoverable, so sign-in would need a username");
  } else {
    pass("the credential is discoverable");
  }

  // -- sign in -------------------------------------------------------------
  // The session is cleared first, so what follows is the passkey signing
  // somebody in rather than a cookie that was already there.
  await send("Network.clearBrowserCookies");
  await go("/signin/passkey");

  const button = await evaluate(
    `document.getElementById('go') !== null`);
  if (!button) {
    fail("the passkey sign-in screen has no button");
    return;
  }
  await evaluate(`document.getElementById('go').click(); true`);
  await sleep(3000);

  const signInMessage = await evaluate(
    `document.getElementById('msg') ? document.getElementById('msg').textContent : ''`);
  const cookies = await send("Network.getCookies", { urls: [base + "/"] });
  const session = cookies.cookies.find((c) => c.name === "quilzo_token");

  if (!session || !session.value) {
    fail(`signing in with the passkey set no session (page said: ` +
         `${JSON.stringify(signInMessage)})`);
    return;
  }
  pass("a passkey signed somebody in and the server minted a session");

  // And the session actually works.
  await go("/");
  const title = await evaluate(`document.title`);
  if (/sign in/i.test(title || "")) {
    fail(`the minted session does not authenticate (landed on ${title})`);
  } else {
    pass(`the session authenticates (landed on ${JSON.stringify(title)})`);
  }
}

try {
  await main();
} catch (e) {
  fail(String(e && e.message ? e.message : e));
} finally {
  ws.close();
  chrome.kill();
}
console.log(failed ? "\nBROWSER CHECK FAILED" : "\nBROWSER CHECK PASSED");
process.exit(failed ? 1 : 0);
