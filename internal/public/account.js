// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial
//
// Passkeys for a site's members: creating an account, signing in, and adding
// another key. The server checks everything; this only carries bytes between
// the browser's passkey prompt and the server, because WebAuthn is a browser
// API and there is no way to reach it without a script.
//
// Nothing is stored here, and nothing is read from the page but the buttons
// it wires up. Every message reaches the page through textContent.
(function () {
  "use strict";

  var msg = document.getElementById("account-msg");
  function say(text) {
    if (msg) {
      msg.textContent = text;
    }
  }

  // Base64url both ways: WebAuthn speaks ArrayBuffer and JSON does not.
  function toBytes(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) {
      s += "=";
    }
    var raw = atob(s);
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) {
      out[i] = raw.charCodeAt(i);
    }
    return out;
  }
  function toText(buffer) {
    var bytes = new Uint8Array(buffer);
    var s = "";
    for (var i = 0; i < bytes.length; i++) {
      s += String.fromCharCode(bytes[i]);
    }
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // Every request goes to this page's own address, which is what a site
  // served under a sub-path rewrote; everything else is relative to it.
  var root = (document.body.getAttribute("data-account") || "/account").replace(/\/+$/, "");
  function post(path, body) {
    return fetch(root + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body || {})
    }).then(function (response) {
      return response.json().catch(function () {
        return {};
      }).then(function (data) {
        if (!response.ok) {
          throw new Error(data.error || "That did not work. Try again.");
        }
        return data;
      });
    });
  }

  function supported() {
    if (!window.PublicKeyCredential) {
      say("This browser cannot use passkeys. Try a current version of Chrome, Edge, Safari or Firefox.");
      return false;
    }
    return true;
  }

  // Where to go after signing in: a path on this site, never anywhere else.
  function next() {
    var n = new URLSearchParams(location.search).get("next") || "";
    return /^\/(?!\/)/.test(n) && n.indexOf("\\") < 0 ? n : root;
  }

  function registered(credential, challenge, extra) {
    var made = credential.response;
    if (!made.getPublicKey || !made.getPublicKey()) {
      throw new Error("This browser cannot report the passkey in a form this site reads. Use a current browser.");
    }
    var body = {
      challenge: challenge,
      id: credential.id,
      clientDataJSON: toText(made.clientDataJSON),
      authenticatorData: toText(made.getAuthenticatorData()),
      publicKey: toText(made.getPublicKey()),
      algorithm: made.getPublicKeyAlgorithm()
    };
    for (var k in extra) {
      body[k] = extra[k];
    }
    return body;
  }

  function create(start) {
    return navigator.credentials.create({
      publicKey: {
        challenge: toBytes(start.challenge),
        rp: { id: start.rp.id, name: start.rp.name },
        user: {
          id: toBytes(start.user.id),
          name: start.user.name,
          displayName: start.user.displayName
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -8 },
          { type: "public-key", alg: -257 }
        ],
        authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
        excludeCredentials: (start.exclude || []).map(function (id) {
          return { type: "public-key", id: toBytes(id) };
        }),
        timeout: 120000,
        attestation: "none"
      }
    });
  }

  function showCodes(codes) {
    var box = document.getElementById("account-codes");
    var list = document.getElementById("account-code-list");
    if (!box || !list) {
      return;
    }
    list.textContent = "";
    codes.forEach(function (c) {
      var li = document.createElement("li");
      li.textContent = c;
      list.appendChild(li);
    });
    box.hidden = false;
    box.querySelector("h2").focus();
  }

  var signup = document.getElementById("signup-form");
  if (signup) {
    signup.addEventListener("submit", function (e) {
      e.preventDefault();
      if (!supported()) {
        return;
      }
      var button = signup.querySelector("button");
      button.disabled = true;
      say("Follow your device's prompt to make a passkey.");
      var name = signup.querySelector("[name=name]").value;
      var inviteField = signup.querySelector("[name=invite]");
      var invite = inviteField ? inviteField.value : "";
      var challenge = null;
      post("/signup/start", { name: name, invite: invite }).then(function (start) {
        challenge = start.challenge;
        return create(start);
      }).then(function (credential) {
        if (!credential) {
          throw new Error("No passkey was made.");
        }
        return post("/signup/finish", registered(credential, challenge, {}));
      }).then(function (done) {
        // Signed in now: the ways to sign in are no longer the point, and
        // the codes are the one thing on the page to read.
        Array.prototype.forEach.call(document.querySelectorAll("main > section"), function (sec) {
          sec.hidden = sec.id !== "account-codes";
        });
        var h = document.getElementById("account-h");
        if (h) {
          h.textContent = "Your account is ready";
        }
        say("");
        showCodes(done.codes || []);
      }).catch(function (err) {
        button.disabled = false;
        say(err.name === "NotAllowedError" ? "The passkey prompt was closed. Nothing was made." : err.message);
      });
    });
  }

  var signin = document.getElementById("signin-button");
  if (signin) {
    signin.addEventListener("click", function () {
      if (!supported()) {
        return;
      }
      signin.disabled = true;
      say("Follow your device's prompt to sign in.");
      var challenge = null;
      post("/signin/start").then(function (start) {
        challenge = start.challenge;
        return navigator.credentials.get({
          publicKey: {
            challenge: toBytes(start.challenge),
            rpId: start.rpId,
            userVerification: "preferred",
            timeout: 120000
          }
        });
      }).then(function (credential) {
        if (!credential) {
          throw new Error("No passkey was offered.");
        }
        var got = credential.response;
        return post("/signin/finish", {
          challenge: challenge,
          id: credential.id,
          clientDataJSON: toText(got.clientDataJSON),
          authenticatorData: toText(got.authenticatorData),
          signature: toText(got.signature)
        });
      }).then(function () {
        location.assign(next());
      }).catch(function (err) {
        signin.disabled = false;
        say(err.name === "NotAllowedError" ? "The passkey prompt was closed. You are not signed in." : err.message);
      });
    });
  }

  var add = document.getElementById("add-passkey");
  if (add) {
    add.addEventListener("click", function () {
      if (!supported()) {
        return;
      }
      add.disabled = true;
      say("Follow your device's prompt to make another passkey.");
      var challenge = null;
      post("/passkey/start").then(function (start) {
        challenge = start.challenge;
        return create(start);
      }).then(function (credential) {
        if (!credential) {
          throw new Error("No passkey was made.");
        }
        var label = document.getElementById("passkey-label");
        return post("/passkey/finish", registered(credential, challenge,
          { label: label ? label.value : "" }));
      }).then(function () {
        location.assign(root + "?done=passkey-added");
      }).catch(function (err) {
        add.disabled = false;
        say(err.name === "NotAllowedError" ? "The passkey prompt was closed. Nothing was added." : err.message);
      });
    });
  }
})();
