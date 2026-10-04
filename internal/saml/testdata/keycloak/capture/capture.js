// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Follows each request through a Keycloak sign-in in Chromium and keeps the
// SAMLResponse posted back, without anything listening on the service side.
//   node capture.js requests.txt PASSWORD_FILE OUT_DIR
const { chromium } = require('playwright-core');
const fs = require('fs');
const [,, reqFile, pwFile, outDir] = process.argv;
(async () => {
  const b = await chromium.launch({ executablePath: process.env.CHROMIUM });
  const lines = fs.readFileSync(reqFile, 'utf8').trim().split('\n');
  for (const line of lines) {
    const [name, id, url] = line.split(' ');
    const ctx = await b.newContext();
    const p = await ctx.newPage();
    let captured = null;
    await p.route('http://127.0.0.1:18780/**', async route => {
      const body = route.request().postData() || '';
      const params = new URLSearchParams(body);
      captured = { name, request_id: id, relay_state: params.get('RelayState'), captured: new Date().toISOString(), response: params.get('SAMLResponse') };
      await route.fulfill({ status: 200, body: 'captured' });
    });
    await p.goto(url);
    await p.fill('#username', 'dana');
    await p.fill('#password', fs.readFileSync(pwFile, 'utf8').trim());
    await p.click('#kc-login');
    for (let i = 0; i < 50 && !captured; i++) await p.waitForTimeout(100);
    if (!captured) { console.log(name, 'NOT CAPTURED', p.url(), (await p.content()).slice(0, 300)); continue; }
    fs.writeFileSync(`${outDir}/${name}.json`, JSON.stringify(captured, null, 1) + '\n');
    console.log(name, 'captured', captured.response.length, 'relay', captured.relay_state);
    await ctx.close();
  }
  await b.close();
})();
