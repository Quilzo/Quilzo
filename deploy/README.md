# Getting a stable https address

Telegram will not open a Mini App over plain HTTP, and the Apps Center points at
one address. So this needs two things the rest of the project does not: a real
certificate, and a process that comes back after a reboot.

Two paths. The first takes five minutes and is for trying it; the second is what
a listing needs.

---

## Trying it: a tunnel

A tunnel gives you an https address for a process on your laptop, with no server
and no DNS.

```bash
# in one terminal
export QUILZO_TELEGRAM_TOKEN=…
quilzo telegram serve --addr 127.0.0.1:8082 --no-bot

# in another
cloudflared tunnel --url http://127.0.0.1:8082
```

That prints a `https://something-random.trycloudflare.com` address. Restart it
and you get a different one, which is fine for a first look and is exactly why
this is not the second path.

Once you have the address, restart the server with it so the bot can put it in a
button:

```bash
quilzo telegram serve --app-url https://something-random.trycloudflare.com
```

Then give @BotFather the same address, and send your bot `/start`.

**Do not submit a listing on a tunnel address.** It stops answering when you
close the terminal, and a Mini App that does not open is a listing that gets
pulled — which is not a rejection you can appeal, because they were right.

---

## Listing it: a small server

Anything with 512 MB will do. This is one static binary and a directory.

### 1. A user and a place

```bash
sudo useradd --system --home /srv/quilzo --shell /usr/sbin/nologin quilzo
sudo install -d -o quilzo -g quilzo /srv/quilzo
sudo install -d -o quilzo -g quilzo /srv/quilzo/submissions
sudo install -d -m 0750 -o root -g quilzo /etc/quilzo
```

### 2. The binary

```bash
make build
sudo install -m 0755 bin/quilzo /usr/local/bin/quilzo
```

Or take a release binary — it is static, so there is nothing to install
alongside it.

### 3. The store

Copy your `.quilzo` directory and your `templates` directory to
`/srv/quilzo`, owned by `quilzo`. Then check it from the server:

```bash
sudo -u quilzo quilzo --root /srv/quilzo theme check
```

### 4. DNS

Two names pointing at the server. They can be subdomains of one domain and they
must not be the same host — the Mini App and the published site have different
exposures, and sharing an origin would mean one policy covering both.

```
pages.example.com   A   your.server.ip     # the Mini App
example.com         A   your.server.ip     # the published site
```

### 5. The token

```bash
sudo install -m 0600 -o quilzo -g quilzo /dev/null /etc/quilzo/telegram.env
sudo editor /etc/quilzo/telegram.env
```

One line, and mind the mode:

```
QUILZO_TELEGRAM_TOKEN=123456:AA…
```

Never as a command-line argument. An argument is in `ps` output for every user
on the machine and in whatever a monitoring agent collects, and neither can be
taken back — which is why `quilzo telegram` has no `--token` flag to reach for.

### 6. The services

Edit the two hostnames in each file, then:

```bash
sudo cp deploy/quilzo-telegram.service deploy/quilzo-site.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now quilzo-site quilzo-telegram
sudo systemctl status quilzo-telegram
```

### 7. The certificate

Edit both hostnames in the `Caddyfile`, then:

```bash
sudo caddy run --config deploy/Caddyfile
```

Caddy gets and renews the certificate itself. That is the whole reason it is
here rather than nginx: a Mini App whose certificate expires stops opening, and
there is no cron job to have forgotten.

For a permanent install, `caddy add-package` / a `caddy.service` unit — the Caddy
documentation covers that better than this file would.

### 8. Check it from outside

```bash
curl -sI https://pages.example.com/health
curl -s  https://pages.example.com/health
```

The second should print `{"status":"ok"}` and nothing else. It deliberately says
nothing about the version, the store or whether a token is configured, because a
health endpoint is a public URL and every fact on it is free to whoever is
probing.

---

## The admin is deliberately not in any of this

It is loopback and it holds credentials. Putting it behind a public hostname is
the change that turns a compromise of the proxy into a compromise of the store.
Reach it over SSH instead:

```bash
ssh -N -L 8080:127.0.0.1:8080 you@your-server
# then open http://127.0.0.1:8080
```

---

## What to check before you submit

- `https://pages.example.com/` refuses a request with no link — a `403`, not a
  form. Anyone who finds the address without a credential gets nothing.
- `https://pages.example.com/terms` and `/privacy` both answer.
- Sending your bot `/start` produces a button, and the button opens the form.
- The certificate is valid and not from a tunnel you are going to close.
- `systemctl restart quilzo-telegram` and everything still answers.
