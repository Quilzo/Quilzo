# Putting the published site on the internet

The public site needs two things the rest of the project does not: a real
certificate, and a process that comes back after a reboot. This directory has
both — a Caddyfile that gets and renews its own certificate, and a hardened
systemd unit.

Anything with 512 MB will do. This is one static binary and a directory.

### 1. A user and a place

```bash
sudo useradd --system --home /srv/quilzo --shell /usr/sbin/nologin quilzo
sudo install -d -o quilzo -g quilzo /srv/quilzo
sudo install -d -o quilzo -g quilzo /srv/quilzo/submissions
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

```
example.com         A   your.server.ip
```

### 5. The service

Edit the hostname in `--base-url`, then:

```bash
sudo cp deploy/quilzo-site.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now quilzo-site
sudo systemctl status quilzo-site
```

### 6. The certificate

Edit the hostname in the `Caddyfile`, then:

```bash
sudo caddy run --config deploy/Caddyfile
```

Caddy gets and renews the certificate itself, which is the whole reason it is
here rather than nginx: there is no cron job to have forgotten.

For a permanent install, `caddy add-package` / a `caddy.service` unit — the Caddy
documentation covers that better than this file would.

### 7. Check it from outside

```bash
curl -sI https://example.com/
```

---

## The admin is deliberately not in any of this

It is loopback and it holds credentials. Putting it behind a public hostname is
the change that turns a compromise of the proxy into a compromise of the store.
Reach it over SSH instead:

```bash
ssh -N -L 8080:127.0.0.1:8080 you@your-server
# then open http://127.0.0.1:8080
```
