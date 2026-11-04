# Putting the published site on the internet

The public site needs two things the rest of the project does not: a real
certificate, and a process that comes back after a reboot. This directory has
both — a Caddyfile that gets and renews its own certificate, and a hardened
systemd unit.

Anything with 512 MB will do. This is one static binary and a directory.

There are two ways to run it here: with Docker Compose, which is the next
section, or as a systemd service, which is the one after.

## With Docker Compose

`compose.yaml` runs the admin, the published site and Caddy over one store,
each container read-only, holding no capability and not running as root. You need Docker with the Compose plugin, and for a real site a
hostname whose DNS points at this machine (`localhost` works for a trial).

Every command below is run in this directory, in this order:

```bash
cd deploy
cp compose.env.example .env    # then set QUILZO_DOMAIN in .env
docker compose run --rm admin init
docker compose run --rm admin auditlog dir /srv/audit
docker compose run --rm admin config set network.trusted_proxies 172.31.250.10
docker compose run --rm admin demo --examples /srv/templates/examples
docker compose run --rm admin init --admin you
docker compose up -d
```

What each one is for:

- `init` makes the store, on the `store` volume. Every Quilzo container
  names `/srv/store` in its entrypoint, so a command given to
  `docker compose run` cannot lose it; and every one is read-only, so a
  write anywhere but a volume fails out loud rather than going into a
  container's own layer, which `--rm` would delete.
- `auditlog dir` points the store at the audit log that `logd` writes. From
  then on the admin and the site hand it their records over a socket and
  cannot open the log to change one; `quilzo logd status` says whether the
  separation is in force. (`docker compose run` starts `logd` first, so it
  is running for every step after this one.)
- `network.trusted_proxies` is Caddy's fixed address on the network it
  shares with the site, the one address the site believes `X-Forwarded-For`
  from (see the note in `compose.yaml`).
- `demo` installs Marginalia, the demonstration: a design, eleven pages and
  a small shop, published, so the site has something to serve the moment it
  starts. Its design goes to the `templates` volume, which the admin writes
  and the site reads; its example files go there too, because the rest of
  `/srv` is read-only. For a site of your own from the start, run
  `docker compose run --rm admin template use sections` instead: it writes a
  design and a sample page, and the site serves what you publish.
- `init --admin you` makes `you` the first administrator and prints the link
  that adds their passkey. Open it once.
- `up -d` starts everything, and `restart: unless-stopped` brings it back
  after a reboot.

To run an image you built from this checkout rather than a release, build
it with the version it is, so that `quilzo version` and the bill of
materials inside it say so (without `--build-arg VERSION` it is "dev"),
then name it in `.env`:

```bash
docker build --build-arg VERSION=v0.3.0 -t quilzo:0.3.0 ..
# and in .env: QUILZO_IMAGE=quilzo and QUILZO_VERSION=0.3.0
```

### Commands once there is an administrator

From `init --admin` on, the store asks every command who is asking. Give a
command an administrator's token through the environment, never on its
command line, where anybody on the machine can read it:

```bash
export QUILZO_TOKEN=...    # an administrator's token
docker compose run --rm -e QUILZO_TOKEN admin logd status
```

An administrator makes tokens in the admin. While the store has none at all,
the first, for the first administrator, is
`docker compose run --rm admin token issue first --principal you --ttl 1h`.

### What the containers do not do

An agent that runs a program (`quilzo agent run --program`) runs it in the
native agent box, which makes a user namespace of its own, and Docker's
default system call filter refuses that inside a container: `quilzo agent
backends` says so and why. Run those agents where Quilzo runs on the machine
itself, or with a backend that runs the box elsewhere (`agent backends` lists
them). Every other agent, and the rest of Quilzo, works here as it does
anywhere.

The store is the `store` volume, and it is kept until you delete it:
`docker compose down` stops the stack and keeps every volume; only
`docker compose down -v` throws them away.

## As a systemd service

### 1. A user and a place

```bash
sudo useradd --system --home /srv/quilzo --shell /usr/sbin/nologin quilzo
sudo install -d -o quilzo -g quilzo /srv/quilzo
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
`/srv/quilzo`, owned by `quilzo`, so the store is `/srv/quilzo/.quilzo`. Then
check it from the server, and make what the site writes:

```bash
sudo -u quilzo quilzo theme check --dir /srv/quilzo/templates
sudo -u quilzo quilzo --root /srv/quilzo/.quilzo site --prepare
```

The unit makes the store read-only to the site except the paths `--prepare`
lists, and the site confines itself to the same paths with Landlock: a flaw
in the one process facing the internet cannot reach the store's policy,
tokens or configuration.

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

Caddy connects to the site from 127.0.0.1, so to the site every visitor is
Caddy until it is told Caddy is a proxy. Turn on `site.trusted_proxy` to
believe the address Caddy forwards; a proxy on this machine is believed
without being named, and only there. Leave `network.trusted_proxies` empty:
it is the admin's list as well as the site's, and naming 127.0.0.1 in it
would let any program on this machine choose its address on both.

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

### Except what the identity provider calls

Provisioning (`quilzo scim`) and the identity provider's security events
(`quilzo signals`) are sent by the provider to the admin, so those two paths need
a public https address while everything else stays on loopback. The `Caddyfile`
has a block, commented out, that publishes `/scim/v2/` and `/sso/signals` and
answers 404 for every other path. Each endpoint authenticates the provider with a
bearer of its own, and the shield can turn either off (`scim`, `signals`).

Give the provider the same hostname the admin's single sign-on uses, since the
receiver's address is derived from it: the OIDC redirect URI, or the SAML
provider's `--url`.
