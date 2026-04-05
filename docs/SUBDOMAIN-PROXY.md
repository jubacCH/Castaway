# Subdomain Proxy Setup

Route external traffic to your internal web UIs via per-connection subdomains.
Target apps see their own root `/` — no path rewriting needed, everything works.

## Architecture

```
Internet
    ↓
*.apps.b8n.ch (DNS + NPM wildcard proxy)
    ↓
Castaway LXC (10.10.30.58:8000)
    ↓ (resolves slug from Host header → connection.subdomain)
Internal target (e.g. https://prxmx01.b8n.ch:8006)
```

## DNS Setup

Add to your DNS (e.g. phpIPAM, BIND, AdGuard):

```
*.apps.b8n.ch  A  <NPM-IP>
```

Single wildcard record. Every subdomain (`proxmox.apps.b8n.ch`, `homepage.apps.b8n.ch`, …) resolves to your NPM.

## NPM Setup

### 1. Wildcard SSL Certificate (DNS-01 Challenge)

You need a **wildcard cert** because individual certs per subdomain don't scale.

NPM → **SSL Certificates** → **Add SSL Certificate** → **Let's Encrypt**:
- Domain Names: `apps.b8n.ch`, `*.apps.b8n.ch`
- Use a DNS Challenge: **Yes**
- DNS Provider: (pick your DNS provider, e.g. Cloudflare)
- Credentials file (token from your DNS provider)
- Save

### 2. Catchall Proxy Host

NPM → **Hosts** → **Proxy Hosts** → **Add Proxy Host**:

**Details:**
- Domain Names: `*.apps.b8n.ch`
- Scheme: `http`
- Forward Hostname/IP: `10.10.30.58`
- Forward Port: `8000`
- **Websockets Support: ✓** (critical for live UIs)
- Block Common Exploits: ✓

**SSL:**
- SSL Certificate: select wildcard cert from step 1
- Force SSL: ✓
- HTTP/2: ✓
- HSTS: ✓

**Advanced:**
```nginx
# Forward original Host header (Castaway needs it to resolve subdomain)
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;

# Long timeouts for WebSocket + long-running apps
proxy_read_timeout 86400;
proxy_send_timeout 86400;
proxy_connect_timeout 60;

# WebSocket upgrade
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";

# Larger buffers for rich UIs
proxy_buffer_size 128k;
proxy_buffers 4 256k;
proxy_busy_buffers_size 256k;

# Disable request body limit (uploads)
client_max_body_size 0;
```

### 3. Main Castaway UI (if not already set up)

If Castaway UI itself is on a different subdomain (e.g. `castaway.b8n.ch`),
add another proxy host for it. **Important**: both hosts must share a parent
domain (`.b8n.ch`) so session cookies work across them.

## Castaway Settings

### Environment Variables

On the LXC in `/opt/castaway/.env`:

```env
SECURE_COOKIES=true
COOKIE_DOMAIN=.b8n.ch
SESSION_DAYS=1
```

`COOKIE_DOMAIN=.b8n.ch` makes the session cookie shared across
`castaway.b8n.ch` AND `*.apps.b8n.ch`.

Restart: `docker compose up -d`

### App Settings

Log into Castaway → **Settings** → set:
- **Proxy Domain**: `apps.b8n.ch`
- **Login URL**: `https://castaway.b8n.ch/login` (used for redirects when unauth subdomain access)

### Per-Connection Subdomain

Each connection can have a **Subdomain** slug. Auto-generated from the
connection name during phpIPAM sync (e.g. `prxmx01` from `prxmx01.b8n.ch`).
Editable in the connection form.

## Testing

1. Log in to `https://castaway.b8n.ch/`
2. Click **Open Web** on a connection — opens `https://<slug>.apps.b8n.ch/`
3. Your session cookie is already valid on the subdomain → no re-login
4. The target app sees its own root `/` → should work unchanged

## Troubleshooting

**"No connection found for subdomain"**
- The subdomain slug doesn't match any connection. Check in the connection form.

**Redirect loop to /login**
- Cookie isn't shared. Check:
  - `COOKIE_DOMAIN=.b8n.ch` is set
  - Main castaway UI and subdomains share the parent domain
  - Browser shows cookie with correct Domain

**WebSocket fails**
- NPM: Ensure "Websockets Support" is checked in proxy host
- NPM: Verify `proxy_set_header Upgrade` and `Connection "upgrade"` in Advanced

**HTTPS certificate warnings**
- Wildcard cert only covers one level. `*.apps.b8n.ch` does NOT cover `foo.bar.apps.b8n.ch`.
  Use single-level subdomain names.

**Apps break anyway**
- Some apps check `Origin:` header against a hardcoded hostname.
  Those need to be configured to trust the proxy subdomain.
- Some apps set `Secure` cookies that only work on their original domain
  when hardcoded. Usually still OK via `Domain=` rewrite in Castaway.
