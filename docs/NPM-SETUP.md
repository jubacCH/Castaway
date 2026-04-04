# Nginx Proxy Manager Setup für Castaway

## Voraussetzungen

- Nginx Proxy Manager läuft bereits
- Domain zeigt auf NPM (z.B. `castaway.b8n.ch → <NPM-IP>`)
- Castaway läuft intern auf `10.10.30.58:8000`

## Proxy Host erstellen

**Details Tab:**
- **Domain Names**: `castaway.b8n.ch` (oder deine Domain)
- **Scheme**: `http`
- **Forward Hostname / IP**: `10.10.30.58`
- **Forward Port**: `8000`
- **Cache Assets**: Off
- **Block Common Exploits**: ✓ aktivieren
- **Websockets Support**: ✓ **UNBEDINGT aktivieren** (für SSH Terminal!)
- **Access List**: (optional — z.B. nur aus bestimmten IPs)

**SSL Tab:**
- **SSL Certificate**: Request new Let's Encrypt cert
- **Force SSL**: ✓ aktivieren
- **HTTP/2 Support**: ✓ aktivieren
- **HSTS Enabled**: ✓ aktivieren
- **HSTS Subdomains**: ✓ (wenn Wildcard Cert)

**Advanced Tab** (für WebSocket + lange SSH Sessions):

```nginx
# Increase timeouts for long-running SSH sessions
proxy_read_timeout 86400;
proxy_send_timeout 86400;

# WebSocket headers
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";

# Forward client IP
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header Host $host;

# Larger buffers for terminal output
proxy_buffer_size 128k;
proxy_buffers 4 256k;
proxy_busy_buffers_size 256k;
```

## Castaway Environment

Setze auf dem LXC in `/opt/castaway/.env`:

```env
POSTGRES_DB=castaway
POSTGRES_USER=castaway
POSTGRES_PASSWORD=<your-password>
SECURE_COOKIES=true
SESSION_DAYS=1
```

Dann neu starten:

```bash
cd /opt/castaway
docker compose restart castaway
```

**Was die Env bewirkt:**
- `SECURE_COOKIES=true` — Session-Cookies nur über HTTPS
- `SESSION_DAYS=1` — Session läuft nach 1 Tag ab (statt 7)

## Weitere Security-Empfehlungen

### 1. Access List mit Username/Password (Basic Auth als zusätzliche Schicht)
In NPM: **Access Lists** → neue Liste → Basic Auth User hinzufügen → Proxy Host zuweisen.
Dann müssen Angreifer erst die NPM Basic Auth knacken bevor sie überhaupt zur Castaway-Login-Seite kommen.

### 2. Fail2ban auf dem NPM-Host
NPM logt Auth-Failures — Fail2ban kann nach X Fehlversuchen die IP temporär bannen.

### 3. Cloudflare vor NPM (optional)
Für DDoS-Schutz + WAF → Cloudflare → NPM → Castaway.

### 4. MFA einschalten
Nach dem ersten Login via HTTPS-URL:
1. **Profile** → **Enable MFA**
2. QR Code mit Google Authenticator / Authy / 1Password scannen
3. 6-stelligen Code eingeben zum Bestätigen

## Testen

```bash
# Health check (sollte Redirect zu Login geben)
curl -I https://castaway.b8n.ch/

# WebSocket test (SSH terminal)
# Öffne eine Connection im Browser — SSH sollte funktionieren
```

Wenn WebSockets nicht funktionieren: **Websockets Support** im NPM Proxy Host einschalten!
