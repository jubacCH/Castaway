# Castaway

Self-hosted SSH session manager for homelabs. Manage connections, open SSH terminals in the browser, sync hosts from phpIPAM, import credentials from Vaultwarden, and preview web interfaces — all in one place.

![Castaway](https://img.shields.io/badge/stack-FastAPI%20%2B%20Tailwind-blue) ![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **SSH in Browser** — xterm.js terminal via WebSocket + asyncssh
- **Connection Management** — CRUD with folders, tags, and search
- **phpIPAM Integration** — auto-sync hosts with custom field support (`SSH`, `Port_Web`)
- **Vaultwarden Integration** — import credentials with client-side vault decryption and auto-matching
- **Web Interface Previews** — Playwright screenshots of web UIs, shown as card thumbnails
- **Connection Status** — periodic TCP port checks with online/offline indicators
- **RDP Support** — `.rdp` file download with pre-filled credentials
- **Multi-User** — role-based access (admin/user), first user becomes admin
- **Session Audit Log** — who connected where, when, for how long
- **API Keys** — `X-API-Key` header auth for CLI and external integrations
- **CLI Tool** — `castaway list`, `castaway ssh`, `castaway sync phpipam`, etc.
- **Dark Theme** — Geist + Space Grotesk fonts, Material Symbols icons

## Quick Start

```bash
git clone https://github.com/jubacCH/Castaway.git
cd Castaway
cp .env.example .env
# Edit .env — set POSTGRES_PASSWORD
docker compose up -d --build
```

Open http://localhost:8000 and register your admin account.

## Architecture

```
Castaway/
├── backend/
│   ├── main.py              # FastAPI app, middleware, lifespan
│   ├── config.py             # DB URL, SECRET_KEY, DATA_DIR
│   ├── models/               # SQLAlchemy models (10 tables)
│   ├── routers/              # API endpoints
│   ├── services/             # Business logic
│   │   ├── phpipam.py        # phpIPAM API client + host sync
│   │   ├── vaultwarden.py    # Bitwarden API + vault decryption
│   │   ├── screenshots.py    # Playwright headless screenshots
│   │   ├── status_check.py   # TCP port check
│   │   └── scheduler.py      # Background jobs
│   ├── schemas/              # Pydantic request/response models
│   ├── templates/            # Jinja2 + Tailwind SSR pages
│   ├── static/               # CSS, JS
│   ├── alembic/              # Database migrations
│   ├── Dockerfile
│   └── requirements.txt
├── cli/                      # Typer CLI tool
├── docker-compose.yml
└── pyproject.toml            # CLI packaging
```

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI, async SQLAlchemy, asyncpg |
| Database | PostgreSQL 16 |
| Frontend | Jinja2 SSR, Tailwind CSS (CDN), Material Symbols |
| SSH | asyncssh + xterm.js via WebSocket |
| Screenshots | Playwright headless Chromium |
| Encryption | Fernet (PBKDF2, 480k iterations) |
| Auth | bcrypt, HMAC-SHA256 session tokens, API keys |
| CLI | Typer + httpx |
| Deploy | Docker Compose |

## Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_DB` | `castaway` | Database name |
| `POSTGRES_USER` | `castaway` | Database user |
| `POSTGRES_PASSWORD` | *required* | Database password |
| `SECRET_KEY` | auto-generated | Encryption key (persisted in `DATA_DIR/.secret_key`) |
| `PORT` | `8000` | Web UI port |
| `DNS_SERVER` | `10.10.10.2` | Internal DNS for container (for phpIPAM/SSH access) |
| `DEBUG` | `false` | Enable `/api/docs` (Swagger UI) |

### phpIPAM Custom Fields

Add these custom fields to phpIPAM addresses:

| Field | Type | Description |
|---|---|---|
| `SSH` | Boolean/Text | Set to "Yes" to import as SSH connection |
| `Port_Web` | Text/Number | Web interface port (e.g. `8006`). Auto-detects http/https |

### Vaultwarden Auto-Match

Vault entries are matched to connections when:
1. Entry name contains **"ssh"** (case-insensitive)
2. Connection FQDN (e.g. `proxmox.b8n.ch`) appears in the entry name

Name your vault entries like: `SSH proxmox.b8n.ch`, `SSH nas.example.com`

## CLI

Install the CLI:

```bash
pip install .
```

Configure:

```bash
castaway config set-url http://localhost:8000
castaway config set-key cw_your_api_key_here
```

Usage:

```bash
castaway list                          # List connections
castaway ssh proxmox                   # SSH via local client
castaway test 42                       # Test connection
castaway add myserver 10.0.1.5 -u root # Add connection
castaway rm 42                         # Remove connection
castaway sync phpipam 1                # Sync from phpIPAM config #1
castaway sync vaultwarden 1 --auto     # Auto-match + assign credentials
```

## API

All endpoints require authentication (session cookie or `X-API-Key` header).

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register` | Register (first user = admin) |
| POST | `/api/auth/login` | Login |
| GET | `/api/connections` | List connections |
| POST | `/api/connections` | Create connection |
| PUT | `/api/connections/{id}` | Update connection |
| DELETE | `/api/connections/{id}` | Delete connection |
| POST | `/api/connections/{id}/test` | Test SSH connectivity |
| WS | `/ws/ssh/{id}` | SSH terminal WebSocket |
| POST | `/api/phpipam/configs/{id}/sync` | Sync hosts from phpIPAM |
| GET | `/api/vaultwarden/configs/{id}/auto-match` | Auto-match credentials |
| POST | `/api/vaultwarden/configs/{id}/bulk-assign` | Assign matched credentials |
| POST | `/api/connections/screenshots/refresh` | Refresh all screenshots |
| POST | `/api/connections/status/refresh` | Check all connection ports |
| GET | `/api/settings` | Get app settings |
| GET/POST/DELETE | `/api/keys` | Manage API keys |

Enable `DEBUG=true` for full Swagger docs at `/api/docs`.

## Security

- Passwords encrypted at rest with Fernet (PBKDF2-SHA256, 480k iterations)
- Credentials never returned in API responses
- bcrypt (cost 12) for user passwords
- HMAC-SHA256 session tokens, 7-day expiry
- Account lockout after 5 failed logins (15 min, DB-persisted)
- CSRF protection (double-submit cookie)
- CSP, HSTS, X-Frame-Options headers
- Non-root Docker user
- Vaultwarden vault decryption is client-side (master password never sent in plaintext)

## License

MIT
