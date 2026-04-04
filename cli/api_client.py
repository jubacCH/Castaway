"""HTTP client wrapper for the Castaway REST API."""

import json
import sys
from pathlib import Path

import httpx

CONFIG_DIR = Path.home() / ".config" / "castaway"
CONFIG_FILE = CONFIG_DIR / "config.json"


def _load_config() -> dict:
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {}


def _save_config(cfg: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


def get_url() -> str:
    cfg = _load_config()
    url = cfg.get("url", "")
    if not url:
        print("Error: API URL not configured. Run: castaway config set-url <url>", file=sys.stderr)
        sys.exit(1)
    return url.rstrip("/")


def get_api_key() -> str:
    cfg = _load_config()
    key = cfg.get("api_key", "")
    if not key:
        print("Error: API key not configured. Run: castaway config set-key <key>", file=sys.stderr)
        sys.exit(1)
    return key


def set_config(key: str, value: str):
    cfg = _load_config()
    cfg[key] = value
    _save_config(cfg)


def api_get(path: str, params: dict | None = None) -> dict:
    url = get_url()
    key = get_api_key()
    with httpx.Client(timeout=15) as client:
        resp = client.get(f"{url}{path}", params=params, headers={"X-API-Key": key})
        resp.raise_for_status()
        return resp.json()


def api_post(path: str, data: dict | None = None) -> dict:
    url = get_url()
    key = get_api_key()
    with httpx.Client(timeout=30) as client:
        resp = client.post(f"{url}{path}", json=data, headers={"X-API-Key": key})
        resp.raise_for_status()
        return resp.json()


def api_delete(path: str) -> dict:
    url = get_url()
    key = get_api_key()
    with httpx.Client(timeout=15) as client:
        resp = client.delete(f"{url}{path}", headers={"X-API-Key": key})
        resp.raise_for_status()
        return resp.json()
