"""Sync commands for phpIPAM and Vaultwarden."""

import typer

from cli.api_client import api_get, api_post

app = typer.Typer(help="Sync with external sources")


@app.command("phpipam")
def sync_phpipam(
    config_id: int = typer.Argument(..., help="phpIPAM config ID"),
):
    """Sync hosts from phpIPAM."""
    typer.echo(f"Syncing from phpIPAM config {config_id}...")
    data = api_post(f"/api/phpipam/configs/{config_id}/sync")

    typer.echo(f"  Added:   {data.get('added', 0)}")
    typer.echo(f"  Updated: {data.get('updated', 0)}")
    typer.echo(f"  Skipped: {data.get('skipped', 0)}")

    errors = data.get("errors", [])
    if errors:
        typer.echo(f"  Errors:  {len(errors)}")
        for e in errors[:5]:
            typer.echo(f"    - {e}")


@app.command("vaultwarden")
def sync_vaultwarden(
    config_id: int = typer.Argument(..., help="Vaultwarden config ID"),
    auto: bool = typer.Option(False, "--auto", help="Auto-match and assign without confirmation"),
):
    """Sync credentials from Vaultwarden and auto-match to connections."""
    typer.echo(f"Fetching matches from Vaultwarden config {config_id}...")
    data = api_get(f"/api/vaultwarden/configs/{config_id}/auto-match")

    matches = data.get("matches", [])
    if not matches:
        typer.echo("No matches found.")
        return

    typer.echo(f"Found {len(matches)} match(es):")
    for m in matches:
        typer.echo(f"  {m['connection_name']} ({m['connection_host']}) <- {m['credential_name']} ({m['credential_username']}) [{m['match_type']}]")

    if not auto:
        typer.confirm("Apply these matches?", abort=True)

    assignments = [{"connection_id": m["connection_id"], "credential_id": m["credential_id"]} for m in matches]
    result = api_post(f"/api/vaultwarden/configs/{config_id}/bulk-assign", {"assignments": assignments})

    typer.echo(f"\nAssigned: {result.get('assigned', 0)}")
    errors = result.get("errors", [])
    if errors:
        for e in errors:
            typer.echo(f"  Error: {e}", err=True)


@app.command("list-phpipam")
def list_phpipam():
    """List phpIPAM configurations."""
    data = api_get("/api/phpipam/configs")
    configs = data.get("configs", [])
    if not configs:
        typer.echo("No phpIPAM configs.")
        return
    for c in configs:
        typer.echo(f"  {c['id']}: {c['name']} ({c['url']}) last_sync={c.get('last_sync_at', 'never')}")


@app.command("list-vaultwarden")
def list_vaultwarden():
    """List Vaultwarden configurations."""
    data = api_get("/api/vaultwarden/configs")
    configs = data.get("configs", [])
    if not configs:
        typer.echo("No Vaultwarden configs.")
        return
    for c in configs:
        typer.echo(f"  {c['id']}: {c['name']} ({c['url']}) last_sync={c.get('last_sync_at', 'never')}")
