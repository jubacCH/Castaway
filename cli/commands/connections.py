"""Connection management CLI commands."""

import subprocess
import sys

import typer

from cli.api_client import api_delete, api_get, api_post

app = typer.Typer(help="Manage SSH connections")


@app.command("list")
def list_connections(
    folder: str | None = typer.Option(None, "--folder", "-f", help="Filter by folder ID"),
    search: str | None = typer.Option(None, "--search", "-s", help="Search by name or host"),
):
    """List all connections."""
    params = {}
    if folder:
        params["folder_id"] = folder
    if search:
        params["search"] = search

    data = api_get("/api/connections", params)
    conns = data.get("connections", [])

    if not conns:
        typer.echo("No connections found.")
        return

    # Table output
    typer.echo(f"{'ID':>4}  {'Name':<24} {'Host':<20} {'Port':>5}  {'User':<16} {'Source':<10}")
    typer.echo("-" * 90)
    for c in conns:
        name = (c["name"][:22] + "..") if len(c["name"]) > 24 else c["name"]
        host = (c["host"][:18] + "..") if len(c["host"]) > 20 else c["host"]
        user = (c["username"] or "-")[:16]
        typer.echo(f"{c['id']:>4}  {name:<24} {host:<20} {c['port']:>5}  {user:<16} {c['source']:<10}")

    typer.echo(f"\n{len(conns)} connection(s)")


@app.command("add")
def add_connection(
    name: str = typer.Argument(..., help="Connection name"),
    host: str = typer.Argument(..., help="Hostname or IP"),
    port: int = typer.Option(22, "--port", "-p", help="SSH port"),
    username: str = typer.Option(None, "--user", "-u", help="Username"),
    password: str = typer.Option(None, "--password", help="Password (will be encrypted)"),
):
    """Add a new SSH connection."""
    body = {
        "name": name,
        "host": host,
        "port": port,
        "protocol": "ssh",
        "auth_method": "password" if password else "agent",
        "username": username,
        "password": password,
    }
    data = api_post("/api/connections", body)
    typer.echo(f"Created connection '{data['name']}' (id={data['id']})")


@app.command("rm")
def remove_connection(
    conn_id: int = typer.Argument(..., help="Connection ID to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
):
    """Remove a connection."""
    if not force:
        typer.confirm(f"Delete connection {conn_id}?", abort=True)
    api_delete(f"/api/connections/{conn_id}")
    typer.echo(f"Deleted connection {conn_id}")


@app.command("test")
def test_connection(
    conn_id: int = typer.Argument(..., help="Connection ID to test"),
):
    """Test SSH connectivity."""
    data = api_post(f"/api/connections/{conn_id}/test")
    if data.get("ok"):
        typer.echo("Connection successful!")
    else:
        typer.echo(f"Failed: {data.get('error', 'unknown')}", err=True)
        raise typer.Exit(1)


@app.command("ssh")
def ssh_connect(
    name_or_id: str = typer.Argument(..., help="Connection name or ID"),
):
    """Open an SSH session to a connection (uses local ssh client)."""
    # Try as ID first
    try:
        conn_id = int(name_or_id)
        data = api_get(f"/api/connections/{conn_id}")
    except (ValueError, Exception):
        # Search by name
        results = api_get("/api/connections", {"search": name_or_id})
        conns = results.get("connections", [])
        if not conns:
            typer.echo(f"No connection found matching '{name_or_id}'", err=True)
            raise typer.Exit(1)
        if len(conns) > 1:
            typer.echo(f"Multiple matches for '{name_or_id}':")
            for c in conns:
                typer.echo(f"  {c['id']}: {c['name']} ({c['host']})")
            raise typer.Exit(1)
        data = conns[0]

    host = data["host"]
    port = data.get("port", 22)
    user = data.get("username")

    cmd = ["ssh"]
    if port != 22:
        cmd.extend(["-p", str(port)])
    if user:
        cmd.append(f"{user}@{host}")
    else:
        cmd.append(host)

    typer.echo(f"Connecting to {data['name']} ({' '.join(cmd)})...")
    sys.exit(subprocess.call(cmd))
