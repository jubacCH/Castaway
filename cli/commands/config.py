"""CLI configuration commands."""

import typer

from cli.api_client import CONFIG_FILE, set_config

app = typer.Typer(help="Configure CLI settings")


@app.command("set-url")
def set_url(url: str = typer.Argument(..., help="Castaway API URL (e.g. http://localhost:8000)")):
    """Set the Castaway API base URL."""
    set_config("url", url.rstrip("/"))
    typer.echo(f"API URL set to: {url}")


@app.command("set-key")
def set_key(key: str = typer.Argument(..., help="API key")):
    """Set the API key for authentication."""
    set_config("api_key", key)
    typer.echo("API key saved.")


@app.command("show")
def show():
    """Show current CLI configuration."""
    if CONFIG_FILE.exists():
        typer.echo(CONFIG_FILE.read_text())
    else:
        typer.echo("No configuration found. Run 'castaway config set-url' first.")


@app.command("path")
def config_path():
    """Show config file path."""
    typer.echo(str(CONFIG_FILE))
