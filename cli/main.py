"""Castaway CLI — SSH Session Manager."""

import typer

from cli.commands import config, connections, sync

app = typer.Typer(
    name="castaway",
    help="Castaway — Self-hosted SSH Session Manager CLI",
    no_args_is_help=True,
)

# Sub-command groups
app.add_typer(connections.app, name="conn", help="Manage connections")
app.add_typer(sync.app, name="sync", help="Sync with phpIPAM / Vaultwarden")
app.add_typer(config.app, name="config", help="CLI configuration")

# Top-level shortcuts
app.command("list")(connections.list_connections)
app.command("ssh")(connections.ssh_connect)
app.command("add")(connections.add_connection)
app.command("rm")(connections.remove_connection)
app.command("test")(connections.test_connection)


@app.command("version")
def version():
    """Show Castaway CLI version."""
    typer.echo("Castaway CLI v0.1.0")


if __name__ == "__main__":
    app()
