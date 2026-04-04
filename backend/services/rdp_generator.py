"""Generate .rdp files with pre-filled connection settings."""


def generate_rdp(host: str, port: int = 3389, username: str | None = None,
                 fullscreen: bool = True) -> str:
    """Generate RDP file content."""
    lines = [
        f"full address:s:{host}:{port}",
        "prompt for credentials:i:1",
        f"screen mode id:i:{'2' if fullscreen else '1'}",
        "desktopwidth:i:1920",
        "desktopheight:i:1080",
        "session bpp:i:32",
        "compression:i:1",
        "keyboardhook:i:2",
        "audiocapturemode:i:0",
        "videoplaybackmode:i:1",
        "connection type:i:7",
        "networkautodetect:i:1",
        "bandwidthautodetect:i:1",
        "displayconnectionbar:i:1",
        "enableworkspacereconnect:i:0",
        "disable wallpaper:i:0",
        "allow font smoothing:i:1",
        "allow desktop composition:i:1",
        "disable full window drag:i:0",
        "disable menu anims:i:0",
        "disable themes:i:0",
        "disable cursor setting:i:0",
        "bitmapcachepersistenable:i:1",
        "autoreconnection enabled:i:1",
    ]
    if username:
        lines.append(f"username:s:{username}")

    return "\r\n".join(lines) + "\r\n"
