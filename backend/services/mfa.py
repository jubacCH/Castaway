"""MFA (TOTP) service — secret generation, verification, QR code."""

import base64
import io
import secrets as std_secrets

import pyotp
import qrcode

ISSUER = "Castaway"


def generate_secret() -> str:
    """Generate a new TOTP secret (base32, 20 bytes)."""
    return pyotp.random_base32(length=32)


def verify_code(secret: str, code: str) -> bool:
    """Verify a TOTP code. Allows 1 period of drift."""
    if not secret or not code:
        return False
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code.strip(), valid_window=1)
    except Exception:
        return False


def provisioning_uri(secret: str, username: str) -> str:
    """Build otpauth:// URI for QR code."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=ISSUER)


def qr_code_png(uri: str) -> bytes:
    """Generate QR code PNG from provisioning URI."""
    qr = qrcode.QRCode(version=1, box_size=8, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="white", back_color="#0f172a")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def generate_backup_codes(n: int = 8) -> list[str]:
    """Generate n single-use backup codes."""
    return [std_secrets.token_hex(5) for _ in range(n)]
