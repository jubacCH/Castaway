"""Shared Jinja2 templates with timezone-aware filters."""

from datetime import datetime, timezone as _tz
from html import escape as html_escape

from fastapi.templating import Jinja2Templates

try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo

templates = Jinja2Templates(directory="templates")


def localtime(dt, fmt=None):
    if dt is None:
        return "\u2014"
    if fmt is None:
        fmt = "%Y-%m-%d %H:%M:%S"
    return dt.strftime(fmt)


templates.env.filters["localtime"] = localtime


def _csrf_input(request):
    token = getattr(getattr(request, "state", None), "csrf_token", "")
    return f'<input type="hidden" name="csrf_token" value="{html_escape(token)}">'


def _csrf_meta(request):
    token = getattr(getattr(request, "state", None), "csrf_token", "")
    return f'<meta name="csrf-token" content="{html_escape(token)}">'


templates.env.globals["csrf_input"] = _csrf_input
templates.env.globals["csrf_meta"] = _csrf_meta
