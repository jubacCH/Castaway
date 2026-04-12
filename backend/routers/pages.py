"""Server-side rendered pages."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import get_db
from models.connection import SSHConnection
from models.folder import Folder
from models.tag import Tag, connection_tags
from templating import templates

router = APIRouter()


@router.get("/")
async def index(request: Request):
    return RedirectResponse(url="/connections", status_code=302)


@router.get("/login")
async def login_page(request: Request):
    user = getattr(request.state, "current_user", None)
    if user:
        return RedirectResponse(url="/connections", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request})


@router.get("/register")
async def register_page(request: Request, db: AsyncSession = Depends(get_db)):
    from models.user import User
    user_count = (await db.execute(select(func.count()).select_from(User))).scalar() or 0
    if user_count > 0:
        user = getattr(request.state, "current_user", None)
        if not user or user.role != "admin":
            return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("register.html", {"request": request, "first_user": user_count == 0})


@router.get("/connections")
async def connections_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = getattr(request.state, "current_user", None)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    # Load connections
    result = await db.execute(
        select(SSHConnection).where(SSHConnection.user_id == user.id).order_by(SSHConnection.name)
    )
    connections = result.scalars().all()

    # Load folders
    folders = (await db.execute(
        select(Folder).where(Folder.user_id == user.id).order_by(Folder.sort_order, Folder.name)
    )).scalars().all()

    # Load tags
    tags = (await db.execute(
        select(Tag).where(Tag.user_id == user.id).order_by(Tag.name)
    )).scalars().all()

    # Attach tags + session stats to connections — batched to avoid N+1 queries
    from models.session_log import SessionLog
    conn_ids = [c.id for c in connections]
    conn_list = []

    if conn_ids:
        # Batch load all tags for all connections in one query
        tag_rows_all = (await db.execute(
            select(connection_tags.c.connection_id, Tag)
            .join(Tag, connection_tags.c.tag_id == Tag.id)
            .where(connection_tags.c.connection_id.in_(conn_ids))
        )).all()
        tags_by_conn: dict[int, list] = {cid: [] for cid in conn_ids}
        for row in tag_rows_all:
            tags_by_conn[row.connection_id].append(row[1])

        # Batch load session counts per connection in one query
        count_rows = (await db.execute(
            select(SessionLog.connection_id, func.count().label("cnt"))
            .where(SessionLog.connection_id.in_(conn_ids))
            .group_by(SessionLog.connection_id)
        )).all()
        counts_by_conn: dict[int, int] = {row.connection_id: row.cnt for row in count_rows}

        # Batch load latest session per connection using a subquery
        subq = (
            select(
                SessionLog.connection_id,
                func.max(SessionLog.started_at).label("max_started"),
            )
            .where(SessionLog.connection_id.in_(conn_ids))
            .group_by(SessionLog.connection_id)
            .subquery()
        )
        last_sessions_rows = (await db.execute(
            select(SessionLog).join(
                subq,
                and_(
                    SessionLog.connection_id == subq.c.connection_id,
                    SessionLog.started_at == subq.c.max_started,
                ),
            )
        )).scalars().all()
        last_by_conn: dict[int, object] = {s.connection_id: s for s in last_sessions_rows}
    else:
        tags_by_conn = {}
        counts_by_conn = {}
        last_by_conn = {}

    for conn in connections:
        conn_list.append({
            "conn": conn,
            "tags": tags_by_conn.get(conn.id, []),
            "session_count": counts_by_conn.get(conn.id, 0),
            "last_session": last_by_conn.get(conn.id),
        })

    # Load proxy_domain for subdomain links
    from models.setting import Setting
    pd_row = await db.get(Setting, "proxy_domain")
    proxy_domain = pd_row.value if pd_row else ""

    return templates.TemplateResponse("connections/list.html", {
        "request": request,
        "connections": conn_list,
        "folders": folders,
        "tags": tags,
        "user": user,
        "proxy_domain": proxy_domain,
    })


@router.get("/connections/new")
async def connection_new_page(request: Request, db: AsyncSession = Depends(get_db)):
    user = getattr(request.state, "current_user", None)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    folders = (await db.execute(
        select(Folder).where(Folder.user_id == user.id).order_by(Folder.name)
    )).scalars().all()
    tags = (await db.execute(
        select(Tag).where(Tag.user_id == user.id).order_by(Tag.name)
    )).scalars().all()

    return templates.TemplateResponse("connections/form.html", {
        "request": request,
        "connection": None,
        "folders": folders,
        "tags": tags,
        "user": user,
    })


@router.get("/connections/{conn_id}/edit")
async def connection_edit_page(request: Request, conn_id: int, db: AsyncSession = Depends(get_db)):
    user = getattr(request.state, "current_user", None)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    conn = await db.get(SSHConnection, conn_id)
    if not conn or (conn.user_id != user.id and user.role != "admin"):
        return RedirectResponse(url="/connections", status_code=302)

    folders = (await db.execute(
        select(Folder).where(Folder.user_id == user.id).order_by(Folder.name)
    )).scalars().all()
    tags = (await db.execute(
        select(Tag).where(Tag.user_id == user.id).order_by(Tag.name)
    )).scalars().all()
    selected_tags = (await db.execute(
        select(Tag).join(connection_tags).where(connection_tags.c.connection_id == conn.id)
    )).scalars().all()

    return templates.TemplateResponse("connections/form.html", {
        "request": request,
        "connection": conn,
        "folders": folders,
        "tags": tags,
        "selected_tag_ids": [t.id for t in selected_tags],
        "user": user,
    })


@router.get("/terminal/{conn_id}")
async def terminal_page(request: Request, conn_id: int, db: AsyncSession = Depends(get_db)):
    user = getattr(request.state, "current_user", None)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    conn = await db.get(SSHConnection, conn_id)
    if not conn or (conn.user_id != user.id and user.role != "admin"):
        return RedirectResponse(url="/connections", status_code=302)

    return templates.TemplateResponse("terminal.html", {
        "request": request,
        "connection": conn,
        "user": user,
    })


@router.get("/profile")
async def profile_page(request: Request):
    user = getattr(request.state, "current_user", None)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("profile.html", {
        "request": request, "user": user,
    })


@router.get("/sessions")
async def sessions_page(request: Request):
    user = getattr(request.state, "current_user", None)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("sessions/list.html", {
        "request": request,
        "user": user,
    })


@router.get("/users")
async def users_page(request: Request):
    user = getattr(request.state, "current_user", None)
    if not user or user.role != "admin":
        return RedirectResponse(url="/connections", status_code=302)
    return templates.TemplateResponse("users/list.html", {
        "request": request,
        "user": user,
    })


@router.get("/settings")
async def settings_page(request: Request):
    user = getattr(request.state, "current_user", None)
    if not user or user.role != "admin":
        return RedirectResponse(url="/connections", status_code=302)
    return templates.TemplateResponse("settings/general.html", {
        "request": request,
        "user": user,
    })


@router.get("/settings/phpipam")
async def phpipam_page(request: Request):
    user = getattr(request.state, "current_user", None)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("settings/phpipam.html", {
        "request": request,
        "user": user,
    })


@router.get("/settings/vaultwarden")
async def vaultwarden_page(request: Request):
    user = getattr(request.state, "current_user", None)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("settings/vaultwarden.html", {
        "request": request,
        "user": user,
    })
