"""Server-side rendered pages."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
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

    # Attach tags + session stats to connections
    from models.session_log import SessionLog
    conn_list = []
    for conn in connections:
        tag_rows = (await db.execute(
            select(Tag).join(connection_tags).where(connection_tags.c.connection_id == conn.id)
        )).scalars().all()
        session_count = (await db.execute(
            select(func.count()).select_from(SessionLog).where(SessionLog.connection_id == conn.id)
        )).scalar() or 0
        last_session = (await db.execute(
            select(SessionLog).where(SessionLog.connection_id == conn.id)
            .order_by(SessionLog.started_at.desc()).limit(1)
        )).scalar_one_or_none()
        conn_list.append({
            "conn": conn, "tags": tag_rows,
            "session_count": session_count,
            "last_session": last_session,
        })

    return templates.TemplateResponse("connections/list.html", {
        "request": request,
        "connections": conn_list,
        "folders": folders,
        "tags": tags,
        "user": user,
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
