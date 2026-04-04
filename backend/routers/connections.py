"""Connection CRUD API routes."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import encrypt_value, get_db
from models.connection import SSHConnection
from models.tag import Tag, connection_tags
from schemas.connection import ConnectionCreate, ConnectionOut, ConnectionUpdate

router = APIRouter(prefix="/api/connections")


def _require_user(request: Request):
    user = getattr(request.state, "current_user", None)
    if not user:
        return None
    return user


def _conn_to_dict(conn: SSHConnection, tags: list[dict] | None = None) -> dict:
    return {
        "id": conn.id,
        "name": conn.name,
        "host": conn.host,
        "port": conn.port,
        "protocol": conn.protocol,
        "username": conn.username,
        "auth_method": conn.auth_method,
        "folder_id": conn.folder_id,
        "notes": conn.notes,
        "jump_host_id": conn.jump_host_id,
        "web_url": conn.web_url,
        "source": conn.source,
        "source_id": conn.source_id,
        "created_at": str(conn.created_at) if conn.created_at else None,
        "updated_at": str(conn.updated_at) if conn.updated_at else None,
        "tags": tags or [],
    }


@router.get("")
async def list_connections(
    request: Request,
    folder_id: int | None = None,
    tag: str | None = None,
    search: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    q = select(SSHConnection).where(SSHConnection.user_id == user.id)
    if folder_id is not None:
        q = q.where(SSHConnection.folder_id == folder_id)
    if search:
        q = q.where(
            SSHConnection.name.ilike(f"%{search}%")
            | SSHConnection.host.ilike(f"%{search}%")
        )
    q = q.order_by(SSHConnection.name)

    result = await db.execute(q)
    connections = result.scalars().all()

    # Load tags for each connection
    items = []
    for conn in connections:
        tag_rows = (await db.execute(
            select(Tag).join(connection_tags).where(connection_tags.c.connection_id == conn.id)
        )).scalars().all()
        tags_list = [{"id": t.id, "name": t.name, "color": t.color} for t in tag_rows]
        items.append(_conn_to_dict(conn, tags_list))

    return {"connections": items}


@router.post("")
async def create_connection(
    request: Request,
    body: ConnectionCreate,
    db: AsyncSession = Depends(get_db),
):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    conn = SSHConnection(
        user_id=user.id,
        name=body.name,
        host=body.host,
        port=body.port,
        protocol=body.protocol,
        username=body.username,
        auth_method=body.auth_method,
        folder_id=body.folder_id,
        notes=body.notes,
        jump_host_id=body.jump_host_id,
        web_url=body.web_url,
    )
    if body.password:
        conn.encrypted_password = encrypt_value(body.password)
    if body.private_key:
        conn.encrypted_key = encrypt_value(body.private_key)
    if body.key_passphrase:
        conn.key_passphrase = encrypt_value(body.key_passphrase)

    db.add(conn)
    await db.flush()

    # Set tags
    if body.tag_ids:
        for tag_id in body.tag_ids:
            await db.execute(connection_tags.insert().values(connection_id=conn.id, tag_id=tag_id))

    await db.commit()
    return _conn_to_dict(conn)


@router.delete("/all")
async def delete_all_connections(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    result = await db.execute(select(SSHConnection).where(SSHConnection.user_id == user.id))
    conns = result.scalars().all()
    count = len(conns)
    for conn in conns:
        await db.delete(conn)
    await db.commit()
    return {"ok": True, "deleted": count}


@router.post("/screenshots/refresh")
async def refresh_screenshots(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    from services.screenshots import refresh_all_screenshots
    result = await refresh_all_screenshots(db, user.id)
    return result


@router.get("/{conn_id}")
async def get_connection(request: Request, conn_id: int, db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    conn = await db.get(SSHConnection, conn_id)
    if not conn or (conn.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    tag_rows = (await db.execute(
        select(Tag).join(connection_tags).where(connection_tags.c.connection_id == conn.id)
    )).scalars().all()
    tags_list = [{"id": t.id, "name": t.name, "color": t.color} for t in tag_rows]

    return _conn_to_dict(conn, tags_list)


@router.put("/{conn_id}")
async def update_connection(
    request: Request,
    conn_id: int,
    body: ConnectionUpdate,
    db: AsyncSession = Depends(get_db),
):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    conn = await db.get(SSHConnection, conn_id)
    if not conn or (conn.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    for field in ("name", "host", "port", "protocol", "auth_method", "folder_id", "notes", "jump_host_id", "web_url"):
        val = getattr(body, field, None)
        if val is not None:
            setattr(conn, field, val)

    # Username: allow clearing with empty string
    if body.username is not None:
        conn.username = body.username if body.username else None

    if body.password is not None:
        conn.encrypted_password = encrypt_value(body.password) if body.password else None
    if body.private_key is not None:
        conn.encrypted_key = encrypt_value(body.private_key) if body.private_key else None
    if body.key_passphrase is not None:
        conn.key_passphrase = encrypt_value(body.key_passphrase) if body.key_passphrase else None

    if body.tag_ids is not None:
        await db.execute(delete(connection_tags).where(connection_tags.c.connection_id == conn.id))
        for tag_id in body.tag_ids:
            await db.execute(connection_tags.insert().values(connection_id=conn.id, tag_id=tag_id))

    await db.commit()
    return _conn_to_dict(conn)


@router.delete("/{conn_id}")
async def delete_connection(request: Request, conn_id: int, db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    conn = await db.get(SSHConnection, conn_id)
    if not conn or (conn.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    await db.delete(conn)
    await db.commit()
    return {"ok": True}


@router.post("/{conn_id}/test")
async def test_connection(request: Request, conn_id: int, db: AsyncSession = Depends(get_db)):
    """Test SSH connectivity to a saved connection."""
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    conn = await db.get(SSHConnection, conn_id)
    if not conn or (conn.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    if conn.protocol != "ssh":
        return JSONResponse({"error": "Only SSH connections can be tested"}, status_code=400)

    import asyncssh
    from models.base import decrypt_value

    try:
        kwargs: dict = {
            "host": conn.host,
            "port": conn.port,
            "username": conn.username,
            "known_hosts": None,
        }
        if conn.auth_method == "password" and conn.encrypted_password:
            kwargs["password"] = decrypt_value(conn.encrypted_password)
        elif conn.auth_method == "key" and conn.encrypted_key:
            key_data = decrypt_value(conn.encrypted_key)
            passphrase = decrypt_value(conn.key_passphrase) if conn.key_passphrase else None
            kwargs["client_keys"] = [asyncssh.import_private_key(key_data, passphrase)]

        async with asyncssh.connect(**kwargs) as ssh_conn:
            result = await ssh_conn.run("echo ok", check=True, timeout=5)
            return {"ok": True, "message": "Connection successful"}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=200)


@router.get("/{conn_id}/screenshot.jpg")
async def get_screenshot(request: Request, conn_id: int, db: AsyncSession = Depends(get_db)):
    """Serve cached screenshot image."""
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    conn = await db.get(SSHConnection, conn_id)
    if not conn or (conn.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    from services.screenshots import screenshot_path
    path = screenshot_path(conn.id)
    if not path.exists():
        return JSONResponse({"error": "No screenshot"}, status_code=404)

    return FileResponse(path, media_type="image/jpeg")


@router.post("/{conn_id}/screenshot")
async def capture_screenshot_endpoint(request: Request, conn_id: int,
                                      db: AsyncSession = Depends(get_db)):
    """Capture screenshot for a single connection."""
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    conn = await db.get(SSHConnection, conn_id)
    if not conn or (conn.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    if not conn.web_url:
        return JSONResponse({"error": "No web URL configured"}, status_code=400)

    from services.screenshots import capture_for_connection
    ok = await capture_for_connection(db, conn.id)
    return {"ok": ok}


