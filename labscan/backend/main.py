"""
LabScan : API FastAPI + service de l'interface web.

Lancement :  uvicorn backend.main:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import db, report
from .pipeline import WEB_STEPS, http_endpoints
from .scanners import SCANNERS, ScanOptionError
from .scope import ScopeError, check_osint_target, check_target, load_scope

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
MAX_PARALLEL_SCANS = 2

_semaphore = asyncio.Semaphore(MAX_PARALLEL_SCANS)
_tasks: set[asyncio.Task] = set()


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    yield
    for t in _tasks:
        t.cancel()


app = FastAPI(title="LabScan", version="0.3.0", lifespan=lifespan)


class ScanRequest(BaseModel):
    tool: str
    target: str = Field(min_length=1, max_length=253)
    preset: str | None = None
    ports: str | None = None


class PipelineRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)


def _spawn(coro) -> None:
    task = asyncio.create_task(coro)
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


async def _execute(scan_id: int, tool: str, target: str, options: dict) -> dict:
    async with _semaphore:
        db.set_status(scan_id, "running")
        result = await SCANNERS[tool].run(target, options)
        data = result.to_dict()
        db.save_result(scan_id, data)
        return data


async def _run_pipeline(pipeline_id: int, target: str) -> None:
    """nmap (services) -> whatweb + nikto sur chaque service HTTP découvert."""
    db.set_pipeline_status(pipeline_id, "running")
    try:
        nmap_opts = {"preset": "services", "ports": None}
        nmap_id = db.create_scan("nmap", target, "services", nmap_opts, pipeline_id)
        nmap_result = await _execute(nmap_id, "nmap", target, nmap_opts)

        for url in http_endpoints(nmap_result):
            for tool, preset in WEB_STEPS:
                if not SCANNERS[tool].is_available():
                    continue
                opts = {"preset": preset, "ports": None}
                sid = db.create_scan(tool, url, preset, opts, pipeline_id)
                await _execute(sid, tool, url, opts)
        db.set_pipeline_status(pipeline_id, "done", finished=True)
    except Exception:
        db.set_pipeline_status(pipeline_id, "error", finished=True)
        raise


@app.get("/api/tools")
def tools():
    return [s.info() for s in SCANNERS.values()]


@app.get("/api/scope")
def scope():
    return load_scope()


@app.post("/api/scans", status_code=202)
async def create_scan(req: ScanRequest):
    scanner = SCANNERS.get(req.tool)
    if scanner is None:
        raise HTTPException(404, f"outil inconnu : {req.tool}")
    if not scanner.is_available():
        raise HTTPException(409, f"{req.tool} n'est pas installé sur cette machine")

    guard = check_target if scanner.requires_scope else check_osint_target
    try:
        target = await asyncio.to_thread(guard, req.target)
    except ScopeError as exc:
        raise HTTPException(403, f"Cible refusée : {exc}") from exc

    options = {"preset": req.preset or next(iter(scanner.presets)), "ports": req.ports}
    try:
        scanner.build_command(target, options)  # validation des options avant mise en file
    except ScanOptionError as exc:
        raise HTTPException(422, str(exc)) from exc

    scan_id = db.create_scan(req.tool, target, options["preset"], options)
    _spawn(_execute(scan_id, req.tool, target, options))
    return {"id": scan_id, "status": "queued"}


@app.get("/api/scans")
def list_scans():
    return db.list_scans()


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int):
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "scan introuvable")
    return scan


@app.get("/api/scans/{scan_id}/export")
def export_scan(scan_id: int):
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "scan introuvable")
    return Response(
        json.dumps(scan, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="labscan-{scan_id}.json"'},
    )


@app.get("/api/scans/{scan_id}/pdf")
def scan_pdf(scan_id: int):
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "scan introuvable")
    return Response(
        report.scan_pdf(scan), media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="labscan-{scan_id}.pdf"'},
    )


@app.delete("/api/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: int):
    if not db.delete_scan(scan_id):
        raise HTTPException(404, "scan introuvable")


# --- Chaînes (pipelines) ---------------------------------------------------

@app.post("/api/pipelines", status_code=202)
async def create_pipeline(req: PipelineRequest):
    if not SCANNERS["nmap"].is_available():
        raise HTTPException(409, "nmap est requis pour lancer une chaîne")
    try:
        target = await asyncio.to_thread(check_target, req.target)
    except ScopeError as exc:
        raise HTTPException(403, f"Cible refusée : {exc}") from exc
    pipeline_id = db.create_pipeline(target)
    _spawn(_run_pipeline(pipeline_id, target))
    return {"id": pipeline_id, "status": "queued"}


@app.get("/api/pipelines")
def list_pipelines():
    return db.list_pipelines()


@app.get("/api/pipelines/{pipeline_id}")
def get_pipeline(pipeline_id: int):
    pipeline = db.get_pipeline(pipeline_id)
    if pipeline is None:
        raise HTTPException(404, "chaîne introuvable")
    return pipeline


@app.get("/api/pipelines/{pipeline_id}/pdf")
def pipeline_pdf(pipeline_id: int):
    pipeline = db.get_pipeline(pipeline_id)
    if pipeline is None:
        raise HTTPException(404, "chaîne introuvable")
    return Response(
        report.pipeline_pdf(pipeline), media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="labscan-chaine-{pipeline_id}.pdf"'},
    )


@app.delete("/api/pipelines/{pipeline_id}", status_code=204)
def delete_pipeline(pipeline_id: int):
    if not db.delete_pipeline(pipeline_id):
        raise HTTPException(404, "chaîne introuvable")


app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
