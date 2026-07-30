"""DepSentry REST API.

Run:  uvicorn api.main:app --reload --port 8000
Docs: http://127.0.0.1:8000/docs

Path handling note: scanning is a filesystem operation, so `project_path` is
resolved and checked against an allow-list root. Without that, the endpoint
would let a caller walk the server's disk.
"""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from depsentry.integrity import AuditLog  # noqa: E402
from depsentry.pipeline import scan_project  # noqa: E402
from depsentry.report import to_sarif  # noqa: E402
from depsentry.sbom import generate_sbom  # noqa: E402
from depsentry.vulndb import DEFAULT_DB, VulnerabilityDB  # noqa: E402

# Scans are confined to this root. Widen deliberately, never to "/".
ALLOWED_ROOT = ROOT

app = FastAPI(
    title="DepSentry API",
    version="1.0.0",
    description="Reachability-aware software supply chain risk analysis.",
)


class ScanRequest(BaseModel):
    project_path: str = Field(..., description="Path to the project root.")
    sign: bool = Field(False, description="Sign the SBOM with a demo HMAC key.")
    fail_on: float | None = Field(None, ge=0, le=10, description="CI gate threshold.")


def _safe_path(raw: str) -> Path:
    """Resolve a request path and refuse anything outside ALLOWED_ROOT."""
    candidate = (ALLOWED_ROOT / raw).resolve() if not Path(raw).is_absolute() \
        else Path(raw).resolve()
    try:
        candidate.relative_to(ALLOWED_ROOT.resolve())
    except ValueError:
        raise HTTPException(
            status_code=403,
            detail=f"Path must be inside {ALLOWED_ROOT}.",
        )
    if not candidate.is_dir():
        raise HTTPException(status_code=404, detail=f"No such directory: {raw}")
    return candidate


@app.get("/health")
def health() -> dict:
    with VulnerabilityDB(DEFAULT_DB) as db:
        count = db.count()
    return {"status": "ok", "advisories": count}


@app.get("/advisories")
def advisories(limit: int = 50) -> dict:
    with VulnerabilityDB(DEFAULT_DB) as db:
        items = db.all_advisories()[:limit]
    return {
        "count": len(items),
        "advisories": [
            {
                "id": a.vuln_id,
                "package": a.package,
                "cvss": a.cvss_score,
                "severity": a.severity.value,
                "fixed": a.fixed,
                "symbols": list(a.affected_symbols),
                "summary": a.summary,
            }
            for a in items
        ],
    }


@app.post("/scan")
def scan(request: ScanRequest) -> dict:
    path = _safe_path(request.project_path)
    result = scan_project(
        path,
        signing_key=b"depsentry-demo-key" if request.sign else None,
        audit_log_path=ROOT / "reports" / "audit.jsonl",
    )

    payload = result.to_dict()
    if request.fail_on is not None:
        breaching = [
            f for f in result.actionable_findings if f.risk_score >= request.fail_on
        ]
        payload["gate"] = {
            "threshold": request.fail_on,
            "passed": not breaching,
            "breaching": [f.vulnerability.vuln_id for f in breaching],
        }
    return payload


@app.post("/scan/sarif")
def scan_sarif(request: ScanRequest) -> dict:
    return to_sarif(scan_project(_safe_path(request.project_path)))


@app.post("/sbom")
def sbom(request: ScanRequest) -> dict:
    return generate_sbom(_safe_path(request.project_path)).to_cyclonedx()


@app.get("/audit/verify")
def audit_verify() -> dict:
    ok, message = AuditLog(ROOT / "reports" / "audit.jsonl").verify()
    return {"intact": ok, "message": message}
