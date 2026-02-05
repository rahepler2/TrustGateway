"""
Nexus Trust Gateway — entry point (Flask server + CLI).

Usage:
  python app.py serve [--port 5000]
  python app.py scan flask==3.0.0,requests==2.31.0
  python app.py scan --ecosystem docker nginx==1.25
  python app.py bulk requirements.txt
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, Future
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .config import ScanVerdict, SCAN_WORKERS, FLASK_HOST, FLASK_PORT
from .pipeline import TrustGateway

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("trust-gateway")

# ---------------------------------------------------------------------------
# Thread pool + in-memory job/batch tracking
# ---------------------------------------------------------------------------

POOL = ThreadPoolExecutor(max_workers=SCAN_WORKERS)
JOBS: Dict[str, Dict] = {}
BATCHES: Dict[str, Dict] = {}
GATEWAY = TrustGateway()


def submit_scan_job(package: str, version: str, ecosystem: str = "pypi") -> str:
    job_id = str(uuid.uuid4())
    future = POOL.submit(GATEWAY.process_package, package, version, ecosystem)
    JOBS[job_id] = {
        "future": future,
        "package": package,
        "version": version,
        "ecosystem": ecosystem,
        "submitted_at": time.time(),
    }
    log.info(f"Submitted job {job_id} for {package}=={version} ({ecosystem})")
    return job_id


def get_job_status(job_id: str) -> Dict:
    info = JOBS.get(job_id)
    if not info:
        return {"error": "unknown job id"}
    future: Future = info["future"]
    status = "running"
    result = None
    if future.done():
        try:
            verdict, report = future.result(timeout=0)
            status = "done"
            result = {"verdict": verdict.value, "report": str(report)}
        except Exception as e:
            status = "error"
            result = {"error": str(e)}
    return {
        "job_id": job_id,
        "package": info["package"],
        "version": info["version"],
        "ecosystem": info["ecosystem"],
        "status": status,
        "result": result,
    }


def parse_spec(spec: str) -> Tuple[Optional[str], Optional[str]]:
    spec = spec.strip()
    if "==" in spec:
        p, v = spec.split("==", 1)
        return p.strip(), v.strip()
    return spec, None


# ---------------------------------------------------------------------------
# Flask server
# ---------------------------------------------------------------------------

def create_app():
    from flask import Flask, request as flask_request, jsonify

    app = Flask("trust-gateway")

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok"}), 200

    @app.route("/help", methods=["GET"])
    def help_endpoint():
        return jsonify({
            "description": "Nexus Trust Gateway API",
            "endpoints": {
                "POST /request": "Scan one or more pinned package==version specs",
                "POST /request/batch": "Upload requirements file to vet a batch",
                "POST /webhook/nexus": "Webhook for Nexus component-created events",
                "GET  /job/<job_id>": "Query single job status",
                "GET  /batch/<batch_id>/status": "Query batch status",
            },
            "ecosystems": ["pypi", "npm", "docker", "maven", "nuget"],
            "notes": "All package specs must be pinned (pkg==version).",
        }), 200

    @app.route("/webhook/nexus", methods=["POST"])
    def nexus_webhook():
        payload = flask_request.get_json(force=True)
        log.info("Received Nexus webhook")

        # Nexus webhook payload: {"component": {"name":..., "version":..., "format":...}}
        component = payload.get("component", {}) or {}
        package = component.get("name") or payload.get("package") or payload.get("name")
        version = component.get("version") or payload.get("version")
        fmt = (component.get("format") or payload.get("ecosystem") or "pypi").lower()

        # Map Nexus format names to our ecosystem keys
        eco_map = {"pypi": "pypi", "npm": "npm", "docker": "docker",
                    "maven2": "maven", "nuget": "nuget", "raw": "pypi"}
        ecosystem = eco_map.get(fmt, fmt)

        if not package or not version:
            return jsonify({"error": "missing package/version in payload"}), 400

        job_id = submit_scan_job(package, version, ecosystem)
        return jsonify({"status": "submitted", "job_id": job_id}), 202

    @app.route("/request", methods=["POST"])
    def request_package():
        data = flask_request.get_json(force=True)
        if not data:
            return jsonify({"error": "invalid json body"}), 400

        wait = int(data.get("wait", 120))
        ecosystem = data.get("ecosystem", "pypi").lower()

        pkg_list: List[Tuple[str, Optional[str]]] = []
        if "packages" in data:
            for spec in data["packages"]:
                p, v = parse_spec(spec)
                pkg_list.append((p, v))
        elif "package" in data and "version" in data:
            pkg_list.append((data["package"], data["version"]))
        elif "package" in data:
            for part in str(data["package"]).split(","):
                p, v = parse_spec(part)
                pkg_list.append((p, v))
        else:
            return jsonify({"error": "provide 'package' & 'version' or 'packages' list"}), 400

        unpinned = [p for (p, v) in pkg_list if v is None]
        if unpinned:
            return jsonify({"error": "unpinned package(s)", "unpinned": unpinned}), 400

        job_ids = [submit_scan_job(p, v, ecosystem) for p, v in pkg_list]

        if wait <= 0:
            return jsonify({"status": "accepted", "job_ids": job_ids}), 202

        start = time.time()
        remaining = wait
        done_results = {}
        for jid, (p, v) in zip(job_ids, pkg_list):
            fut = JOBS[jid]["future"]
            try:
                verdict, report = fut.result(timeout=remaining)
                done_results[jid] = {
                    "package": p, "version": v,
                    "verdict": verdict.value, "report": str(report),
                }
            except Exception as e:
                done_results[jid] = {"package": p, "version": v, "error": str(e)}
            remaining = max(0, wait - (time.time() - start))

        any_fail = any(d.get("verdict") not in ("pass", "warn") for d in done_results.values())
        return jsonify({"status": "completed", "results": done_results}), (409 if any_fail else 200)

    @app.route("/request/batch", methods=["POST"])
    def request_batch():
        ecosystem = "pypi"  # default; can be overridden in form data
        req_text = None

        if "requirements" in flask_request.files:
            f = flask_request.files["requirements"]
            req_text = f.read().decode("utf-8")
            ecosystem = flask_request.form.get("ecosystem", "pypi").lower()
        elif flask_request.is_json and "requirements_text" in flask_request.json:
            req_text = flask_request.json.get("requirements_text")
            ecosystem = flask_request.json.get("ecosystem", "pypi").lower()
        else:
            return jsonify({"error": "provide 'requirements' file or 'requirements_text'"}), 400

        items = []
        for raw in req_text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            line = line.split("#", 1)[0].strip()
            p, v = parse_spec(line)
            items.append((p, v))

        pinned = [(p, v) for (p, v) in items if v is not None]
        unpinned = [p for (p, v) in items if v is None]

        if not pinned:
            return jsonify({"error": "no pinned entries found", "unpinned": unpinned}), 400

        batch_id = str(uuid.uuid4())
        job_entries = []
        for pkg, ver in pinned:
            jid = submit_scan_job(pkg, ver, ecosystem)
            job_entries.append({"package": pkg, "version": ver, "job_id": jid})

        BATCHES[batch_id] = {
            "job_ids": [je["job_id"] for je in job_entries],
            "submitted_at": time.time(),
            "items": job_entries,
        }
        return jsonify({"batch_id": batch_id, "jobs": job_entries, "unpinned": unpinned}), 202

    @app.route("/job/<job_id>", methods=["GET"])
    def job_status(job_id):
        return jsonify(get_job_status(job_id)), 200

    @app.route("/batch/<batch_id>/status", methods=["GET"])
    def batch_status(batch_id):
        batch = BATCHES.get(batch_id)
        if not batch:
            return jsonify({"error": "unknown batch id"}), 404

        jobs_summary = []
        overall = "done"
        for entry in batch["items"]:
            js = get_job_status(entry["job_id"])
            jobs_summary.append({
                "job_id": entry["job_id"],
                "package": entry["package"],
                "version": entry["version"],
                "status": js.get("status"),
                "result": js.get("result"),
            })
            if js.get("status") == "running":
                overall = "running"
            elif js.get("status") == "error" and overall != "running":
                overall = "error"

        return jsonify({
            "batch_id": batch_id,
            "submitted_at": batch["submitted_at"],
            "overall": overall,
            "jobs": jobs_summary,
        }), 200

    return app


# ---------------------------------------------------------------------------
# CLI handlers
# ---------------------------------------------------------------------------

def cmd_scan(args):
    specs: List[str] = []
    for entry in (args.packages or []):
        for part in str(entry).split(","):
            if part.strip():
                specs.append(part.strip())

    if not specs:
        print("Provide at least one package spec (pkg==ver).")
        return 2

    ecosystem = args.ecosystem
    overall_rc = 0
    for spec in specs:
        pkg, ver = parse_spec(spec)
        if ver is None:
            log.warning(f"Skipping unpinned spec '{spec}'. Use pkg==version.")
            overall_rc = 2
            continue
        verdict, report = GATEWAY.process_package(pkg, ver, ecosystem)
        print(f"\nVerdict for {pkg}=={ver}: {verdict.value.upper()}")
        print(f"Report: {report}")
        if verdict == ScanVerdict.FAIL:
            overall_rc = 1
    return overall_rc


def cmd_bulk(args):
    ecosystem = args.ecosystem
    results = []
    with open(args.file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pkg, ver = parse_spec(line)
            if ver is None:
                log.warning(f"Skipping '{line}' — must use package==version")
                continue
            verdict, report = GATEWAY.process_package(pkg, ver, ecosystem)
            results.append((pkg, ver, verdict))

    print("\n" + "=" * 60)
    print("BULK SCAN SUMMARY")
    for pkg, ver, v in results:
        icon = "+" if v == ScanVerdict.PASS else "!" if v == ScanVerdict.WARN else "x"
        print(f"  [{icon}] {pkg}=={ver}: {v.value}")
    failed = sum(1 for _, _, v in results if v == ScanVerdict.FAIL)
    print(f"\n{len(results)} scanned, {failed} blocked")
    return 1 if failed > 0 else 0


def cmd_serve(args):
    app = create_app()
    port = args.port
    log.info(f"Starting Trust Gateway on 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port)
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Nexus Trust Gateway")
    subparsers = parser.add_subparsers(dest="command")

    scan_p = subparsers.add_parser("scan", help="Scan packages (pkg==ver, comma-separated)")
    scan_p.add_argument("packages", nargs="*", help="Package specs")
    scan_p.add_argument("--ecosystem", "-e", default="pypi",
                        choices=["pypi", "npm", "docker", "maven", "nuget"],
                        help="Package ecosystem (default: pypi)")

    bulk_p = subparsers.add_parser("bulk", help="Scan packages from a requirements file")
    bulk_p.add_argument("file", help="Requirements file path")
    bulk_p.add_argument("--ecosystem", "-e", default="pypi",
                        choices=["pypi", "npm", "docker", "maven", "nuget"])

    serve_p = subparsers.add_parser("serve", help="Run API server")
    serve_p.add_argument("--port", type=int, default=FLASK_PORT)

    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(cmd_scan(args))
    elif args.command == "bulk":
        sys.exit(cmd_bulk(args))
    elif args.command == "serve":
        sys.exit(cmd_serve(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
