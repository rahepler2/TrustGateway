#!/usr/bin/env python3
"""
nexus-request — Developer CLI for the Nexus Trust Gateway.

Usage:
  nexus-request scan requests==2.32.3
  nexus-request scan requests 2.32.3
  nexus-request scan nginx:1.25 -e docker
  nexus-request scan -f requirements.txt
  nexus-request scan -f package-lock.json -e npm
  nexus-request status <job_id>
  nexus-request status --batch <batch_id>

Environment:
  TRUST_GATEWAY_URL  default: http://localhost:5000
  TRUST_GATEWAY_KEY  optional Bearer token
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library required.  pip install requests")
    sys.exit(1)

GATEWAY_URL = os.getenv("TRUST_GATEWAY_URL", "http://localhost:5002").rstrip("/")
GATEWAY_KEY = os.getenv("TRUST_GATEWAY_KEY")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "3"))

# Map file extensions to ecosystems for auto-detection
FILE_ECOSYSTEM_MAP = {
    "requirements.txt": "pypi",
    "constraints.txt": "pypi",
    "package.json": "npm",
    "package-lock.json": "npm",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "packages.config": "nuget",
}


def _headers():
    h = {"Accept": "application/json"}
    if GATEWAY_KEY:
        h["Authorization"] = f"Bearer {GATEWAY_KEY}"
    return h


def _json(obj):
    if isinstance(obj, (dict, list)):
        print(json.dumps(obj, indent=2))
    else:
        print(obj)


def _detect_ecosystem(filename: str) -> str | None:
    base = os.path.basename(filename).lower()
    return FILE_ECOSYSTEM_MAP.get(base)


# ---------------------------------------------------------------------------
# API calls
# ---------------------------------------------------------------------------

def api_submit(spec: str, ecosystem: str, wait: int) -> dict:
    url = f"{GATEWAY_URL}/request"
    payload = {"package": spec, "ecosystem": ecosystem, "wait": wait}
    resp = requests.post(url, headers=_headers(), json=payload, timeout=10 + wait)
    try:
        return {"code": resp.status_code, "body": resp.json()}
    except Exception:
        return {"code": resp.status_code, "body": resp.text}


def api_submit_batch(filepath: str, ecosystem: str, wait: int) -> dict:
    url = f"{GATEWAY_URL}/request/batch"
    with open(filepath, "rb") as f:
        files = {"requirements": (os.path.basename(filepath), f, "text/plain")}
        data = {"wait": str(wait), "ecosystem": ecosystem}
        resp = requests.post(url, headers=_headers(), files=files, data=data, timeout=30 + wait)
    try:
        return {"code": resp.status_code, "body": resp.json()}
    except Exception:
        return {"code": resp.status_code, "body": resp.text}


def api_job(job_id: str) -> dict:
    resp = requests.get(f"{GATEWAY_URL}/job/{job_id}", headers=_headers(), timeout=10)
    try:
        return {"code": resp.status_code, "body": resp.json()}
    except Exception:
        return {"code": resp.status_code, "body": resp.text}


def api_batch(batch_id: str) -> dict:
    resp = requests.get(f"{GATEWAY_URL}/batch/{batch_id}/status", headers=_headers(), timeout=10)
    try:
        return {"code": resp.status_code, "body": resp.json()}
    except Exception:
        return {"code": resp.status_code, "body": resp.text}


# ---------------------------------------------------------------------------
# Polling
# ---------------------------------------------------------------------------

def poll_job(job_id: str, timeout: int) -> dict:
    short_id = job_id[:8]
    start = time.time()
    while time.time() - start < timeout:
        r = api_job(job_id)
        body = r.get("body") if isinstance(r.get("body"), dict) else {}
        status = body.get("status")
        if status in ("done", "error"):
            print()
            return r
        elapsed = int(time.time() - start)
        print(f"\r  Scanning {short_id}... {elapsed}s", end="", flush=True)
        time.sleep(POLL_INTERVAL)
    print()
    return {"code": 202, "body": {"error": "timeout", "job_id": job_id}}


def poll_batch(batch_id: str, timeout: int) -> dict:
    short_id = batch_id[:8]
    start = time.time()
    while time.time() - start < timeout:
        r = api_batch(batch_id)
        body = r.get("body") if isinstance(r.get("body"), dict) else {}
        if body.get("overall") in ("done", "error"):
            print()
            return r
        jobs = body.get("jobs", [])
        done = sum(1 for j in jobs if j.get("status") in ("done", "error"))
        elapsed = int(time.time() - start)
        print(f"\r  Batch {short_id}... {done}/{len(jobs)} done ({elapsed}s)", end="", flush=True)
        time.sleep(POLL_INTERVAL)
    print()
    return {"code": 202, "body": {"error": "timeout", "batch_id": batch_id}}


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_scan(args):
    ecosystem = args.ecosystem
    wait = args.wait

    # File-based batch scan
    if args.file:
        if not ecosystem:
            ecosystem = _detect_ecosystem(args.file) or "pypi"
        print(f"Scanning {args.file} ({ecosystem})...")
        resp = api_submit_batch(args.file, ecosystem, wait)
        _json(resp["body"])

        if resp["code"] == 202:
            batch_id = resp["body"].get("batch_id") if isinstance(resp["body"], dict) else None
            if batch_id:
                r = poll_batch(batch_id, wait)
                final = r.get("body", {})
                _json(final)
                failed = sum(
                    1 for job in final.get("jobs", [])
                    if isinstance(job.get("result"), dict)
                    and job["result"].get("verdict") not in ("pass", "warn")
                )
                sys.exit(0 if failed == 0 else 1)
        sys.exit(0 if resp["code"] in (200, 201) else 2)

    # Single package scan
    if not args.package:
        print("Error: provide a package name or use -f <file>")
        sys.exit(2)

    # Build spec from positional args: "requests 2.32.3" -> "requests==2.32.3"
    parts = args.package
    if len(parts) == 1:
        spec = parts[0]
    elif len(parts) == 2:
        name, version = parts
        # Auto-detect: "nginx:1.25" is docker, "pkg==ver" is already formatted
        if "==" in name or ":" in name:
            spec = name  # already formatted, ignore second arg
        else:
            spec = f"{name}=={version}"
    else:
        spec = parts[0]  # take the first, ignore the rest

    # Auto-detect docker from colon notation
    if not ecosystem and ":" in spec and "==" not in spec:
        ecosystem = "docker"
    ecosystem = ecosystem or "pypi"

    print(f"Scanning {spec} ({ecosystem})...")
    resp = api_submit(spec, ecosystem, wait)
    _json(resp["body"])

    if resp["code"] == 202:
        body = resp["body"] if isinstance(resp["body"], dict) else {}
        job_ids = body.get("job_ids", [])
        if job_ids:
            all_ok = True
            for jid in job_ids:
                r = poll_job(jid, timeout=wait)
                b = r.get("body") if isinstance(r.get("body"), dict) else {}
                _json(b)
                result = b.get("result", {})
                if isinstance(result, dict) and result.get("verdict") not in ("pass", "warn"):
                    all_ok = False
            sys.exit(0 if all_ok else 1)

    sys.exit(0 if resp["code"] in (200, 201) else 2)


def cmd_status(args):
    if args.batch:
        r = api_batch(args.batch)
        _json(r.get("body", r))
        sys.exit(0 if r["code"] == 200 else 2)

    if not args.id:
        print("Error: provide a job ID or --batch <batch_id>")
        sys.exit(2)

    r = api_job(args.id)
    _json(r.get("body", r))
    sys.exit(0 if r["code"] == 200 else 2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        prog="nexus-request",
        description="Nexus Trust Gateway — scan packages before they reach your machine",
    )
    sub = p.add_subparsers(dest="cmd")

    # scan
    s = sub.add_parser("scan", help="Scan a package or requirements file")
    s.add_argument("package", nargs="*", help="package==version or package version")
    s.add_argument("-f", "--file", help="requirements.txt, package-lock.json, etc.")
    s.add_argument("-e", "--ecosystem",
                   choices=["pypi", "npm", "docker", "maven", "nuget"],
                   help="Package ecosystem (auto-detected when possible)")
    s.add_argument("-w", "--wait", type=int, default=120,
                   help="Seconds to wait for results (default: 120)")

    # status
    st = sub.add_parser("status", help="Check scan status")
    st.add_argument("id", nargs="?", help="Job ID")
    st.add_argument("--batch", "-b", help="Batch ID")

    args = p.parse_args()

    if args.cmd == "scan":
        cmd_scan(args)
    elif args.cmd == "status":
        cmd_status(args)
    else:
        p.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
