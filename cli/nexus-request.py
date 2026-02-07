#!/usr/bin/env python3
"""
nexus-request — Developer CLI for the Nexus Trust Gateway.

Usage:
  nexus-request scan python requests
  nexus-request scan python requests==2.32.3
  nexus-request scan python requests 2.32.3
  nexus-request scan docker nginx:1.25
  nexus-request scan docker nginx 1.25
  nexus-request scan npm express@4.18.2
  nexus-request scan maven org.apache.commons:commons-lang3:3.14.0
  nexus-request scan python -f requirements.txt
  nexus-request scan npm -f package-lock.json
  nexus-request status <job_id>
  nexus-request status --batch <batch_id>

Environment:
  TRUST_GATEWAY_URL  default: http://localhost:5002
  TRUST_GATEWAY_KEY  optional API key (sent as X-API-Key header)
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

# Ecosystem aliases — accept common names
ECO_ALIASES = {
    "python": "pypi", "pypi": "pypi", "pip": "pypi",
    "node": "npm", "npm": "npm", "js": "npm",
    "docker": "docker", "container": "docker", "image": "docker",
    "maven": "maven", "java": "maven", "mvn": "maven",
    "nuget": "nuget", "dotnet": "nuget", "csharp": "nuget",
}

# Map filenames to ecosystems for -f auto-detection
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
        h["X-API-Key"] = GATEWAY_KEY
    return h


def _json(obj):
    if isinstance(obj, (dict, list)):
        print(json.dumps(obj, indent=2))
    else:
        print(obj)


def _resolve_ecosystem(name: str) -> str | None:
    return ECO_ALIASES.get(name.lower())


def _detect_ecosystem(filename: str) -> str | None:
    base = os.path.basename(filename).lower()
    return FILE_ECOSYSTEM_MAP.get(base)


def _split_spec(spec: str, ecosystem: str):
    """Split a package spec into (name, version). Handles ==, @, and docker colon notation."""
    if "==" in spec:
        p, v = spec.split("==", 1)
        return p.strip(), v.strip()
    if ecosystem == "npm" and "@" in spec:
        # handle @scope/pkg@ver and pkg@ver
        if spec.startswith("@") and spec.count("@") >= 2:
            idx = spec.rfind("@")
            return spec[:idx], spec[idx + 1:]
        elif not spec.startswith("@"):
            idx = spec.rfind("@")
            return spec[:idx], spec[idx + 1:]
    if ecosystem == "docker" and ":" in spec:
        idx = spec.rfind(":")
        return spec[:idx], spec[idx + 1:]
    if ecosystem == "maven" and spec.count(":") >= 2:
        parts = spec.rsplit(":", 1)
        return parts[0], parts[1]
    return spec, None


# ---------------------------------------------------------------------------
# API calls
# ---------------------------------------------------------------------------

def api_submit(name: str, version: str | None, ecosystem: str, wait: int) -> dict:
    url = f"{GATEWAY_URL}/request"
    payload = {"package": name, "ecosystem": ecosystem, "wait": wait}
    if version:
        payload["version"] = version
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
# Result display
# ---------------------------------------------------------------------------

def _print_result(body: dict):
    """Pretty-print a scan result."""
    if not isinstance(body, dict):
        print(body)
        return

    result = body.get("result")
    if not isinstance(result, dict):
        _json(body)
        return

    verdict = result.get("verdict", "unknown").upper()
    pkg = body.get("package", "?")
    ver = body.get("version", "?")
    eco = body.get("ecosystem", "?")

    color = {"PASS": "\033[32m", "WARN": "\033[33m", "FAIL": "\033[31m", "ERROR": "\033[31m"}
    reset = "\033[0m"
    c = color.get(verdict, "")

    print(f"  {c}{verdict}{reset}  {pkg}=={ver} ({eco})")
    if result.get("report"):
        print(f"  Report: {result['report']}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_scan(args):
    # Resolve ecosystem from first positional arg
    ecosystem = _resolve_ecosystem(args.ecosystem)
    if not ecosystem:
        print(f"Error: unknown ecosystem '{args.ecosystem}'")
        print(f"  Valid: python, docker, npm, maven, nuget")
        sys.exit(2)

    wait = args.wait

    # File-based batch scan
    if args.file:
        print(f"Scanning {args.file} ({ecosystem})...")
        resp = api_submit_batch(args.file, ecosystem, wait)

        if resp["code"] == 202:
            body = resp["body"] if isinstance(resp["body"], dict) else {}
            batch_id = body.get("batch_id")
            jobs = body.get("jobs", [])
            unpinned = body.get("unpinned", [])
            if unpinned:
                print(f"  Skipped {len(unpinned)} unpinned: {', '.join(unpinned)}")
            if batch_id:
                print(f"  Batch ID: {batch_id}")
                print(f"  Jobs: {len(jobs)}")
                for j in jobs:
                    print(f"    {j['job_id'][:8]}  {j['package']}=={j['version']}")
                r = poll_batch(batch_id, wait)
                final = r.get("body", {})
                failed = 0
                for job in final.get("jobs", []):
                    _print_result(job)
                    if isinstance(job.get("result"), dict):
                        if job["result"].get("verdict") not in ("pass", "warn"):
                            failed += 1
                sys.exit(0 if failed == 0 else 1)
        else:
            _json(resp["body"])
        sys.exit(0 if resp["code"] in (200, 201) else 2)

    # Single package scan
    if not args.package:
        print("Error: provide a package name or use -f <file>")
        print(f"  Example: nexus-request scan {args.ecosystem} requests")
        sys.exit(2)

    # Build name + version from remaining positional args
    parts = args.package
    if len(parts) >= 2:
        name_part = parts[0]
        ver_part = parts[1]
        if "==" in name_part or "@" in name_part or (ecosystem == "docker" and ":" in name_part):
            name, version = _split_spec(name_part, ecosystem)
        else:
            name = name_part
            version = ver_part
    elif len(parts) == 1:
        name, version = _split_spec(parts[0], ecosystem)
    else:
        print("Error: provide a package name")
        sys.exit(2)

    sep = ":" if ecosystem == "docker" and version else "=="
    label = f"{name}{sep}{version}" if version else name
    print(f"Scanning {label} ({ecosystem})...")

    resp = api_submit(name, version, ecosystem, wait)
    body = resp["body"] if isinstance(resp["body"], dict) else {}

    if resp["code"] == 202:
        job_ids = body.get("job_ids", [])
        if job_ids:
            for jid in job_ids:
                print(f"  Job ID: {jid}")
            all_ok = True
            for jid in job_ids:
                r = poll_job(jid, timeout=wait)
                b = r.get("body") if isinstance(r.get("body"), dict) else {}
                _print_result(b)
                result = b.get("result", {})
                if isinstance(result, dict) and result.get("verdict") not in ("pass", "warn"):
                    all_ok = False
            sys.exit(0 if all_ok else 1)
    elif resp["code"] == 200:
        results = body.get("results", {})
        all_ok = True
        for jid, r in results.items():
            v = r.get("verdict", "error")
            pkg = r.get("package", "?")
            ver = r.get("version", "?")
            color = {"pass": "\033[32m", "warn": "\033[33m"}.get(v, "\033[31m")
            print(f"  {color}{v.upper()}\033[0m  {pkg}=={ver}")
            if v not in ("pass", "warn"):
                all_ok = False
        sys.exit(0 if all_ok else 1)

    _json(body)
    sys.exit(2)


def cmd_status(args):
    if args.batch:
        r = api_batch(args.batch)
        body = r.get("body") if isinstance(r.get("body"), dict) else {}
        if isinstance(body, dict) and "jobs" in body:
            for job in body.get("jobs", []):
                _print_result(job)
        else:
            _json(body)
        sys.exit(0 if r["code"] == 200 else 2)

    if not args.id:
        print("Error: provide a job ID or --batch <batch_id>")
        sys.exit(2)

    r = api_job(args.id)
    body = r.get("body") if isinstance(r.get("body"), dict) else {}
    _print_result(body)
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

    # scan <ecosystem> [package] [version]
    s = sub.add_parser("scan", help="Scan a package or requirements file")
    s.add_argument("ecosystem", help="Ecosystem: python, docker, npm, maven, nuget")
    s.add_argument("package", nargs="*", help="Package name and optional version")
    s.add_argument("-f", "--file", help="requirements.txt, package-lock.json, etc.")
    s.add_argument("-w", "--wait", type=int, default=120,
                   help="Seconds to wait for results (default: 120)")

    # status <job_id> | --batch <batch_id>
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
