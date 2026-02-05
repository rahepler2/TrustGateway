#!/usr/bin/env python3
"""
nexus-request — Developer CLI for requesting package/container vetting
from the Nexus Trust Gateway.

Usage:
  # Submit a single PyPI package
  nexus-request submit --package "requests==2.31.0" --wait 300

  # Submit multiple pinned specs (comma-separated)
  nexus-request submit --package "requests==2.31.0,flask==3.0.0" --wait 300

  # Submit a Docker image for scanning
  nexus-request submit --package "nginx==1.25" --ecosystem docker --wait 600

  # Submit a requirements file (multipart upload)
  nexus-request submit-batch --requirements requirements.txt --wait 600

  # Poll status of a job or batch
  nexus-request status --job <job_id>
  nexus-request status --batch <batch_id>

Environment:
  TRUST_GATEWAY_URL  default: http://localhost:5000
  TRUST_GATEWAY_KEY  optional Bearer token for Authorization header
  POLL_INTERVAL      default: 3 (seconds between status polls)
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

TRUST_GATEWAY_URL = os.getenv("TRUST_GATEWAY_URL", "http://localhost:5000").rstrip("/")
TRUST_GATEWAY_KEY = os.getenv("TRUST_GATEWAY_KEY")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "3"))


def _headers():
    h = {"Accept": "application/json"}
    if TRUST_GATEWAY_KEY:
        h["Authorization"] = f"Bearer {TRUST_GATEWAY_KEY}"
    return h


def _print_json(obj):
    if isinstance(obj, (dict, list)):
        print(json.dumps(obj, indent=2))
    else:
        print(obj)


# ---------------------------------------------------------------------------
# API calls
# ---------------------------------------------------------------------------

def submit_package(spec: str, wait: int, ecosystem: str) -> dict:
    url = f"{TRUST_GATEWAY_URL}/request"
    payload = {"package": spec, "wait": wait, "ecosystem": ecosystem}
    resp = requests.post(url, headers=_headers(), json=payload, timeout=10 + wait)
    try:
        return {"status_code": resp.status_code, "body": resp.json()}
    except Exception:
        return {"status_code": resp.status_code, "body": resp.text}


def submit_batch(requirements_path: str, wait: int, ecosystem: str) -> dict:
    url = f"{TRUST_GATEWAY_URL}/request/batch"
    with open(requirements_path, "rb") as f:
        files = {"requirements": (os.path.basename(requirements_path), f, "text/plain")}
        data = {"wait": str(wait), "ecosystem": ecosystem}
        resp = requests.post(url, headers=_headers(), files=files, data=data, timeout=30 + wait)
    try:
        return {"status_code": resp.status_code, "body": resp.json()}
    except Exception:
        return {"status_code": resp.status_code, "body": resp.text}


def get_job(job_id: str) -> dict:
    url = f"{TRUST_GATEWAY_URL}/job/{job_id}"
    resp = requests.get(url, headers=_headers(), timeout=10)
    try:
        return {"status_code": resp.status_code, "body": resp.json()}
    except Exception:
        return {"status_code": resp.status_code, "body": resp.text}


def get_batch(batch_id: str) -> dict:
    url = f"{TRUST_GATEWAY_URL}/batch/{batch_id}/status"
    resp = requests.get(url, headers=_headers(), timeout=10)
    try:
        return {"status_code": resp.status_code, "body": resp.json()}
    except Exception:
        return {"status_code": resp.status_code, "body": resp.text}


# ---------------------------------------------------------------------------
# Polling helpers
# ---------------------------------------------------------------------------

def wait_for_job(job_id: str, timeout: int) -> dict:
    start = time.time()
    print(f"[INFO] Scanning in progress for job {job_id[:8]}... please wait.")
    while time.time() - start < timeout:
        r = get_job(job_id)
        body = r.get("body") if isinstance(r.get("body"), dict) else {}
        status = body.get("status")
        if status in ("done", "error"):
            return r
        elapsed = int(time.time() - start)
        print(f"\r[INFO] Scanning... ({elapsed}s elapsed)", end="", flush=True)
        time.sleep(POLL_INTERVAL)
    print()
    return {"status_code": 202, "body": {"error": "timeout", "job_id": job_id}}


def wait_for_batch(batch_id: str, timeout: int) -> dict:
    start = time.time()
    print(f"[INFO] Batch {batch_id[:8]}... scanning in progress.")
    while time.time() - start < timeout:
        r = get_batch(batch_id)
        body = r.get("body") if isinstance(r.get("body"), dict) else {}
        overall = body.get("overall")
        if overall in ("done", "error"):
            return r
        # Show per-job progress
        jobs = body.get("jobs", [])
        done_count = sum(1 for j in jobs if j.get("status") in ("done", "error"))
        elapsed = int(time.time() - start)
        print(f"\r[INFO] {done_count}/{len(jobs)} packages scanned ({elapsed}s elapsed)", end="", flush=True)
        time.sleep(POLL_INTERVAL)
    print()
    return {"status_code": 202, "body": {"error": "timeout", "batch_id": batch_id}}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        prog="nexus-request",
        description="Request package/container vetting from the Nexus Trust Gateway",
    )
    sp = p.add_subparsers(dest="cmd")

    # submit
    sub = sp.add_parser("submit", help="Submit package spec(s) for scanning")
    sub.add_argument("--package", "-p", required=True,
                     help="pkg==version or comma-separated list")
    sub.add_argument("--ecosystem", "-e", default="pypi",
                     choices=["pypi", "npm", "docker", "maven", "nuget"],
                     help="Package ecosystem (default: pypi)")
    sub.add_argument("--wait", "-w", type=int, default=120,
                     help="Seconds to wait for completion (default: 120)")

    # submit-batch
    batch = sp.add_parser("submit-batch", help="Upload requirements file for batch scanning")
    batch.add_argument("--requirements", "-r", required=True,
                       help="Path to requirements.txt / package-lock.json")
    batch.add_argument("--ecosystem", "-e", default="pypi",
                       choices=["pypi", "npm", "docker", "maven", "nuget"])
    batch.add_argument("--wait", "-w", type=int, default=600,
                       help="Total seconds to wait (default: 600)")

    # status
    stat = sp.add_parser("status", help="Query job or batch status")
    stat.add_argument("--job", help="Job ID")
    stat.add_argument("--batch", help="Batch ID")

    args = p.parse_args()

    if args.cmd == "submit":
        print(f"[INFO] Submitting {args.package} ({args.ecosystem}) to Trust Gateway...")
        resp = submit_package(args.package, args.wait, args.ecosystem)
        code = resp["status_code"]
        _print_json(resp["body"])

        if code == 202:
            body = resp["body"] if isinstance(resp["body"], dict) else {}
            job_ids = body.get("job_ids", [])
            if job_ids:
                all_ok = True
                for jid in job_ids:
                    r = wait_for_job(jid, timeout=args.wait)
                    print()
                    b = r.get("body") if isinstance(r.get("body"), dict) else {}
                    _print_json(b)
                    result = b.get("result", {})
                    if isinstance(result, dict):
                        verdict = result.get("verdict", "")
                        if verdict not in ("pass", "warn"):
                            all_ok = False
                sys.exit(0 if all_ok else 1)

        sys.exit(0 if code in (200, 201) else 2)

    elif args.cmd == "submit-batch":
        print(f"[INFO] Uploading {args.requirements} for batch scanning ({args.ecosystem})...")
        resp = submit_batch(args.requirements, args.wait, args.ecosystem)
        code = resp["status_code"]
        _print_json(resp["body"])

        if code == 202:
            batch_id = resp["body"].get("batch_id") if isinstance(resp["body"], dict) else None
            if batch_id:
                r = wait_for_batch(batch_id, timeout=args.wait)
                print()
                final = r.get("body", {})
                _print_json(final)
                failed = sum(
                    1 for job in final.get("jobs", [])
                    if isinstance(job.get("result"), dict)
                    and job["result"].get("verdict") not in ("pass", "warn")
                )
                sys.exit(0 if failed == 0 else 1)

        sys.exit(0 if code in (200, 201) else 2)

    elif args.cmd == "status":
        if args.job:
            r = get_job(args.job)
            _print_json(r.get("body", r))
            sys.exit(0 if r["status_code"] == 200 else 2)
        elif args.batch:
            r = get_batch(args.batch)
            _print_json(r.get("body", r))
            sys.exit(0 if r["status_code"] == 200 else 2)
        else:
            print("Provide --job <id> or --batch <id>")
            sys.exit(2)
    else:
        p.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
