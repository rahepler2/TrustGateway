#!/usr/bin/env python3
"""
nexus-request — CLI for requesting package vetting from Trust Gateway

Usage:
  # Submit a single package (blocks up to --wait seconds)
  nexus-request submit --package "requests==2.31.0" --wait 300

  # Submit multiple pinned specs (comma-separated)
  nexus-request submit --package "requests==2.31.0,flask==3.0.0" --wait 300

  # Submit a requirements file (multipart upload)
  nexus-request submit-batch --requirements requirements.txt --wait 600

  # Poll status of a job or batch
  nexus-request status --job <job_id>
  nexus-request status --batch <batch_id>

Environment:
  TRUST_GATEWAY_URL  default: http://trust-gateway:5000
  TRUST_GATEWAY_KEY  optional Bearer token for Authorization header
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Optional

import requests

TRUST_GATEWAY_URL = os.getenv("TRUST_GATEWAY_URL", "http://trust-gateway:5000").rstrip("/")
TRUST_GATEWAY_KEY = os.getenv("TRUST_GATEWAY_KEY")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "3"))

def auth_headers():
    h = {"Accept": "application/json"}
    if TRUST_GATEWAY_KEY:
        h["Authorization"] = f"Bearer {TRUST_GATEWAY_KEY}"
    return h

def submit_package(package_spec: str, wait: int = 120) -> dict:
    url = f"{TRUST_GATEWAY_URL}/request"
    payload = {"package": package_spec, "wait": wait}
    resp = requests.post(url, headers=auth_headers(), json=payload, timeout=10 + wait)
    try:
        return {"status_code": resp.status_code, "body": resp.json()}
    except Exception:
        return {"status_code": resp.status_code, "body": resp.text}

def submit_batch(requirements_path: str, wait: int = 300) -> dict:
    url = f"{TRUST_GATEWAY_URL}/request/batch"
    with open(requirements_path, "rb") as f:
        files = {"requirements": (requirements_path, f, "text/plain")}
        data = {"wait": str(wait)}
        resp = requests.post(url, headers=auth_headers(), files=files, data=data, timeout=30 + wait)
    try:
        return {"status_code": resp.status_code, "body": resp.json()}
    except Exception:
        return {"status_code": resp.status_code, "body": resp.text}

def get_job(job_id: str) -> dict:
    url = f"{TRUST_GATEWAY_URL}/job/{job_id}"
    resp = requests.get(url, headers=auth_headers(), timeout=10)
    try:
        return {"status_code": resp.status_code, "body": resp.json()}
    except Exception:
        return {"status_code": resp.status_code, "body": resp.text}

def get_batch(batch_id: str) -> dict:
    url = f"{TRUST_GATEWAY_URL}/batch/{batch_id}/status"
    resp = requests.get(url, headers=auth_headers(), timeout=10)
    try:
        return {"status_code": resp.status_code, "body": resp.json()}
    except Exception:
        return {"status_code": resp.status_code, "body": resp.text}

def wait_for_job(job_id: str, timeout: int = 300) -> dict:
    start = time.time()
    while time.time() - start < timeout:
        r = get_job(job_id)
        body = r.get("body") if isinstance(r.get("body"), dict) else {}
        status = body.get("status") if isinstance(body, dict) else None
        if status == "done" or status == "error":
            return r
        time.sleep(POLL_INTERVAL)
    return {"status_code": 202, "body": {"error": "timeout", "job_id": job_id}}

def wait_for_batch(batch_id: str, timeout: int = 900) -> dict:
    start = time.time()
    while time.time() - start < timeout:
        r = get_batch(batch_id)
        body = r.get("body") if isinstance(r.get("body"), dict) else {}
        overall = body.get("overall")
        if overall in ("done", "error"):
            return r
        time.sleep(POLL_INTERVAL)
    return {"status_code": 202, "body": {"error": "timeout", "batch_id": batch_id}}

def main():
    p = argparse.ArgumentParser(prog="nexus-request", description="Request package vetting from Trust Gateway")
    sp = p.add_subparsers(dest="cmd")

    submit = sp.add_parser("submit", help="Submit a package spec or comma-separated specs")
    submit.add_argument("--package", "-p", required=True, help="pkg==version or comma-separated list")
    submit.add_argument("--wait", type=int, default=120, help="Seconds to wait for completion per request")

    submitb = sp.add_parser("submit-batch", help="Upload requirements file (multipart)")
    submitb.add_argument("--requirements", "-r", required=True)
    submitb.add_argument("--wait", type=int, default=600, help="Total seconds to wait for batch completion")

    status = sp.add_parser("status", help="Query job or batch status")
    status.add_argument("--job", help="Job id")
    status.add_argument("--batch", help="Batch id")

    args = p.parse_args()

    if args.cmd == "submit":
        resp = submit_package(args.package, args.wait)
        code = resp["status_code"]
        print(json.dumps(resp["body"], indent=2) if isinstance(resp["body"], (dict, list)) else resp["body"])
        # If accepted (202) and user wants to wait, try to poll each job id if returned
        if code == 202:
            # returned {"status":"accepted","job_ids":[...]} or similar
            body = resp["body"] if isinstance(resp["body"], dict) else {}
            job_ids = body.get("job_ids") or body.get("job_ids", [])
            if job_ids:
                print("[INFO] Waiting for jobs to complete...")
                all_ok = True
                for jid in job_ids:
                    r = wait_for_job(jid, timeout=args.wait)
                    b = r.get("body") if isinstance(r.get("body"), dict) else {}
                    print(json.dumps(b, indent=2) if isinstance(b, dict) else b)
                    if b.get("result", {}).get("verdict") not in ("PASS", "WARN"):
                        all_ok = False
                sys.exit(0 if all_ok else 1)
        sys.exit(0 if code in (200, 201) else 2)

    elif args.cmd == "submit-batch":
        resp = submit_batch(args.requirements, args.wait)
        code = resp["status_code"]
        print(json.dumps(resp["body"], indent=2) if isinstance(resp["body"], (dict, list)) else resp["body"])
        if code == 202:
            batch_id = resp["body"].get("batch_id")
            if batch_id:
                print(f"[INFO] Waiting for batch {batch_id} up to {args.wait} seconds...")
                r = wait_for_batch(batch_id, timeout=args.wait)
                print(json.dumps(r.get("body", {}), indent=2) if isinstance(r.get("body"), dict) else r)
                final = r.get("body", {})
                # determine if any job failed
                failed = 0
                for job in final.get("jobs", []):
                    if job.get("result", {}).get("verdict") not in ("PASS", "WARN"):
                        failed += 1
                sys.exit(0 if failed == 0 else 1)
        sys.exit(0 if code in (200, 201) else 2)

    elif args.cmd == "status":
        if args.job:
            r = get_job(args.job)
            print(json.dumps(r.get("body", r), indent=2))
            sys.exit(0 if r["status_code"] == 200 else 2)
        if args.batch:
            r = get_batch(args.batch)
            print(json.dumps(r.get("body", r), indent=2))
            sys.exit(0 if r["status_code"] == 200 else 2)
        print("Provide --job or --batch")
        sys.exit(2)
    else:
        p.print_help()
        sys.exit(2)

if __name__ == "__main__":
    main()
