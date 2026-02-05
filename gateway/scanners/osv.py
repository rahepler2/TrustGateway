"""
OSV-Scanner — checks the Open Source Vulnerabilities database for known
malware (MAL-*), advisories (GHSA-*, PYSEC-*, CVE-*), etc.

Uses local osv-scanner binary when available, falls back to the OSV REST API.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

import requests as http_requests

log = logging.getLogger("trust-gateway")


class OSVScanner:
    def scan(self, package: str, version: str, ecosystem: str, results_dir: Path) -> dict:
        log.info(f"[OSV] Checking {package}=={version} ({ecosystem})")

        if shutil.which("osv-scanner"):
            return self._scan_local(package, version, results_dir)

        return self._scan_api(package, version, ecosystem, results_dir)

    # -- local binary ---------------------------------------------------------

    def _scan_local(self, package: str, version: str, results_dir: Path) -> dict:
        output_file = results_dir / "osv-results.json"
        requirements_file = results_dir / "requirements.txt"
        requirements_file.write_text(f"{package}=={version}\n")

        cmd = [
            "osv-scanner", "scan",
            "--format", "json",
            "--lockfile", f"requirements.txt:{requirements_file}",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            log.error("[OSV] Local osv-scanner timed out")
            return {"skipped": True, "results": []}

        try:
            data = json.loads(result.stdout) if result.stdout.strip() else {"results": []}
        except json.JSONDecodeError:
            log.warning("[OSV] Could not parse local output")
            data = {"results": [], "raw_output": result.stdout[:500]}

        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
        return data

    # -- REST API fallback ----------------------------------------------------

    def _scan_api(self, package: str, version: str, ecosystem: str, results_dir: Path) -> dict:
        try:
            url = "https://api.osv.dev/v1/query"
            payload = {
                "package": {"name": package, "ecosystem": ecosystem},
                "version": version,
            }
            resp = http_requests.post(url, json=payload, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                return {"results": data.get("vulns", [])}
            log.warning(f"[OSV] API returned {resp.status_code}")
            return {"results": []}
        except Exception as e:
            log.warning(f"[OSV] API error: {e}")
            return {"results": []}
