"""
Nexus Trust Gateway — Package Scanning Orchestrator (server + CLI)
=================================================================

Purpose
-------
Lightweight orchestrator that:
 - Scans single packages, a comma-separated list, or a requirements file
 - Supports CLI usage (scan, bulk) and server mode (webhook, request endpoints)
 - Keeps the original step-by-step console output so developers see progress
 - Runs package behavioral analysis in container if available (no dev-local install required)
 - Uses environment variables only for configuration (no secrets in source)

Behavior
--------
CLI:
  - python orchestrator.py scan pkg==1.2.3 [,pkg2==2.3.4,...]
  - python orchestrator.py bulk requirements.txt
  - python orchestrator.py serve --port 5000

Server endpoints:
  - POST /webhook/nexus           (Nexus component created webhook -> async scan job)
  - POST /request                (synchronous request for one or multiple package==version specs;
                                  will wait (optional) and return result or job id)
  - POST /request/batch          (multipart upload of requirements file; returns batch_id)
  - GET  /job/<job_id>           (job status)
  - GET  /batch/<batch_id>/status (batch status)

Notes
-----
- Provide NEXUS_USER and NEXUS_PASS via environment variables.
- Ensure services run on the same Docker network (nexus:8081, trivy-server:8080 by default).
- This is a PoC / lightweight orchestrator. Persist job/batch state to a DB for production.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests as http_requests

# ---------------------------------------------------------------------------
# Configuration (env-driven)
# ---------------------------------------------------------------------------

@dataclass
class NexusConfig:
    base_url: str = os.getenv("NEXUS_URL", "http://nexus:8081")
    username: Optional[str] = os.getenv("NEXUS_USER")
    password: Optional[str] = os.getenv("NEXUS_PASS")
    proxy_repo: str = os.getenv("NEXUS_PROXY_REPO", "pypi-upstream")
    quarantine_repo: str = os.getenv("NEXUS_QUARANTINE_REPO", "pypi-quarantine")
    trusted_repo: str = os.getenv("NEXUS_TRUSTED_REPO", "pypi-trusted")
    group_repo: str = os.getenv("NEXUS_GROUP_REPO", "pypi-group")


@dataclass
class TrivyConfig:
    server_url: str = os.getenv("TRIVY_SERVER_URL", "http://trivy-server:8080")
    container_name: str = os.getenv("TRIVY_CONTAINER", "trivy-server")


@dataclass
class ScanPolicy:
    max_cvss_score: float = float(os.getenv("POLICY_MAX_CVSS", "7.0"))
    block_on_critical: bool = os.getenv("POLICY_BLOCK_CRITICAL", "true").lower() == "true"
    block_on_high: bool = os.getenv("POLICY_BLOCK_HIGH", "true").lower() == "true"
    allowed_licenses: list = field(default_factory=lambda: ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"])
    block_on_network_activity: bool = os.getenv("POLICY_BLOCK_NET", "true").lower() == "true"
    block_on_file_system_access: bool = os.getenv("POLICY_BLOCK_FS", "false").lower() == "true"
    block_on_known_malware: bool = os.getenv("POLICY_BLOCK_MALWARE", "true").lower() == "true"


class ScanVerdict(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("trust-gateway")


# ---------------------------------------------------------------------------
# Nexus API Client
# ---------------------------------------------------------------------------

class NexusClient:
    def __init__(self, config: NexusConfig):
        self.config = config
        self.session = http_requests.Session()
        if self.config.username and self.config.password:
            self.session.auth = (self.config.username, self.config.password)
        else:
            log.warning("Nexus credentials not provided via env; API operations will likely fail.")
        self.base = config.base_url.rstrip("/")

    def download_package(self, package: str, version: str, dest_dir: str) -> Optional[Path]:
        """Download package==version from the proxy repo via pip download (authenticated)."""
        from urllib.parse import urlparse, quote

        log.info(f"Downloading {package}=={version} from Nexus proxy '{self.config.proxy_repo}'")
        if not self.config.username or not self.config.password:
            log.error("NEXUS_USER and NEXUS_PASS are required for proxy downloads.")
            return None

        test_url = f"{self.base}/repository/{self.config.proxy_repo}/simple/"
        try:
            resp = self.session.get(test_url, timeout=10)
            if resp.status_code == 401:
                log.error("Nexus authentication failed (401).")
                return None
            if resp.status_code != 200:
                log.error(f"Nexus returned HTTP {resp.status_code} for {test_url}")
                return None
        except Exception as e:
            log.error(f"Error connecting to Nexus: {e}")
            return None

        parsed = urlparse(self.base)
        encoded_user = quote(self.config.username, safe='')
        encoded_pass = quote(self.config.password, safe='')
        proxy_url = f"{parsed.scheme}://{encoded_user}:{encoded_pass}@{parsed.netloc}/repository/{self.config.proxy_repo}/simple/"
        host = parsed.netloc.split(":")[0]

        cmd = [
            sys.executable, "-m", "pip", "download",
            f"{package}=={version}",
            "--no-deps",
            "--dest", dest_dir,
            "--index-url", proxy_url,
            "--trusted-host", host,
        ]
        safe_url = f"{parsed.scheme}://{self.config.username}:****@{parsed.netloc}/repository/{self.config.proxy_repo}/simple/"
        log.debug(f"Running pip download (sanitized): pip download {package}=={version} --index-url {safe_url}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            log.error("pip download timed out after 120 seconds")
            return None

        if result.returncode != 0:
            log.error(f"pip download failed (exit {result.returncode})")
            log.debug(result.stderr[:800])
            return None

        files = list(Path(dest_dir).iterdir())
        if files:
            log.info(f"Downloaded: {files[0].name}")
            return files[0]
        log.error("pip reported success but no files found in download directory")
        return None

    def upload_to_repo(self, repo_name: str, package_file: Path) -> bool:
        """Upload a Python package file to a hosted Nexus PyPI repository (PyPI-style form)."""
        if not self.config.username or not self.config.password:
            log.error("NEXUS_USER and NEXUS_PASS required to upload artifacts.")
            return False

        upload_url = f"{self.base}/repository/{repo_name}/"
        filename = package_file.name
        pkg_name, pkg_version = self._parse_package_filename(filename)

        try:
            with open(package_file, "rb") as f:
                data = {
                    ":action": "file_upload",
                    "protocol_version": "1",
                    "name": pkg_name,
                    "version": pkg_version,
                    "filetype": "bdist_wheel" if filename.endswith(".whl") else "sdist",
                }
                files = {"content": (filename, f, "application/octet-stream")}
                resp = self.session.post(upload_url, data=data, files=files, timeout=30)
        except Exception as e:
            log.error(f"Upload exception: {e}")
            return False

        if resp.status_code in (200, 201, 204):
            log.info(f"Uploaded {filename} to {repo_name}")
            return True
        else:
            log.warning(f"Upload returned {resp.status_code}; trying components API fallback")
            return self._upload_via_components_api(repo_name, package_file)

    def _upload_via_components_api(self, repo_name: str, package_file: Path) -> bool:
        url = f"{self.base}/service/rest/v1/components?repository={repo_name}"
        try:
            with open(package_file, "rb") as f:
                files = {"pypi.asset": (package_file.name, f, "application/octet-stream")}
                resp = self.session.post(url, files=files, timeout=30)
        except Exception as e:
            log.error(f"Components API upload exception: {e}")
            return False

        if resp.status_code in (200, 201, 204):
            log.info("Fallback upload succeeded")
            return True
        else:
            log.error(f"Fallback upload failed ({resp.status_code}): {resp.text[:300]}")
            return False

    @staticmethod
    def _parse_package_filename(filename: str) -> Tuple[str, str]:
        basename = filename
        for ext in [".whl", ".tar.gz", ".tar.bz2", ".zip"]:
            if basename.endswith(ext):
                basename = basename[:-len(ext)]
                break
        parts = basename.split("-")
        if len(parts) >= 2:
            return parts[0], parts[1]
        return basename, "unknown"

    def check_package_exists(self, repo_name: str, package: str, version: str) -> bool:
        url = f"{self.base}/service/rest/v1/search"
        params = {"repository": repo_name, "name": package, "version": version}
        try:
            resp = self.session.get(url, params=params, timeout=10)
        except Exception as e:
            log.error(f"Nexus search error: {e}")
            return False
        if resp.status_code == 200:
            data = resp.json()
            return len(data.get("items", [])) > 0
        return False


# ---------------------------------------------------------------------------
# Extraction & Scanners
# ---------------------------------------------------------------------------

def extract_package(package_path: Path, extract_dir: Path) -> Path:
    extract_dir.mkdir(parents=True, exist_ok=True)
    filename = package_path.name.lower()
    if filename.endswith(".whl"):
        log.info(f"Extracting wheel: {package_path.name}")
        with zipfile.ZipFile(package_path, "r") as zf:
            zf.extractall(extract_dir)
    elif filename.endswith(".tar.gz") or filename.endswith(".tgz"):
        import tarfile
        log.info(f"Extracting sdist: {package_path.name}")
        with tarfile.open(package_path, "r:gz") as tf:
            tf.extractall(path=extract_dir)
    elif filename.endswith(".zip"):
        log.info(f"Extracting zip: {package_path.name}")
        with zipfile.ZipFile(package_path, "r") as zf:
            zf.extractall(extract_dir)
    else:
        log.warning(f"Unknown package format: {filename}, copying as-is")
        shutil.copy2(package_path, extract_dir)
    return extract_dir


class TrivyScanner:
    def __init__(self, config: TrivyConfig = None):
        self.config = config or TrivyConfig()

    def scan(self, extracted_dir: Path, results_dir: Path) -> dict:
        log.info(f"[Trivy] Scanning {extracted_dir}")
        output_file = results_dir / "trivy-results.json"
        if shutil.which("trivy"):
            return self._scan_local(extracted_dir, output_file)
        return self._scan_via_docker(extracted_dir, output_file)

    def _scan_local(self, scan_dir: Path, output_file: Path) -> dict:
        cmd = ["trivy", "fs", "--scanners", "vuln,secret", "--format", "json", "--output", str(output_file), str(scan_dir)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode not in (0, 1):
            log.warning(f"[Trivy] Exit code {result.returncode}: {result.stderr[:200]}")
        if output_file.exists():
            with open(output_file) as f:
                return json.load(f)
        return {"error": result.stderr, "Results": []}

    def _scan_via_docker(self, scan_dir: Path, output_file: Path) -> dict:
        container = self.config.container_name
        log.info(f"[Trivy] Using Docker container '{container}'")
        check = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", container], capture_output=True, text=True)
        if check.returncode != 0 or "true" not in check.stdout.lower():
            log.error(f"[Trivy] Container '{container}' not running")
            return {"error": f"Container '{container}' not running", "Results": []}
        container_scan_dir = "/tmp/scan-target"
        container_output = "/tmp/trivy-results.json"
        try:
            subprocess.run(["docker", "exec", container, "rm", "-rf", container_scan_dir], check=False)
            subprocess.run(["docker", "cp", f"{scan_dir}/.", f"{container}:{container_scan_dir}"], check=True)
            result = subprocess.run(
                ["docker", "exec", container, "trivy", "fs", "--scanners", "vuln,secret", "--format", "json", "--output", container_output, container_scan_dir],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode not in (0, 1):
                log.warning(f"[Trivy] Exit code {result.returncode}: {result.stderr[:200]}")
            subprocess.run(["docker", "cp", f"{container}:{container_output}", str(output_file)], check=True)
            if output_file.exists():
                with open(output_file) as f:
                    return json.load(f)
        except subprocess.CalledProcessError as e:
            log.error(f"[Trivy] Docker operation failed: {e}")
        except subprocess.TimeoutExpired:
            log.error("[Trivy] Scan timed out")
        return {"error": "Trivy scan failed", "Results": []}


class PackageAnalysisScanner:
    IMAGE = "gcr.io/ossf-malware-analysis/analysis"
    def scan(self, package: str, version: str, ecosystem: str, results_dir: Path) -> dict:
        log.info(f"[PackageAnalysis] Analyzing {package}=={version} ({ecosystem})")
        check = subprocess.run(["docker", "image", "inspect", self.IMAGE], capture_output=True)
        if check.returncode != 0:
            log.warning("[PackageAnalysis] Analysis image not present. Skipping behavioral analysis.")
            return {"error": "analysis image not available", "skipped": True}
        host_results = str(results_dir / "package-analysis")
        os.makedirs(host_results, exist_ok=True)
        cmd = [
            "docker", "run", "--rm", "--privileged",
            "-v", "/var/lib/containers:/var/lib/containers",
            "-v", f"{host_results}:/tmp/results",
            self.IMAGE,
            "analyze",
            "-ecosystem", ecosystem,
            "-package", package,
            "-version", version,
            "-output", "/tmp/results/output.json",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            log.error("[PackageAnalysis] Timed out")
            return {"error": "timeout", "skipped": True}
        output_file = Path(host_results) / "output.json"
        if output_file.exists():
            with open(output_file) as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    log.error("[PackageAnalysis] Invalid JSON output")
                    return {"error": "invalid json", "skipped": True}
        return {"error": "no output", "skipped": True}


class OSVScanner:
    def scan(self, package: str, version: str, ecosystem: str, results_dir: Path) -> dict:
        log.info(f"[OSV] Checking {package}=={version}")
        if shutil.which("osv-scanner"):
            output_file = results_dir / "osv-results.json"
            requirements_file = results_dir / "requirements.txt"
            requirements_file.write_text(f"{package}=={version}\n")
            cmd = ["osv-scanner", "scan", "--format", "json", "--lockfile", f"requirements.txt:{requirements_file}"]
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
        try:
            url = "https://api.osv.dev/v1/query"
            payload = {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
            resp = http_requests.post(url, json=payload, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                return {"results": data.get("vulns", [])}
            else:
                log.warning(f"[OSV] API returned {resp.status_code}")
                return {"results": []}
        except Exception as e:
            log.warning(f"[OSV] API error: {e}")
            return {"results": []}


# ---------------------------------------------------------------------------
# Policy evaluation & report generation
# ---------------------------------------------------------------------------

class PolicyEvaluator:
    def __init__(self, policy: ScanPolicy):
        self.policy = policy

    def evaluate(self, trivy_results: dict, pkg_analysis_results: dict, osv_results: dict) -> Tuple[ScanVerdict, List[str]]:
        reasons: List[str] = []
        verdict = ScanVerdict.PASS

        # Trivy: CVE/secret checks
        for result in trivy_results.get("Results", []) or []:
            for vuln in result.get("Vulnerabilities", []) or []:
                severity = vuln.get("Severity", "UNKNOWN").upper()
                if self.policy.block_on_critical and severity == "CRITICAL":
                    reasons.append(f"CRITICAL CVE: {vuln.get('VulnerabilityID')} in {vuln.get('PkgName')}")
                    verdict = ScanVerdict.FAIL
                if self.policy.block_on_high and severity == "HIGH":
                    reasons.append(f"HIGH CVE: {vuln.get('VulnerabilityID')} in {vuln.get('PkgName')}")
                    verdict = ScanVerdict.FAIL
            for secret in result.get("Secrets", []) or []:
                reasons.append(f"Secret detected: {secret.get('Title', 'unknown')}")
                verdict = ScanVerdict.FAIL

        # Package analysis: behavioral
        if not pkg_analysis_results.get("skipped"):
            network_activity = pkg_analysis_results.get("network", []) or []
            if network_activity and self.policy.block_on_network_activity:
                suspicious = [
                    conn for conn in network_activity
                    if not any(safe in conn.get("host", "") for safe in ["pypi.org", "files.pythonhosted.org", "localhost"])
                ]
                if suspicious:
                    reasons.append(f"Suspicious network activity during install: {len(suspicious)} unexpected connections")
                    verdict = ScanVerdict.FAIL

            commands = pkg_analysis_results.get("commands", []) or []
            suspicious_cmds = [
                cmd for cmd in commands
                if any(flag in str(cmd) for flag in ["curl", "wget", "nc ", "netcat", "/etc/passwd", "/etc/shadow", "ssh", "reverse", "shell"])
            ]
            if suspicious_cmds:
                reasons.append(f"Suspicious commands during install: {suspicious_cmds[:3]}")
                verdict = ScanVerdict.FAIL

        # OSV checks
        osv_vulns = osv_results.get("results", []) or []
        for entry in osv_vulns:
            vid = entry.get("id") if isinstance(entry, dict) else None
            if vid and isinstance(vid, str):
                if vid.startswith("MAL-") and self.policy.block_on_known_malware:
                    reasons.append(f"Known malicious package (OSV): {vid}")
                    verdict = ScanVerdict.FAIL
                elif vid.startswith(("PYSEC-", "GHSA-", "CVE-")):
                    reasons.append(f"Known vulnerability (OSV): {vid}")
                    if verdict == ScanVerdict.PASS:
                        verdict = ScanVerdict.WARN

        if verdict == ScanVerdict.PASS:
            reasons.append("All scans passed — no issues detected")

        return verdict, reasons


def generate_report(package: str, version: str, verdict: ScanVerdict, reasons: List[str], scan_results: dict, results_dir: Path) -> Path:
    report = {
        "package": package,
        "version": version,
        "verdict": verdict.value,
        "reasons": reasons,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "policy_version": "1.0",
        "scan_details": {
            "trivy": {
                "vulnerabilities_found": sum(len(r.get("Vulnerabilities", [])) for r in scan_results.get("trivy", {}).get("Results", []) or []),
                "secrets_found": sum(len(r.get("Secrets", [])) for r in scan_results.get("trivy", {}).get("Results", []) or []),
            },
            "package_analysis": {"skipped": scan_results.get("package_analysis", {}).get("skipped", True)},
            "osv": {"vulnerabilities_found": len(scan_results.get("osv", {}).get("results", []) or [])},
        },
    }
    report_path = results_dir / f"scan-report-{package}-{version}.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    log.info(f"Report saved: {report_path}")
    return report_path


# ---------------------------------------------------------------------------
# Core orchestration (single package)
# ---------------------------------------------------------------------------

class TrustGateway:
    def __init__(self, nexus_config: Optional[NexusConfig] = None, scan_policy: Optional[ScanPolicy] = None, trivy_config: Optional[TrivyConfig] = None):
        self.nexus_config = nexus_config or NexusConfig()
        self.policy = scan_policy or ScanPolicy()
        self.nexus = NexusClient(self.nexus_config)
        self.trivy = TrivyScanner(trivy_config or TrivyConfig())
        self.pkg_analysis = PackageAnalysisScanner()
        self.osv = OSVScanner()
        self.evaluator = PolicyEvaluator(self.policy)

    def process_package(self, package: str, version: str, ecosystem: str = "PyPI") -> Tuple[ScanVerdict, Path]:
        log.info("=" * 60)
        log.info(f"Processing: {package}=={version} ({ecosystem})")
        log.info("=" * 60)

        # Skip if already trusted
        if self.nexus.check_package_exists(self.nexus_config.trusted_repo, package, version):
            log.info(f"{package}=={version} already in trusted repo — skipping")
            return ScanVerdict.PASS, Path("/dev/null")

        with tempfile.TemporaryDirectory(prefix="trust-gateway-") as tmpdir:
            work_dir = Path(tmpdir)
            download_dir = work_dir / "downloads"
            extract_dir = work_dir / "extracted"
            results_dir = work_dir / "results"
            download_dir.mkdir()
            extract_dir.mkdir()
            results_dir.mkdir()

            # Step 1: Download
            log.info("Step 1/6: Downloading package...")
            package_file = self.nexus.download_package(package, version, str(download_dir))
            if not package_file:
                log.error(f"Failed to download {package}=={version}")
                return ScanVerdict.ERROR, Path("/dev/null")

            # Step 2: Extract
            log.info("Step 2/6: Extracting package...")
            extracted = extract_package(package_file, extract_dir)

            # Step 3: Trivy
            log.info("Step 3/6: Running Trivy vulnerability scan...")
            trivy_results = self.trivy.scan(extracted, results_dir)

            # Step 4: Package Analysis
            log.info("Step 4/6: Running Package Analysis (behavioral)...")
            pkg_analysis_results = self.pkg_analysis.scan(package, version, ecosystem.lower(), results_dir)

            # Step 5: OSV-Scanner
            log.info("Step 5/6: Running OSV-Scanner (malware check)...")
            osv_results = self.osv.scan(package, version, ecosystem, results_dir)

            # Step 6: Evaluate
            log.info("Step 6/6: Evaluating policy...")
            all_results = {"trivy": trivy_results, "package_analysis": pkg_analysis_results, "osv": osv_results}
            verdict, reasons = self.evaluator.evaluate(trivy_results, pkg_analysis_results, osv_results)
            report_path = generate_report(package, version, verdict, reasons, all_results, results_dir)

            # Promote or quarantine
            if verdict == ScanVerdict.PASS:
                log.info(f"✓ PASSED — Promoting {package}=={version} to trusted repo")
                self.nexus.upload_to_repo(self.nexus_config.trusted_repo, package_file)
            elif verdict == ScanVerdict.WARN:
                log.warning(f"⚠ WARNING — {package}=={version} passed with warnings. Promoting but flagging for review.")
                self.nexus.upload_to_repo(self.nexus_config.trusted_repo, package_file)
                self.nexus.upload_to_repo(self.nexus_config.quarantine_repo, package_file)
            else:
                log.error(f"✗ FAILED — Quarantining {package}=={version}")
                for reason in reasons:
                    log.error(f"  → {reason}")
                self.nexus.upload_to_repo(self.nexus_config.quarantine_repo, package_file)

            persistent_report = Path("scan-reports") / report_path.name
            persistent_report.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(report_path, persistent_report)

            return verdict, persistent_report


# ---------------------------------------------------------------------------
# Thread pool, job and batch tracking (in-memory)
# ---------------------------------------------------------------------------

POOL = ThreadPoolExecutor(max_workers=int(os.getenv("SCAN_WORKERS", "3")))
JOBS: Dict[str, Dict] = {}    # job_id -> {"future": Future, "package":..., "version":..., "submitted_at": ts}
BATCHES: Dict[str, Dict] = {} # batch_id -> {"job_ids": [...], "submitted_at": ts, "items":[...]}

GATEWAY = TrustGateway()


def submit_scan_job(package: str, version: str) -> str:
    job_id = str(uuid.uuid4())
    future = POOL.submit(GATEWAY.process_package, package, version)
    JOBS[job_id] = {"future": future, "package": package, "version": version, "submitted_at": time.time()}
    log.info(f"Submitted job {job_id} for {package}=={version}")
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
    return {"job_id": job_id, "package": info["package"], "version": info["version"], "status": status, "result": result}


# ---------------------------------------------------------------------------
# Helper: parse package specs
# ---------------------------------------------------------------------------

def parse_spec(spec: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse 'pkg==ver' spec. Returns (pkg, ver) or (spec, None) if not pinned.
    """
    spec = spec.strip()
    if "==" in spec:
        p, v = spec.split("==", 1)
        return p.strip(), v.strip()
    return spec, None


# ---------------------------------------------------------------------------
# Server (Flask) factory with endpoints: webhook, request, batch, job, batch status
# ---------------------------------------------------------------------------

def create_app():
    from flask import Flask, request as flask_request, jsonify
    app = Flask("trust-gateway-server")

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok"}), 200

    @app.route("/webhook/nexus", methods=["POST"])
    def nexus_webhook():
        payload = flask_request.get_json(force=True)
        log.info("Received Nexus webhook")
        component = payload.get("component", {}) or {}
        package = component.get("name") or payload.get("package") or payload.get("name")
        version = component.get("version") or payload.get("version")
        if not package or not version:
            return jsonify({"error": "missing package/version in payload"}), 400
        job_id = submit_scan_job(package, version)
        return jsonify({"status": "submitted", "job_id": job_id}), 202

    @app.route("/request", methods=["POST"])
    def request_package():
        """
        Accepts JSON:
          - {"package":"pkg", "version":"1.2.3", "wait": 120}
          - OR {"packages": ["pkg==ver", "pkg2==ver2"], "wait":120}
        If a single package submitted, it will block until completion or timeout (wait).
        If multiple packages, it will submit each as a job and block until all complete or timeout.
        Returns 200 with result if completed, or 202 with job(s) info if accepted.
        """
        data = flask_request.get_json(force=True)
        if not data:
            return jsonify({"error": "invalid json body"}), 400

        wait = int(data.get("wait", 120))

        # Accept "packages" list or single "package"/"version"
        pkg_list: List[Tuple[str, Optional[str]]] = []
        if "packages" in data:
            for spec in data["packages"]:
                p, v = parse_spec(spec)
                pkg_list.append((p, v))
        elif "package" in data and "version" in data:
            p, v = data["package"], data["version"]
            pkg_list.append((p, v))
        elif "package" in data:
            # accept comma-separated in "package"
            raw = data["package"]
            for part in str(raw).split(","):
                p, v = parse_spec(part)
                pkg_list.append((p, v))
        else:
            return jsonify({"error": "provide 'package' & 'version' or 'packages' list"}), 400

        # Validate pinned versions
        unpinned = [p for (p, v) in pkg_list if v is None]
        if unpinned:
            return jsonify({"error": "unpinned package(s) found; require pkg==version", "unpinned": unpinned}), 400

        # Submit jobs
        job_ids = []
        for p, v in pkg_list:
            jid = submit_scan_job(p, v)
            job_ids.append(jid)

        # If wait==0, return accepted with job ids
        if wait <= 0:
            return jsonify({"status": "accepted", "job_ids": job_ids}), 202

        # Otherwise, block and wait for all jobs to finish up to 'wait' seconds
        start = time.time()
        remaining = wait
        done_results = {}
        for jid, (p, v) in zip(job_ids, pkg_list):
            fut = JOBS[jid]["future"]
            try:
                verdict, report = fut.result(timeout=remaining)
                done_results[jid] = {"package": p, "version": v, "verdict": verdict.value, "report": str(report)}
            except Exception as e:
                done_results[jid] = {"package": p, "version": v, "error": str(e)}
            elapsed = time.time() - start
            remaining = max(0, wait - elapsed)

        # Decide overall HTTP status
        any_fail = any((d.get("verdict") not in ("PASS", "WARN") for d in done_results.values()))
        status_code = 200 if not any_fail else 409
        return jsonify({"status": "completed", "results": done_results}), status_code

    @app.route("/request/batch", methods=["POST"])
    def request_batch():
        """
        Accepts a multipart file upload 'requirements' or JSON with 'requirements_text'.
        Submits each pinned package as a job and returns a batch_id + job list.
        """
        wait = int(flask_request.form.get("wait") or (flask_request.json.get("wait") if flask_request.is_json else flask_request.args.get("wait", 120)))

        req_text = None
        if "requirements" in flask_request.files:
            f = flask_request.files["requirements"]
            req_text = f.read().decode("utf-8")
        elif flask_request.is_json and "requirements_text" in flask_request.json:
            req_text = flask_request.json.get("requirements_text")
        else:
            return jsonify({"error": "provide 'requirements' form file or 'requirements_text' in JSON"}), 400

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
            return jsonify({"error": "no pinned package==version entries found", "unpinned": unpinned}), 400

        batch_id = str(uuid.uuid4())
        job_entries = []
        for pkg, ver in pinned:
            jid = submit_scan_job(pkg, ver)
            job_entries.append({"package": pkg, "version": ver, "job_id": jid})

        BATCHES[batch_id] = {"job_ids": [je["job_id"] for je in job_entries], "submitted_at": time.time(), "items": job_entries}
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
            jid = entry["job_id"]
            js = get_job_status(jid)
            jobs_summary.append({
                "job_id": jid,
                "package": entry["package"],
                "version": entry["version"],
                "status": js.get("status"),
                "result": js.get("result"),
            })
            if js.get("status") == "running":
                overall = "running"
            elif js.get("status") == "error" and overall != "running":
                overall = "error"
        return jsonify({"batch_id": batch_id, "submitted_at": batch["submitted_at"], "overall": overall, "jobs": jobs_summary}), 200

    return app


# ---------------------------------------------------------------------------
# CLI handlers (scan single/comma-list or bulk file)
# ---------------------------------------------------------------------------

def cmd_scan(args):
    """
    CLI scan supports:
      - one or more package specs as positional args (pkg==ver or comma-separated)
    """
    gateway = GATEWAY
    specs: List[str] = []
    if args.packages:
        # args.packages may include comma-separated entries; split
        for entry in args.packages:
            for part in str(entry).split(","):
                if part.strip():
                    specs.append(part.strip())
    else:
        print("Provide at least one package spec (pkg==ver).")
        return 2

    overall_rc = 0
    for spec in specs:
        pkg, ver = parse_spec(spec)
        if ver is None:
            log.warning(f"Skipping unpinned spec '{spec}'. Use pkg==version or add --force.")
            if not args.force:
                overall_rc = 2
                continue
            else:
                log.info("Force enabled: attempting to download latest version (not recommended).")
                # Attempt to treat spec as name and error out (simplicity)
                overall_rc = 2
                continue
        verdict, report = gateway.process_package(pkg, ver)
        print(f"\nVerdict for {pkg}=={ver}: {verdict.value.upper()}")
        print(f"Report: {report}")
        if verdict == ScanVerdict.FAIL:
            overall_rc = 1
    return overall_rc


def cmd_bulk(args):
    gateway = GATEWAY
    results = []
    with open(args.file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                package, version = line.split("==", 1)
            else:
                log.warning(f"Skipping '{line}' — must use package==version format")
                continue
            verdict, report = gateway.process_package(package.strip(), version.strip())
            results.append((package, version, verdict))
    print("\n" + "=" * 60)
    print("BULK SCAN SUMMARY")
    for pkg, ver, v in results:
        icon = "✓" if v == ScanVerdict.PASS else "⚠" if v == ScanVerdict.WARN else "✗"
        print(f"  {icon} {pkg}=={ver}: {v.value}")
    failed = sum(1 for _, _, v in results if v == ScanVerdict.FAIL)
    print(f"\n{len(results)} scanned, {failed} blocked")
    return 1 if failed > 0 else 0


def cmd_serve(args):
    try:
        from flask import Flask  # just to check dependency
    except ImportError:
        print("Flask is required for serve mode: pip install flask")
        return 1
    app = create_app()
    port = args.port
    log.info(f"Starting Trust Gateway server on 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port)
    return 0


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Nexus Trust Gateway — Orchestrator")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan one or more packages (pkg==ver). Accepts comma-separated list.")
    scan_parser.add_argument("packages", nargs="*", help="Package specs (pkg==ver) or comma-separated list")
    scan_parser.add_argument("--force", action="store_true", help="Force actions for unpinned (not recommended)")

    bulk_parser = subparsers.add_parser("bulk", help="Scan packages from a requirements-style file")
    bulk_parser.add_argument("file", help="requirements.txt")

    serve_parser = subparsers.add_parser("serve", help="Run webserver (webhook + request API)")
    serve_parser.add_argument("--port", type=int, default=int(os.getenv("FLASK_PORT", "5000")))

    args = parser.parse_args()

    if args.command == "scan":
        rc = cmd_scan(args)
        sys.exit(rc)
    elif args.command == "bulk":
        rc = cmd_bulk(args)
        sys.exit(rc)
    elif args.command == "serve":
        rc = cmd_serve(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
