"""
Nexus Trust Gateway — Package Scanning Orchestrator
====================================================

Coordinates scanning of PyPI packages through Trivy, OpenSSF Package Analysis,
and OSV-Scanner before promoting them to the trusted Nexus repository or
quarantining them with a full report.

Notes:
- Sensitive defaults (passwords / credentials) are NOT hard-coded. Provide
  credentials via environment variables (NEXUS_URL, NEXUS_USER, NEXUS_PASS, ...).
- The defaults assume the services are running in Docker Compose with service
  names on the same Docker network (nexus:8081, trivy-server:8080, ...).
- The orchestrator prefers containerized tools and will fall back to local
  binaries when available. This avoids requiring developers to install scanner
  binaries on their workstations.
- For production use, run this inside a container (or Kubernetes) and supply
  credentials securely via your secret manager.

Usage examples:
    # Scan and evaluate a single package
    python orchestrator.py scan requests 2.31.0

    # Process a requirements-style allowlist file
    python orchestrator.py bulk packages.txt

    # Run as a webhook listener (Flask-based)
    python orchestrator.py serve --port 5000
"""

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import requests as http_requests  # use this alias consistently

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class NexusConfig:
    """Connection details for the Nexus 3 instance.

    NOTE: do NOT hardcode credentials in source. Provide them via environment
    variables. Defaults assume the orchestrator runs in the same Docker network
    as the Nexus service (service name 'nexus' and port 8081).
    """
    base_url: str = os.getenv("NEXUS_URL", "http://nexus:8081")
    username: Optional[str] = os.getenv("NEXUS_USER")
    password: Optional[str] = os.getenv("NEXUS_PASS")

    # Repository names — set these to match your Nexus repos
    proxy_repo: str = os.getenv("NEXUS_PROXY_REPO", "pypi-upstream")
    quarantine_repo: str = os.getenv("NEXUS_QUARANTINE_REPO", "pypi-quarantine")
    trusted_repo: str = os.getenv("NEXUS_TRUSTED_REPO", "pypi-trusted")
    group_repo: str = os.getenv("NEXUS_GROUP_REPO", "pypi-group")


@dataclass
class TrivyConfig:
    """Trivy server connection details. Defaults match the docker-compose PoC."""
    server_url: str = os.getenv("TRIVY_SERVER_URL", "http://trivy-server:8080")
    container_name: str = os.getenv("TRIVY_CONTAINER", "trivy-server")


@dataclass
class ScanPolicy:
    """
    Configurable policy thresholds. Adjust to match your organization's risk
    tolerance.
    """
    max_cvss_score: float = float(os.getenv("POLICY_MAX_CVSS", "7.0"))
    block_on_critical: bool = os.getenv("POLICY_BLOCK_CRITICAL", "true").lower() == "true"
    block_on_high: bool = os.getenv("POLICY_BLOCK_HIGH", "true").lower() == "true"
    allowed_licenses: list = field(default_factory=lambda: [
        "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
        "ISC", "PSF-2.0", "Python-2.0", "LGPL-2.1", "LGPL-3.0",
        "MPL-2.0", "Unlicense", "CC0-1.0",
    ])
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("trust-gateway")


# ---------------------------------------------------------------------------
# Nexus API Client
# ---------------------------------------------------------------------------

class NexusClient:
    """Lightweight client for a Nexus 3 instance."""

    def __init__(self, config: NexusConfig):
        self.config = config
        self.session = http_requests.Session()
        if self.config.username is not None and self.config.password is not None:
            self.session.auth = (self.config.username, self.config.password)
        else:
            log.warning("Nexus username/password not provided via env vars; API calls will likely fail.")
        self.base = config.base_url.rstrip("/")

    def download_package(self, package: str, version: str, dest_dir: str) -> Optional[Path]:
        """
        Download a package from the upstream proxy repo using 'pip download'
        configured to hit the Nexus proxy repo.

        Returns the Path to the downloaded file, or None on failure.
        """
        from urllib.parse import urlparse, quote

        log.info(f"Downloading {package}=={version} from Nexus proxy repo '{self.config.proxy_repo}'")

        # Ensure credentials present for pip-authenticated proxy
        if not self.config.username or not self.config.password:
            log.error("Nexus credentials are required to download via the proxy. Set NEXUS_USER and NEXUS_PASS.")
            return None

        # Pre-flight: check Nexus reachable and repository accessible
        test_url = f"{self.base}/repository/{self.config.proxy_repo}/simple/"
        try:
            resp = self.session.get(test_url, timeout=10)
            if resp.status_code == 401:
                log.error("Authentication failed for Nexus (401). Check credentials and permissions.")
                return None
            elif resp.status_code == 403:
                log.error("Access denied to the Nexus proxy repository (403). Verify repository permissions.")
                return None
            elif resp.status_code != 200:
                log.error(f"Nexus returned HTTP {resp.status_code} for {test_url}")
                log.debug(f"Nexus response: {resp.text[:400]}")
                return None
        except http_requests.exceptions.ConnectionError:
            log.error(f"Cannot connect to Nexus at {self.base}. Is the service up and reachable?")
            return None
        except http_requests.exceptions.Timeout:
            log.error(f"Timeout connecting to Nexus at {self.base}")
            return None
        except Exception as e:
            log.error(f"Unexpected error checking Nexus: {e}")
            return None

        # Build authenticated URL for pip (credentials URL-encoded)
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
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            log.error("pip download timed out after 120 seconds")
            return None

        if result.returncode != 0:
            log.error(f"pip download failed (exit {result.returncode})")
            log.debug(f"stderr: {result.stderr[:800]}")
            return None

        files = list(Path(dest_dir).iterdir())
        if files:
            log.info(f"Downloaded: {files[0].name}")
            return files[0]

        log.error("pip reported success but no files found in download directory")
        return None

    def upload_to_repo(self, repo_name: str, package_file: Path) -> bool:
        """
        Upload a Python package to a hosted Nexus PyPI repository. Uses the
        simple PyPI upload form; falls back to the components API if needed.
        """
        if not self.config.username or not self.config.password:
            log.error("Nexus credentials required to upload artifacts. Set NEXUS_USER and NEXUS_PASS.")
            return False

        log.info(f"Uploading {package_file.name} to Nexus repository '{repo_name}'")
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
            log.info(f"Successfully uploaded {filename} to {repo_name}")
            return True
        else:
            log.warning(f"Upload returned {resp.status_code}; trying components API fallback")
            return self._upload_via_components_api(repo_name, package_file)

    def _upload_via_components_api(self, repo_name: str, package_file: Path) -> bool:
        """Fallback upload using the Nexus components REST API."""
        if not self.config.username or not self.config.password:
            log.error("Nexus credentials required for components API upload.")
            return False

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
    def _parse_package_filename(filename: str) -> tuple[str, str]:
        """
        Extract package name and version from a wheel or sdist filename.
        """
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
        """Check if a package+version already exists in the repository."""
        url = f"{self.base}/service/rest/v1/search"
        params = {"repository": repo_name, "name": package, "version": version}
        try:
            resp = self.session.get(url, params=params, timeout=10)
        except Exception as e:
            log.error(f"Error querying Nexus: {e}")
            return False

        if resp.status_code == 200:
            data = resp.json()
            return len(data.get("items", [])) > 0
        return False


# ---------------------------------------------------------------------------
# Package Extraction
# ---------------------------------------------------------------------------

def extract_package(package_path: Path, extract_dir: Path) -> Path:
    """
    Extract a .whl or .tar.gz package so scanners can inspect contents.
    """
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

    log.info(f"Extracted to: {extract_dir}")
    return extract_dir


# ---------------------------------------------------------------------------
# Scanner Implementations
# ---------------------------------------------------------------------------

class TrivyScanner:
    """
    Runs Trivy vulnerability and secret scanning on a package. Prefers using the
    local trivy binary, otherwise attempts to exec into the trivy container.
    """

    def __init__(self, config: TrivyConfig = None):
        self.config = config or TrivyConfig()

    def scan(self, extracted_dir: Path, results_dir: Path) -> dict:
        log.info(f"[Trivy] Scanning {extracted_dir}")
        output_file = results_dir / "trivy-results.json"

        if shutil.which("trivy"):
            return self._scan_local(extracted_dir, output_file)
        return self._scan_via_docker(extracted_dir, output_file)

    def _scan_local(self, scan_dir: Path, output_file: Path) -> dict:
        log.info("[Trivy] Using local trivy binary")
        cmd = [
            "trivy", "fs",
            "--scanners", "vuln,secret",
            "--format", "json",
            "--output", str(output_file),
            str(scan_dir),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode not in (0, 1):
            log.warning(f"[Trivy] Exit code {result.returncode}: {result.stderr[:200]}")

        if output_file.exists():
            with open(output_file) as f:
                return json.load(f)

        return {"error": result.stderr, "Results": []}

    def _scan_via_docker(self, scan_dir: Path, output_file: Path) -> dict:
        """Copy files into the trivy container and run trivy fs there."""
        container = self.config.container_name
        log.info(f"[Trivy] Using Docker container '{container}'")

        check = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container],
            capture_output=True, text=True,
        )
        if check.returncode != 0 or "true" not in check.stdout.lower():
            log.error(f"[Trivy] Container '{container}' is not running")
            return {"error": f"Container '{container}' not running", "Results": []}

        container_scan_dir = "/tmp/scan-target"
        container_output = "/tmp/trivy-results.json"

        try:
            subprocess.run(["docker", "exec", container, "rm", "-rf", container_scan_dir], check=False)
            subprocess.run(["docker", "cp", f"{scan_dir}/.", f"{container}:{container_scan_dir}"], check=True)
            result = subprocess.run(
                [
                    "docker", "exec", container,
                    "trivy", "fs",
                    "--scanners", "vuln,secret",
                    "--format", "json",
                    "--output", container_output,
                    container_scan_dir,
                ],
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
            log.error("[Trivy] Scan timed out after 120 seconds")

        return {"error": "Trivy scan failed", "Results": []}


class PackageAnalysisScanner:
    """
    Runs OpenSSF Package Analysis in one-shot mode. If the analysis container
    is available, it is used so developers do not need the analysis binary on
    their workstations.
    """

    IMAGE = "gcr.io/ossf-malware-analysis/analysis"

    def scan(self, package: str, version: str, ecosystem: str, results_dir: Path) -> dict:
        log.info(f"[PackageAnalysis] Analyzing {package}=={version} ({ecosystem})")

        # Prefer running containerized analysis; if docker not available, skip.
        check = subprocess.run(["docker", "image", "inspect", self.IMAGE], capture_output=True)
        if check.returncode != 0:
            log.warning(f"[PackageAnalysis] Analysis image {self.IMAGE} not present. Skipping behavioral analysis.")
            return {"error": "analysis image not available", "skipped": True}

        host_results = str(results_dir / "package-analysis")
        os.makedirs(host_results, exist_ok=True)

        cmd = [
            "docker", "run", "--rm",
            "--privileged",
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
            log.error("[PackageAnalysis] Timed out after 300 seconds")
            return {"error": "timeout", "skipped": True}

        output_file = Path(host_results) / "output.json"
        if output_file.exists():
            with open(output_file) as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    log.error("[PackageAnalysis] Output is not valid JSON")
                    return {"error": "invalid json", "skipped": True}

        return {"error": "no output", "skipped": True}


class OSVScanner:
    """Checks the package against OSV. Uses the public OSV API if a local
    binary is not available to avoid forcing local installs on developer machines.
    """

    def scan(self, package: str, version: str, ecosystem: str, results_dir: Path) -> dict:
        log.info(f"[OSV-Scanner] Checking {package}=={version}")

        # If local binary present, use it (backwards compatible)
        if shutil.which("osv-scanner"):
            output_file = results_dir / "osv-results.json"
            requirements_file = results_dir / "requirements.txt"
            requirements_file.write_text(f"{package}=={version}\n")
            cmd = [
                "osv-scanner",
                "scan",
                "--format", "json",
                "--lockfile", f"requirements.txt:{requirements_file}",
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired:
                log.error("[OSV-Scanner] Local osv-scanner timed out")
                return {"skipped": True, "results": []}

            try:
                data = json.loads(result.stdout) if result.stdout.strip() else {"results": []}
            except json.JSONDecodeError:
                log.warning("[OSV-Scanner] Could not parse local scanner output")
                data = {"results": [], "raw_output": result.stdout[:500]}

            with open(output_file, "w") as f:
                json.dump(data, f, indent=2)
            return data

        # Fallback: query OSV public API
        try:
            url = "https://api.osv.dev/v1/query"
            payload = {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
            resp = http_requests.post(url, json=payload, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                # Normalize to a simple structure for downstream processing
                return {"results": data.get("vulns", [])}
            else:
                log.warning(f"[OSV] API returned {resp.status_code}; skipping OSV check")
                return {"results": []}
        except Exception as e:
            log.warning(f"[OSV] API error: {e}")
            return {"results": []}


# ---------------------------------------------------------------------------
# Policy Evaluator
# ---------------------------------------------------------------------------

class PolicyEvaluator:
    """Evaluates scan results against the configured policy."""

    def __init__(self, policy: ScanPolicy):
        self.policy = policy

    def evaluate(
        self,
        trivy_results: dict,
        pkg_analysis_results: dict,
        osv_results: dict,
    ) -> tuple[ScanVerdict, list[str]]:
        reasons = []
        verdict = ScanVerdict.PASS

        # --- Trivy: CVE & secret evaluation ---
        for result in trivy_results.get("Results", []):
            for vuln in result.get("Vulnerabilities", []) or []:
                severity = vuln.get("Severity", "UNKNOWN").upper()
                cvss = vuln.get("CVSS", {}) or {}
                # CVSS may be nested; try to read score if present (best effort)
                score = None
                try:
                    score = float(vuln.get("CVSS", {}).get("nvd", {}).get("cvssV3", {}).get("baseScore", 0) or 0)
                except Exception:
                    score = None

                if self.policy.block_on_critical and severity == "CRITICAL":
                    reasons.append(f"CRITICAL CVE: {vuln.get('VulnerabilityID')} in {vuln.get('PkgName')}")
                    verdict = ScanVerdict.FAIL

                if self.policy.block_on_high and severity == "HIGH":
                    reasons.append(f"HIGH CVE: {vuln.get('VulnerabilityID')} in {vuln.get('PkgName')}")
                    verdict = ScanVerdict.FAIL

                if score is not None and score >= self.policy.max_cvss_score:
                    reasons.append(f"CVE {vuln.get('VulnerabilityID')} has CVSS {score} >= {self.policy.max_cvss_score}")
                    verdict = ScanVerdict.FAIL

            for secret in result.get("Secrets", []) or []:
                reasons.append(f"Secret detected: {secret.get('Title', 'unknown')}")
                verdict = ScanVerdict.FAIL

        # --- Package Analysis: behavioral flags ---
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

        # --- OSV: known malware / high severity findings ---
        osv_vulns = osv_results.get("results", []) or []
        for entry in osv_vulns:
            # OSV API format may differ; be conservative
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


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------

def generate_report(
    package: str,
    version: str,
    verdict: ScanVerdict,
    reasons: list[str],
    scan_results: dict,
    results_dir: Path,
) -> Path:
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
            "package_analysis": {
                "skipped": scan_results.get("package_analysis", {}).get("skipped", True),
            },
            "osv": {
                "vulnerabilities_found": len(scan_results.get("osv", {}).get("results", []) or []),
            },
        },
    }

    report_path = results_dir / f"scan-report-{package}-{version}.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    log.info(f"Report saved: {report_path}")
    return report_path


# ---------------------------------------------------------------------------
# Main Orchestrator
# ---------------------------------------------------------------------------

class TrustGateway:
    def __init__(
        self,
        nexus_config: Optional[NexusConfig] = None,
        scan_policy: Optional[ScanPolicy] = None,
        trivy_config: Optional[TrivyConfig] = None,
    ):
        self.nexus_config = nexus_config or NexusConfig()
        self.policy = scan_policy or ScanPolicy()
        self.nexus = NexusClient(self.nexus_config)
        self.trivy = TrivyScanner(trivy_config or TrivyConfig())
        self.pkg_analysis = PackageAnalysisScanner()
        self.osv = OSVScanner()
        self.evaluator = PolicyEvaluator(self.policy)

    def process_package(
        self,
        package: str,
        version: str,
        ecosystem: str = "PyPI",
    ) -> tuple[ScanVerdict, Path]:
        log.info("=" * 60)
        log.info(f"Processing: {package}=={version} ({ecosystem})")
        log.info("=" * 60)

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
            log.info("Step 5/6: Running OSV-Scanner (vuln/malware check)...")
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
# CLI
# ---------------------------------------------------------------------------

def cmd_scan(args):
    gateway = TrustGateway()
    verdict, report = gateway.process_package(args.package, args.version)
    print(f"\nVerdict: {verdict.value.upper()}")
    print(f"Report:  {report}")
    return 0 if verdict in (ScanVerdict.PASS, ScanVerdict.WARN) else 1


def cmd_bulk(args):
    gateway = TrustGateway()
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

    print(f"\n{'='*60}")
    print("BULK SCAN SUMMARY")
    print(f"{'='*60}")
    for pkg, ver, v in results:
        icon = "✓" if v == ScanVerdict.PASS else "⚠" if v == ScanVerdict.WARN else "✗"
        print(f"  {icon} {pkg}=={ver}: {v.value}")

    failed = sum(1 for _, _, v in results if v == ScanVerdict.FAIL)
    print(f"\n{len(results)} scanned, {failed} blocked")
    return 1 if failed > 0 else 0


def cmd_serve(args):
    try:
        from flask import Flask, request as flask_request, jsonify
    except ImportError:
        print("Flask is required for serve mode: pip install flask")
        return 1

    app = Flask("trust-gateway")
    gateway = TrustGateway()

    @app.route("/webhook/nexus", methods=["POST"])
    def handle_nexus_webhook():
        payload = flask_request.json
        log.info(f"Received webhook: {json.dumps(payload, indent=2)}")

        component = payload.get("component", {}) or {}
        package = component.get("name", "")
        version = component.get("version", "")

        if not package or not version:
            return jsonify({"error": "missing package or version"}), 400

        verdict, report = gateway.process_package(package, version)

        return jsonify({
            "package": package,
            "version": version,
            "verdict": verdict.value,
            "report": str(report),
        })

    @app.route("/scan", methods=["POST"])
    def handle_scan_request():
        data = flask_request.json
        package = data.get("package", "")
        version = data.get("version", "")

        if not package or not version:
            return jsonify({"error": "provide 'package' and 'version'"}), 400

        verdict, report = gateway.process_package(package, version)

        return jsonify({
            "package": package,
            "version": version,
            "verdict": verdict.value,
            "report": str(report),
        })

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok"})

    log.info(f"Starting webhook listener on port {args.port}")
    app.run(host="0.0.0.0", port=args.port)
    return 0


def main():
    parser = argparse.ArgumentParser(description="Nexus Trust Gateway — Package Scanning Orchestrator")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a single package")
    scan_parser.add_argument("package", help="Package name (e.g. 'requests')")
    scan_parser.add_argument("version", help="Package version (e.g. '2.31.0')")

    bulk_parser = subparsers.add_parser("bulk", help="Scan packages from a file")
    bulk_parser.add_argument("file", help="Requirements-style file (package==version)")

    serve_parser = subparsers.add_parser("serve", help="Run as webhook listener")
    serve_parser.add_argument("--port", type=int, default=int(os.getenv("FLASK_PORT", "5000")))

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
