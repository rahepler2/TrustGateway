"""
TrustGateway — the core scanning pipeline.

Coordinates: download → extract → Trivy → OSSF → OSV → Syft → evaluate → promote/quarantine.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Optional, Tuple

from .config import NexusConfig, TrivyConfig, OSSFConfig, ScanPolicy, ScanVerdict
from .clients.nexus import NexusClient
from .scanners.trivy import TrivyScanner
from .scanners.ossf import OSSFScanner
from .scanners.osv import OSVScanner
from .scanners.syft import SyftScanner
from .policy import PolicyEvaluator, generate_report

log = logging.getLogger("trust-gateway")

# Ecosystem → OSV ecosystem string
ECOSYSTEM_MAP = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "nuget": "NuGet",
    "docker": "Docker",
}


def _extract_scan_summary(all_results: dict, sbom_file: str | None) -> dict:
    """Extract detailed scan metrics from raw results for database storage.

    Stores both aggregate counts (for overview dashboard) and individual
    CVE / SBOM records (for drill-down detail dashboard).
    """
    trivy = all_results.get("trivy", {})
    cve_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    cve_list = []
    for result in trivy.get("Results", []) or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            sev = vuln.get("Severity", "UNKNOWN").lower()
            if sev in cve_counts:
                cve_counts[sev] += 1
            cve_list.append({
                "id": vuln.get("VulnerabilityID", ""),
                "severity": sev,
                "pkg": vuln.get("PkgName", ""),
                "installed": vuln.get("InstalledVersion", ""),
                "fixed": vuln.get("FixedVersion", ""),
                "title": (vuln.get("Title") or vuln.get("Description", ""))[:200],
                "target": target,
            })

    # Sort CVEs: critical first, then high, medium, low
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    cve_list.sort(key=lambda c: sev_order.get(c["severity"], 5))

    secrets_count = sum(
        len(r.get("Secrets", []) or [])
        for r in trivy.get("Results", []) or []
    )

    sbom = all_results.get("sbom", {})
    sbom_summary = {
        "component_count": sbom.get("component_count", 0),
        "format": sbom.get("format", "unknown"),
        "licenses": [],
        "components": [],
    }

    # Read SBOM file for license + component data
    if sbom_file and Path(sbom_file).exists():
        try:
            with open(sbom_file) as f:
                sbom_data = json.load(f)
            seen_licenses = set()
            for comp in sbom_data.get("components", []):
                comp_licenses = []
                for lic in comp.get("licenses", []):
                    lid = (
                        lic.get("license", {}).get("id")
                        or lic.get("license", {}).get("name", "")
                    )
                    if lid:
                        comp_licenses.append(lid)
                        if lid not in seen_licenses:
                            seen_licenses.add(lid)
                            sbom_summary["licenses"].append(lid)
                sbom_summary["components"].append({
                    "name": comp.get("name", ""),
                    "version": comp.get("version", ""),
                    "type": comp.get("type", ""),
                    "license": ", ".join(comp_licenses) if comp_licenses else "",
                })
        except Exception:
            pass

    return {
        "trivy": cve_counts,
        "cves": cve_list,
        "secrets": secrets_count,
        "sbom": sbom_summary,
        "ossf_skipped": all_results.get("ossf", {}).get("skipped", True),
        "osv_count": len(all_results.get("osv", {}).get("results", []) or []),
    }


def extract_package(package_path: Path, extract_dir: Path) -> Path:
    """Extract a downloaded package archive into extract_dir."""
    extract_dir.mkdir(parents=True, exist_ok=True)
    filename = package_path.name.lower()

    if filename.endswith(".whl") or filename.endswith(".zip"):
        log.info(f"Extracting zip/wheel: {package_path.name}")
        with zipfile.ZipFile(package_path, "r") as zf:
            zf.extractall(extract_dir)
    elif filename.endswith((".tar.gz", ".tgz", ".tar.bz2")):
        import tarfile
        log.info(f"Extracting tarball: {package_path.name}")
        mode = "r:gz" if filename.endswith((".tar.gz", ".tgz")) else "r:bz2"
        with tarfile.open(package_path, mode) as tf:
            tf.extractall(path=extract_dir)
    elif filename.endswith(".tar"):
        import tarfile
        log.info(f"Extracting tar: {package_path.name}")
        with tarfile.open(package_path, "r:") as tf:
            tf.extractall(path=extract_dir)
    else:
        log.warning(f"Unknown format: {filename}, copying as-is")
        shutil.copy2(package_path, extract_dir)

    return extract_dir


class TrustGateway:
    def __init__(
        self,
        nexus_config: Optional[NexusConfig] = None,
        scan_policy: Optional[ScanPolicy] = None,
        trivy_config: Optional[TrivyConfig] = None,
        ossf_config: Optional[OSSFConfig] = None,
    ):
        self.nexus_config = nexus_config or NexusConfig()
        self.policy = scan_policy or ScanPolicy()
        self.nexus = NexusClient(self.nexus_config)
        self.trivy = TrivyScanner(trivy_config or TrivyConfig())
        self.ossf = OSSFScanner(ossf_config or OSSFConfig())
        self.osv = OSVScanner()
        self.syft = SyftScanner()
        self.evaluator = PolicyEvaluator(self.policy)

    def process_package(
        self,
        package: str,
        version: str,
        ecosystem: str = "pypi",
    ) -> Tuple[ScanVerdict, Path, dict]:
        """
        Full scanning pipeline for any ecosystem.

        Returns (verdict, report_path, scan_summary).
        """
        eco_lower = ecosystem.lower()
        eco_osv = ECOSYSTEM_MAP.get(eco_lower, "PyPI")
        repos = self.nexus_config.repos_for(eco_lower)
        is_docker = eco_lower == "docker"

        log.info("=" * 60)
        log.info(f"Processing: {package}=={version} ({eco_osv})")
        log.info("=" * 60)

        # Skip if already in trusted
        if not is_docker and self.nexus.check_package_exists(
            repos["trusted"], package, version
        ):
            log.info(f"{package}=={version} already in trusted repo — skipping")
            return ScanVerdict.PASS, Path("/dev/null"), {}

        with tempfile.TemporaryDirectory(prefix="trust-gateway-", dir="/data") as tmpdir:
            work_dir = Path(tmpdir)
            download_dir = work_dir / "downloads"
            extract_dir = work_dir / "extracted"
            results_dir = work_dir / "results"
            download_dir.mkdir()
            extract_dir.mkdir()
            results_dir.mkdir()

            # Step 1: Download
            log.info("Step 1/7: Downloading package...")
            package_file = self.nexus.download_package(
                package, version, str(download_dir), ecosystem=eco_lower
            )
            if not package_file:
                log.error(f"Failed to download {package}=={version}")
                return ScanVerdict.ERROR, Path("/dev/null"), {}

            # Step 2: Extract (skip for Docker — Trivy scans images directly)
            if is_docker:
                log.info("Step 2/7: Docker image — skipping extraction")
                extracted = extract_dir
            else:
                log.info("Step 2/7: Extracting package...")
                extracted = extract_package(package_file, extract_dir)

            # Step 3: Trivy vulnerability scan
            log.info("Step 3/7: Running Trivy vulnerability scan...")
            if is_docker:
                trivy_results = self.trivy.scan(
                    Path(f"{package}:{version}"), results_dir, mode="image"
                )
            else:
                trivy_results = self.trivy.scan(extracted, results_dir)

            # Step 4: OSSF behavioral analysis (via worker API)
            log.info("Step 4/7: Running OSSF behavioral analysis...")
            ossf_results = self.ossf.scan(package, version, eco_osv)

            # Step 5: OSV malware/advisory check
            log.info("Step 5/7: Running OSV-Scanner...")
            osv_results = self.osv.scan(package, version, eco_osv, results_dir)

            # Step 6: SBOM generation
            log.info("Step 6/7: Generating SBOM...")
            if is_docker:
                sbom_results = self.syft.generate_sbom(
                    Path(f"{package}:{version}"), results_dir, mode="image"
                )
            else:
                sbom_results = self.syft.generate_sbom(extracted, results_dir)

            # Step 7: Policy evaluation
            log.info("Step 7/7: Evaluating policy...")
            all_results = {
                "trivy": trivy_results,
                "ossf": ossf_results,
                "osv": osv_results,
                "sbom": sbom_results,
            }
            verdict, reasons = self.evaluator.evaluate(
                trivy_results, ossf_results, osv_results
            )
            report_path = generate_report(
                package, version, eco_osv, verdict, reasons, all_results, results_dir
            )

            # Promote or quarantine
            if verdict == ScanVerdict.PASS:
                log.info(f"PASSED — Promoting {package}=={version} to trusted repo")
                self.nexus.upload_to_repo(
                    repos["trusted"], package_file, ecosystem=eco_lower
                )
            elif verdict == ScanVerdict.WARN:
                log.warning(
                    f"WARNING — {package}=={version} promoted with warnings"
                )
                self.nexus.upload_to_repo(
                    repos["trusted"], package_file, ecosystem=eco_lower
                )
                self.nexus.upload_to_repo(
                    repos["quarantine"], package_file, ecosystem=eco_lower
                )
            else:
                log.error(f"FAILED — Quarantining {package}=={version}")
                for reason in reasons:
                    log.error(f"  -> {reason}")
                self.nexus.upload_to_repo(
                    repos["quarantine"], package_file, ecosystem=eco_lower
                )

            # Extract enriched summary for database storage
            sbom_file = sbom_results.get("output_file")
            scan_summary = _extract_scan_summary(all_results, sbom_file)
            scan_summary["reasons"] = reasons

            # Persist report outside temp dir
            persistent_report = Path("scan-reports") / report_path.name
            persistent_report.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(report_path, persistent_report)

            return verdict, persistent_report, scan_summary
