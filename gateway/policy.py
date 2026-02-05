"""
Policy evaluation — decides PASS / WARN / FAIL / ERROR based on scan results.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

from .config import ScanPolicy, ScanVerdict

log = logging.getLogger("trust-gateway")


class PolicyEvaluator:
    def __init__(self, policy: ScanPolicy):
        self.policy = policy

    def evaluate(
        self,
        trivy_results: dict,
        ossf_results: dict,
        osv_results: dict,
    ) -> Tuple[ScanVerdict, List[str]]:
        reasons: List[str] = []
        verdict = ScanVerdict.PASS

        # -- Trivy: CVE / secret checks --------------------------------------
        for result in trivy_results.get("Results", []) or []:
            for vuln in result.get("Vulnerabilities", []) or []:
                severity = vuln.get("Severity", "UNKNOWN").upper()
                if self.policy.block_on_critical and severity == "CRITICAL":
                    reasons.append(
                        f"CRITICAL CVE: {vuln.get('VulnerabilityID')} in {vuln.get('PkgName')}"
                    )
                    verdict = ScanVerdict.FAIL
                if self.policy.block_on_high and severity == "HIGH":
                    reasons.append(
                        f"HIGH CVE: {vuln.get('VulnerabilityID')} in {vuln.get('PkgName')}"
                    )
                    verdict = ScanVerdict.FAIL
            for secret in result.get("Secrets", []) or []:
                reasons.append(f"Secret detected: {secret.get('Title', 'unknown')}")
                verdict = ScanVerdict.FAIL

        # -- OSSF Package Analysis: behavioral checks ------------------------
        if not ossf_results.get("skipped"):
            network_activity = ossf_results.get("network", []) or []
            if network_activity and self.policy.block_on_network_activity:
                safe_hosts = ["pypi.org", "files.pythonhosted.org", "localhost",
                              "registry.npmjs.org", "registry.yarnpkg.com"]
                suspicious = [
                    conn for conn in network_activity
                    if not any(safe in conn.get("host", "") for safe in safe_hosts)
                ]
                if suspicious:
                    reasons.append(
                        f"Suspicious network activity during install: "
                        f"{len(suspicious)} unexpected connections"
                    )
                    verdict = ScanVerdict.FAIL

            commands = ossf_results.get("commands", []) or []
            suspicious_cmds = [
                cmd for cmd in commands
                if any(
                    flag in str(cmd)
                    for flag in [
                        "curl", "wget", "nc ", "netcat",
                        "/etc/passwd", "/etc/shadow",
                        "ssh", "reverse", "shell",
                    ]
                )
            ]
            if suspicious_cmds:
                reasons.append(f"Suspicious commands during install: {suspicious_cmds[:3]}")
                verdict = ScanVerdict.FAIL

        # -- OSV: malware / advisory checks -----------------------------------
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


def generate_report(
    package: str,
    version: str,
    ecosystem: str,
    verdict: ScanVerdict,
    reasons: List[str],
    scan_results: dict,
    results_dir: Path,
) -> Path:
    """Write a JSON scan report and return the path."""
    report = {
        "package": package,
        "version": version,
        "ecosystem": ecosystem,
        "verdict": verdict.value,
        "reasons": reasons,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "policy_version": "1.0",
        "scan_details": {
            "trivy": {
                "vulnerabilities_found": sum(
                    len(r.get("Vulnerabilities", []))
                    for r in scan_results.get("trivy", {}).get("Results", []) or []
                ),
                "secrets_found": sum(
                    len(r.get("Secrets", []))
                    for r in scan_results.get("trivy", {}).get("Results", []) or []
                ),
            },
            "ossf": {
                "skipped": scan_results.get("ossf", {}).get("skipped", True),
            },
            "osv": {
                "vulnerabilities_found": len(
                    scan_results.get("osv", {}).get("results", []) or []
                ),
            },
            "sbom": scan_results.get("sbom", {"skipped": True}),
        },
    }

    report_path = results_dir / f"scan-report-{package}-{version}.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    log.info(f"Report saved: {report_path}")
    return report_path
