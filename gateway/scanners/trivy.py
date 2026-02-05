"""
Trivy vulnerability + secret scanner.

Prefers the local trivy binary (installed in the gateway container).
Falls back to running via Docker exec against the trivy-server container.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

from ..config import TrivyConfig

log = logging.getLogger("trust-gateway")


class TrivyScanner:
    def __init__(self, config: TrivyConfig | None = None):
        self.config = config or TrivyConfig()

    def scan(self, target: Path, results_dir: Path, mode: str = "fs") -> dict:
        """
        Scan a filesystem path or container image.

        mode:
            'fs'    — scan extracted package directory (default)
            'image' — scan a container image by tag/digest
        """
        log.info(f"[Trivy] Scanning {target} (mode={mode})")
        output_file = results_dir / "trivy-results.json"

        if shutil.which("trivy"):
            return self._scan_local(target, output_file, mode)
        return self._scan_via_docker(target, output_file, mode)

    def _scan_local(self, target: Path, output_file: Path, mode: str) -> dict:
        scan_type = "image" if mode == "image" else "fs"
        cmd = [
            "trivy", scan_type,
            "--scanners", "vuln,secret",
            "--format", "json",
            "--output", str(output_file),
            str(target),
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            log.error("[Trivy] Scan timed out")
            return {"error": "timeout", "Results": []}

        if result.returncode not in (0, 1):
            log.warning(f"[Trivy] Exit code {result.returncode}: {result.stderr[:200]}")

        if output_file.exists():
            with open(output_file) as f:
                return json.load(f)
        return {"error": result.stderr[:500], "Results": []}

    def _scan_via_docker(self, target: Path, output_file: Path, mode: str) -> dict:
        container = self.config.container_name
        log.info(f"[Trivy] Using Docker container '{container}'")

        check = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container],
            capture_output=True, text=True,
        )
        if check.returncode != 0 or "true" not in check.stdout.lower():
            log.error(f"[Trivy] Container '{container}' not running")
            return {"error": f"Container '{container}' not running", "Results": []}

        container_scan_dir = "/tmp/scan-target"
        container_output = "/tmp/trivy-results.json"

        try:
            subprocess.run(["docker", "exec", container, "rm", "-rf", container_scan_dir], check=False)
            subprocess.run(["docker", "cp", f"{target}/.", f"{container}:{container_scan_dir}"], check=True)
            result = subprocess.run(
                [
                    "docker", "exec", container,
                    "trivy", "fs",
                    "--scanners", "vuln,secret",
                    "--format", "json",
                    "--output", container_output,
                    container_scan_dir,
                ],
                capture_output=True, text=True, timeout=300,
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
