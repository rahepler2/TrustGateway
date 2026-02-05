"""
Trivy vulnerability + secret scanner.

Uses client-server mode: the gateway's trivy binary sends scan data to the
trivy-server container, which maintains the vulnerability DB centrally.
One DB, one update schedule, no duplication.

For image scans, falls back to local scan (the image is on the host's Docker
daemon, not inside the trivy-server container).
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
            'fs'    — scan extracted package directory (default, uses client-server)
            'image' — scan a container image by tag/digest (local scan, skip DB download)
        """
        log.info(f"[Trivy] Scanning {target} (mode={mode})")
        output_file = results_dir / "trivy-results.json"

        if not shutil.which("trivy"):
            log.error("[Trivy] Binary not found in PATH")
            return {"error": "trivy binary not found", "Results": []}

        if mode == "image":
            return self._scan_image(target, output_file)
        return self._scan_fs_client_server(target, output_file)

    def _scan_fs_client_server(self, scan_dir: Path, output_file: Path) -> dict:
        """
        Filesystem scan via client-server mode.

        The local trivy binary sends the scan target to the remote trivy-server
        which performs the actual vulnerability lookup against its centrally
        managed DB. No local DB download needed.
        """
        cmd = [
            "trivy", "fs",
            "--server", self.config.server_url,
            "--scanners", "vuln,secret",
            "--format", "json",
            "--output", str(output_file),
            str(scan_dir),
        ]
        log.info(f"[Trivy] Client-server scan via {self.config.server_url}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            log.error("[Trivy] Scan timed out (300s)")
            return {"error": "timeout", "Results": []}

        if result.returncode not in (0, 1):
            log.warning(f"[Trivy] Exit code {result.returncode}: {result.stderr[:300]}")
            # If the server is unreachable, fall back to local scan
            if "failed to connect" in result.stderr.lower() or "server" in result.stderr.lower():
                log.warning("[Trivy] Server unreachable, falling back to local scan")
                return self._scan_fs_local(scan_dir, output_file)

        if output_file.exists():
            with open(output_file) as f:
                return json.load(f)
        return {"error": result.stderr[:500], "Results": []}

    def _scan_fs_local(self, scan_dir: Path, output_file: Path) -> dict:
        """
        Local filesystem scan (fallback). Will download its own DB copy
        on first run — only used if the trivy-server is unreachable.
        """
        cmd = [
            "trivy", "fs",
            "--scanners", "vuln,secret",
            "--format", "json",
            "--output", str(output_file),
            str(scan_dir),
        ]
        log.info("[Trivy] Local fallback scan (will use/download local DB)")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            log.error("[Trivy] Local scan timed out")
            return {"error": "timeout", "Results": []}

        if result.returncode not in (0, 1):
            log.warning(f"[Trivy] Exit code {result.returncode}: {result.stderr[:200]}")

        if output_file.exists():
            with open(output_file) as f:
                return json.load(f)
        return {"error": result.stderr[:500], "Results": []}

    def _scan_image(self, image_ref: Path, output_file: Path) -> dict:
        """
        Container image scan. Runs locally since the image lives on the
        host Docker daemon (accessible via socket mount), not inside the
        trivy-server container. Uses --skip-db-update and points at the
        server for DB access when possible.
        """
        image_str = str(image_ref)
        cmd = [
            "trivy", "image",
            "--server", self.config.server_url,
            "--scanners", "vuln,secret",
            "--format", "json",
            "--output", str(output_file),
            image_str,
        ]
        log.info(f"[Trivy] Image scan: {image_str} via {self.config.server_url}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            log.error("[Trivy] Image scan timed out (600s)")
            return {"error": "timeout", "Results": []}

        if result.returncode not in (0, 1):
            log.warning(f"[Trivy] Exit code {result.returncode}: {result.stderr[:300]}")

        if output_file.exists():
            with open(output_file) as f:
                return json.load(f)
        return {"error": result.stderr[:500], "Results": []}
