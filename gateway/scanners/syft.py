"""
Syft SBOM generator — produces CycloneDX JSON SBOMs for packages/images.

The SBOM is stored alongside scan reports and feeds into:
  - License compliance auditing
  - Dependency inventory in Grafana
  - Regulatory compliance (EO 14028, etc.)
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger("trust-gateway")


class SyftScanner:
    def generate_sbom(self, target: Path, results_dir: Path, mode: str = "dir") -> dict:
        """
        Generate an SBOM for a directory or container image.

        mode:
            'dir'   — scan extracted package directory (default)
            'image' — scan a container image by tag
        """
        if not shutil.which("syft"):
            log.warning("[Syft] Binary not found — skipping SBOM generation")
            return {"skipped": True}

        output_file = results_dir / "sbom-cyclonedx.json"
        source = f"dir:{target}" if mode == "dir" else str(target)

        cmd = [
            "syft", source,
            "--output", f"cyclonedx-json={output_file}",
        ]

        log.info(f"[Syft] Generating SBOM for {target} (mode={mode})")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            log.error("[Syft] SBOM generation timed out")
            return {"skipped": True, "error": "timeout"}

        if result.returncode != 0:
            log.warning(f"[Syft] Exit code {result.returncode}: {result.stderr[:300]}")

        if output_file.exists():
            with open(output_file) as f:
                try:
                    sbom = json.load(f)
                    component_count = len(sbom.get("components", []))
                    log.info(f"[Syft] SBOM generated: {component_count} components")
                    return {
                        "skipped": False,
                        "component_count": component_count,
                        "output_file": str(output_file),
                        "format": "CycloneDX",
                    }
                except json.JSONDecodeError:
                    log.error("[Syft] Invalid JSON output")

        return {"skipped": True, "error": "no output"}
