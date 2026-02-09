"""
OSSF Package Analysis Worker — lightweight Flask wrapper around the OSSF
analysis tooling.

Runs as a dedicated container so the main gateway doesn't need Docker-in-Docker.
The OSSF tools are installed natively in this container's OS.

Uses static analysis mode only (no Docker sandbox needed). Results are written
to local file:// bucket paths and returned as JSON.

Endpoint:
    POST /analyze  {"package": "flask", "version": "3.0.0", "ecosystem": "pypi"}
    GET  /health
"""
from __future__ import annotations

import glob
import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path

from flask import Flask, request, jsonify

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("ossf-worker")

app = Flask("ossf-worker")

TIMEOUT = int(os.getenv("OSSF_TIMEOUT", "300"))

# Map our ecosystem names to what the analyze binary expects
ECO_MAP = {
    "pypi": "pypi",
    "npm": "npm",
    "maven": "packagist",  # closest available
    "nuget": "packagist",
    "rubygems": "rubygems",
    "crates.io": "crates.io",
}


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


def _collect_results(results_dir: str) -> dict:
    """Read all JSON result files from the local bucket path."""
    combined = {"files": [], "commands": [], "network": []}
    for json_file in glob.glob(os.path.join(results_dir, "**", "*.json"), recursive=True):
        try:
            with open(json_file) as f:
                data = json.load(f)
            if isinstance(data, dict):
                for key in ("files", "commands", "network"):
                    if key in data:
                        combined[key].extend(data[key] if isinstance(data[key], list) else [data[key]])
                if not any(k in data for k in ("files", "commands", "network")):
                    combined["raw"] = data
            elif isinstance(data, list):
                combined.setdefault("entries", []).extend(data)
        except (json.JSONDecodeError, OSError) as e:
            log.warning(f"Failed to read result file {json_file}: {e}")
    return combined


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(force=True)
    package = data.get("package")
    version = data.get("version")
    ecosystem = data.get("ecosystem", "pypi")

    if not package or not version:
        return jsonify({"error": "package and version are required"}), 400

    eco_mapped = ECO_MAP.get(ecosystem.lower(), ecosystem.lower())
    log.info(f"Analyzing {package}=={version} ({eco_mapped})")

    with tempfile.TemporaryDirectory(prefix="ossf-") as tmpdir:
        static_dir = os.path.join(tmpdir, "static")
        os.makedirs(static_dir)

        cmd = [
            "/usr/local/bin/analyze",
            "-ecosystem", eco_mapped,
            "-package", package,
            "-version", version,
            "-mode", "static",
            "-nopull",
            "-static-bucket", f"file://{static_dir}",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            log.error(f"Analysis timed out after {TIMEOUT}s")
            return jsonify({"error": "timeout", "skipped": True}), 504
        except FileNotFoundError:
            log.error("analyze binary not found")
            return jsonify({"error": "analyze binary not found", "skipped": True}), 500

        if result.returncode != 0:
            log.warning(f"analyze exited {result.returncode}: {result.stderr[:500]}")

        # Collect any results written to the local bucket
        results = _collect_results(static_dir)

        if results.get("files") or results.get("commands") or results.get("network") or results.get("raw"):
            log.info(f"Analysis complete for {package}=={version}")
            return jsonify(results), 200

        # No structured results — return what we have from stdout/stderr
        log.warning(f"No structured results for {package}=={version}")
        return jsonify({
            "skipped": True,
            "error": "no structured results from static analysis",
            "stderr": result.stderr[:500] if result.stderr else "",
            "stdout": result.stdout[:500] if result.stdout else "",
        }), 200


if __name__ == "__main__":
    port = int(os.getenv("OSSF_PORT", "8090"))
    app.run(host="0.0.0.0", port=port)
