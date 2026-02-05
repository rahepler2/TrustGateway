"""
OSSF Package Analysis Worker — lightweight Flask wrapper around the OSSF
analysis tooling.

Runs as a dedicated container so the main gateway doesn't need Docker-in-Docker.
The OSSF tools are installed natively in this container's OS.

Endpoint:
    POST /analyze  {"package": "flask", "version": "3.0.0", "ecosystem": "pypi"}
    GET  /health
"""
from __future__ import annotations

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


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(force=True)
    package = data.get("package")
    version = data.get("version")
    ecosystem = data.get("ecosystem", "pypi")

    if not package or not version:
        return jsonify({"error": "package and version are required"}), 400

    log.info(f"Analyzing {package}=={version} ({ecosystem})")

    with tempfile.TemporaryDirectory(prefix="ossf-") as tmpdir:
        output_file = Path(tmpdir) / "output.json"

        # The analyze binary is installed in the container at /usr/local/bin/analyze
        cmd = [
            "/usr/local/bin/analyze",
            "-ecosystem", ecosystem,
            "-package", package,
            "-version", version,
            "-output", str(output_file),
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

        if output_file.exists():
            try:
                with open(output_file) as f:
                    results = json.load(f)
                log.info(f"Analysis complete for {package}=={version}")
                return jsonify(results), 200
            except json.JSONDecodeError:
                log.error("Invalid JSON output from analyzer")
                return jsonify({"error": "invalid json output", "skipped": True}), 500

        log.warning(f"No output file produced. stderr: {result.stderr[:500]}")
        return jsonify({
            "error": "no output",
            "skipped": True,
            "stderr": result.stderr[:500],
        }), 500


if __name__ == "__main__":
    port = int(os.getenv("OSSF_PORT", "8090"))
    app.run(host="0.0.0.0", port=port)
