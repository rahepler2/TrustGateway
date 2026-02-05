"""
OSSF Package Analysis scanner — behavioral analysis of packages during install.

Calls the ossf-worker HTTP API (a sidecar container that wraps the OSSF
analysis tooling) so the gateway itself does not need Docker-in-Docker.
"""
from __future__ import annotations

import logging

import requests as http_requests

from ..config import OSSFConfig

log = logging.getLogger("trust-gateway")


class OSSFScanner:
    def __init__(self, config: OSSFConfig | None = None):
        self.config = config or OSSFConfig()

    def scan(self, package: str, version: str, ecosystem: str) -> dict:
        """
        POST to the ossf-worker API and return the analysis result.
        Returns {"skipped": True, ...} when the worker is unreachable.
        """
        log.info(f"[OSSF] Analyzing {package}=={version} ({ecosystem})")
        url = f"{self.config.api_url.rstrip('/')}/analyze"

        try:
            resp = http_requests.post(
                url,
                json={
                    "package": package,
                    "version": version,
                    "ecosystem": ecosystem.lower(),
                },
                timeout=self.config.timeout,
            )
            if resp.status_code == 200:
                return resp.json()
            log.warning(f"[OSSF] Worker returned {resp.status_code}: {resp.text[:300]}")
            return {"error": f"worker returned {resp.status_code}", "skipped": True}
        except http_requests.ConnectionError:
            log.warning("[OSSF] Worker unreachable — skipping behavioral analysis")
            return {"error": "worker unreachable", "skipped": True}
        except http_requests.Timeout:
            log.error("[OSSF] Worker timed out")
            return {"error": "timeout", "skipped": True}
        except Exception as e:
            log.error(f"[OSSF] Unexpected error: {e}")
            return {"error": str(e), "skipped": True}
