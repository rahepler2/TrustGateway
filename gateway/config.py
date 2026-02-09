"""
Unified configuration — all env-driven, no secrets in source.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Nexus repository manager
# ---------------------------------------------------------------------------

@dataclass
class NexusConfig:
    base_url: str = os.getenv("NEXUS_URL", "http://nexus:8081")
    username: Optional[str] = os.getenv("NEXUS_USER")
    password: Optional[str] = os.getenv("NEXUS_PASS")
    # PyPI
    pypi_proxy_repo: str = os.getenv("NEXUS_PYPI_PROXY", "pypi-upstream")
    pypi_trusted_repo: str = os.getenv("NEXUS_PYPI_TRUSTED", "pypi-trusted")
    pypi_quarantine_repo: str = os.getenv("NEXUS_PYPI_QUARANTINE", "pypi-quarantine")
    pypi_group_repo: str = os.getenv("NEXUS_PYPI_GROUP", "pypi-group")
    # npm
    npm_proxy_repo: str = os.getenv("NEXUS_NPM_PROXY", "npm-upstream")
    npm_trusted_repo: str = os.getenv("NEXUS_NPM_TRUSTED", "npm-trusted")
    npm_quarantine_repo: str = os.getenv("NEXUS_NPM_QUARANTINE", "npm-quarantine")
    npm_group_repo: str = os.getenv("NEXUS_NPM_GROUP", "npm-group")
    # Docker
    docker_proxy_repo: str = os.getenv("NEXUS_DOCKER_PROXY", "docker-upstream")
    docker_trusted_repo: str = os.getenv("NEXUS_DOCKER_TRUSTED", "docker-trusted")
    docker_quarantine_repo: str = os.getenv("NEXUS_DOCKER_QUARANTINE", "docker-quarantine")
    docker_group_repo: str = os.getenv("NEXUS_DOCKER_GROUP", "docker-group")
    docker_group_port: int = int(os.getenv("NEXUS_DOCKER_GROUP_PORT", "9443"))
    docker_trusted_port: int = int(os.getenv("NEXUS_DOCKER_TRUSTED_PORT", "9444"))
    docker_proxy_port: int = int(os.getenv("NEXUS_DOCKER_PROXY_PORT", "9445"))
    docker_quarantine_port: int = int(os.getenv("NEXUS_DOCKER_QUARANTINE_PORT", "9446"))
    # Maven
    maven_proxy_repo: str = os.getenv("NEXUS_MAVEN_PROXY", "maven-upstream")
    maven_trusted_repo: str = os.getenv("NEXUS_MAVEN_TRUSTED", "maven-trusted")
    maven_quarantine_repo: str = os.getenv("NEXUS_MAVEN_QUARANTINE", "maven-quarantine")
    maven_group_repo: str = os.getenv("NEXUS_MAVEN_GROUP", "maven-group")
    # NuGet
    nuget_proxy_repo: str = os.getenv("NEXUS_NUGET_PROXY", "nuget-upstream")
    nuget_trusted_repo: str = os.getenv("NEXUS_NUGET_TRUSTED", "nuget-trusted")
    nuget_quarantine_repo: str = os.getenv("NEXUS_NUGET_QUARANTINE", "nuget-quarantine")
    nuget_group_repo: str = os.getenv("NEXUS_NUGET_GROUP", "nuget-group")

    def repos_for(self, ecosystem: str) -> dict:
        """Return proxy/trusted/quarantine/group repo names for an ecosystem."""
        key = ecosystem.lower().replace("pypi", "pypi")
        mapping = {
            "pypi":   {"proxy": self.pypi_proxy_repo, "trusted": self.pypi_trusted_repo,
                       "quarantine": self.pypi_quarantine_repo, "group": self.pypi_group_repo},
            "npm":    {"proxy": self.npm_proxy_repo, "trusted": self.npm_trusted_repo,
                       "quarantine": self.npm_quarantine_repo, "group": self.npm_group_repo},
            "docker": {"proxy": self.docker_proxy_repo, "trusted": self.docker_trusted_repo,
                       "quarantine": self.docker_quarantine_repo, "group": self.docker_group_repo},
            "maven":  {"proxy": self.maven_proxy_repo, "trusted": self.maven_trusted_repo,
                       "quarantine": self.maven_quarantine_repo, "group": self.maven_group_repo},
            "nuget":  {"proxy": self.nuget_proxy_repo, "trusted": self.nuget_trusted_repo,
                       "quarantine": self.nuget_quarantine_repo, "group": self.nuget_group_repo},
        }
        return mapping.get(key, mapping["pypi"])


# ---------------------------------------------------------------------------
# Scanner services
# ---------------------------------------------------------------------------

@dataclass
class TrivyConfig:
    server_url: str = os.getenv("TRIVY_SERVER_URL", "http://trivy-server:8080")
    container_name: str = os.getenv("TRIVY_CONTAINER", "trivy-server")


@dataclass
class OSSFConfig:
    api_url: str = os.getenv("OSSF_API_URL", "http://ossf-worker:8090")
    timeout: int = int(os.getenv("OSSF_TIMEOUT", "300"))


# ---------------------------------------------------------------------------
# Scan policy
# ---------------------------------------------------------------------------

@dataclass
class ScanPolicy:
    max_cvss_score: float = float(os.getenv("POLICY_MAX_CVSS", "7.0"))
    block_on_critical: bool = os.getenv("POLICY_BLOCK_CRITICAL", "true").lower() == "true"
    block_on_high: bool = os.getenv("POLICY_BLOCK_HIGH", "true").lower() == "true"
    allowed_licenses: list = field(default_factory=lambda: [
        "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
    ])
    block_on_network_activity: bool = os.getenv("POLICY_BLOCK_NET", "true").lower() == "true"
    block_on_file_system_access: bool = os.getenv("POLICY_BLOCK_FS", "true").lower() == "true"
    block_on_known_malware: bool = os.getenv("POLICY_BLOCK_MALWARE", "true").lower() == "true"


class ScanVerdict(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Database / storage
# ---------------------------------------------------------------------------

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    _pg_user = os.getenv("PG_USER", "gateway")
    _pg_pass = os.getenv("PG_PASS", "")
    _pg_db = os.getenv("PG_DB", "gatewaydb")
    DATABASE_URL = f"postgresql://{_pg_user}:{_pg_pass}@postgres:5432/{_pg_db}"

# Workers
SCAN_WORKERS = int(os.getenv("SCAN_WORKERS", "3"))

# API key (simple protection until LDAP/AD)
API_KEY = os.getenv("TRUST_GATEWAY_API_KEY")

# Scheduled rescan interval in seconds (0 = disabled, default 6h)
RESCAN_INTERVAL = int(os.getenv("RESCAN_INTERVAL", "21600"))

# Flask
FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.getenv("FLASK_PORT", "5000"))
