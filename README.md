# Nexus Trust Gateway

**Zero-trust package and container security gateway.**

Nexus Trust Gateway sits between public registries (PyPI, npm, Docker Hub, Maven Central, NuGet) and your developers. It scans every package and container image for vulnerabilities, malware, and suspicious behavior before promoting it to a trusted internal repository — or quarantining it for review.

Developers just `pip install` / `npm install` / `docker pull` as normal. They never touch public registries directly.

```
                                    NEXUS TRUST GATEWAY
                           ┌───────────────────────────────────────────┐
 Public Registries         │                                           │        Developers
 ┌──────────────┐          │  ┌─────────┐  ┌───────┐  ┌──────┐        │
 │ PyPI         │─────────▶│  │ Nexus   │─▶│ Trivy │─▶│ OSSF │        │     pip install flask
 │ npm          │          │  │ Proxy   │  │ (CVE) │  │(behav│        │     npm install express
 │ Docker Hub   │          │  └────┬────┘  └───┬───┘  └──┬───┘        │     docker pull nginx
 │ Maven Central│          │       │           │         │             │            │
 │ NuGet Gallery│          │       ▼           ▼         ▼             │            │
 └──────────────┘          │  ┌────────┐  ┌────────┐  ┌──────┐        │            │
                           │  │  OSV   │  │  Syft  │  │Policy│        │            │
                           │  │(malware│  │ (SBOM) │  │Engine│        │            │
                           │  └───┬────┘  └────────┘  └──┬───┘        │            │
                           │      │                      │            │            │
                           │      ▼                      ▼            │            │
                           │  ┌──────────┐        ┌──────────┐        │            │
                           │  │Quarantine│        │ Trusted  │────────┼────────────┘
                           │  │   Repo   │        │   Repo   │        │
                           │  └──────────┘        └──────────┘        │
                           └───────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Docker & Docker Compose
- 8GB RAM minimum (Nexus needs ~1.2GB alone)

### 1. Start Everything

```bash
git clone https://github.com/yourorg/Security-Manger.git
cd Security-Manger

# Create your environment file
cp example.env .env

# Start all services
docker compose up -d
```

This launches 7 services:

| Service | Port | Purpose |
|---------|------|---------|
| **Nexus** | 8081 | Package/container registry (UI + API) |
| **Trivy Server** | 8080 | Vulnerability + secret scanning |
| **OSSF Worker** | 8090 | Behavioral package analysis |
| **Gateway** | 5000 | Scanning pipeline API |
| **PostgreSQL** | 5432 | Job/batch metadata |
| **MinIO** | 9000, 9001 | S3-compatible report/SBOM storage |
| **Grafana** | 3000 | Security dashboards + auditing |

Nexus also exposes Docker registry ports: `9443` (group), `9444` (trusted), `9445` (proxy).

The gateway will wait for Nexus and Trivy to be healthy before starting.

### 2. Configure Nexus Repositories

Once Nexus is up (http://localhost:8081), create the repository structure. Each ecosystem follows the same naming convention:

| Repository | Type | Purpose |
|------------|------|---------|
| `{format}-upstream` | Proxy | Proxies the public registry |
| `{format}-trusted` | Hosted | Scanned and approved artifacts |
| `{format}-quarantine` | Hosted | Failed or flagged artifacts |
| `{format}-group` | Group | Developer-facing, serves from trusted only |

Create these for each ecosystem you use (pypi, npm, docker, maven, nuget).

Then configure a **Nexus webhook** on the `{format}-upstream` proxy repos to POST to `http://gateway:5000/webhook/nexus` on component creation. This triggers automatic scanning when packages are proxied.

### 3. Configure Developer Machines

Reference configs for each ecosystem are in the `config/` directory:

```bash
config/
├── pip.conf            # Python — point at pypi-group
├── npmrc               # Node.js — point at npm-group
├── settings.xml        # Maven — point at maven-group
├── nuget.config        # .NET — point at nuget-group
└── docker-daemon.json  # Docker — point at docker-group (port 9443)
```

Copy and edit these for your environment (replace `<nexus-host>` with your server).

**Example — Python developer setup:**
```ini
# ~/.config/pip/pip.conf
[global]
index-url = http://nexus.internal:8081/repository/pypi-group/simple/
trusted-host = nexus.internal
```

Once configured, `pip install flask` will only serve packages from the trusted repo.

## How Scanning Works

The gateway runs a 7-step pipeline for every package or container:

```
Step 1/7: Download package from Nexus proxy repo
Step 2/7: Extract package archive
Step 3/7: Trivy vulnerability + secret scan (client-server mode)
Step 4/7: OSSF behavioral analysis (via ossf-worker API)
Step 5/7: OSV malware + advisory check
Step 6/7: Syft SBOM generation (CycloneDX)
Step 7/7: Policy evaluation → promote or quarantine
```

For **container images**, step 2 is skipped (Trivy scans images directly) and Syft generates an image-level SBOM.

### Scan Verdicts

| Verdict | Action | Meaning |
|---------|--------|---------|
| **PASS** | Promoted to trusted | No issues found |
| **WARN** | Promoted to trusted + copied to quarantine | Non-blocking issues, flagged for review |
| **FAIL** | Quarantined only | Policy violation — blocked from developers |
| **ERROR** | Not uploaded anywhere | Scan infrastructure failure, investigate |

### Scan Reports

Every scan produces a JSON report stored in `scan-reports/` and uploaded to MinIO:

```json
{
  "package": "urllib3",
  "version": "1.26.5",
  "ecosystem": "PyPI",
  "verdict": "warn",
  "reasons": [
    "Known vulnerability (OSV): PYSEC-2023-192",
    "Known vulnerability (OSV): GHSA-v845-jxx5-vc9f"
  ],
  "scanned_at": "2026-02-05T18:04:39.123456+00:00",
  "policy_version": "1.0",
  "scan_details": {
    "trivy": { "vulnerabilities_found": 2, "secrets_found": 0 },
    "ossf": { "skipped": false },
    "osv": { "vulnerabilities_found": 2 },
    "sbom": { "skipped": false, "component_count": 12, "format": "CycloneDX" }
  }
}
```

## Usage

### Developer CLI

The `cli/` directory contains cross-platform tools for requesting scans:

```bash
# Python (any OS)
python cli/nexus-request.py submit -p "flask==3.0.0" --wait 300

# Multiple packages
python cli/nexus-request.py submit -p "flask==3.0.0,requests==2.32.3"

# Docker image
python cli/nexus-request.py submit -p "nginx==1.25" -e docker --wait 600

# npm package
python cli/nexus-request.py submit -p "express==4.18.2" -e npm

# Batch from requirements.txt
python cli/nexus-request.py submit-batch -r requirements.txt

# Check status
python cli/nexus-request.py status --job <job-id>
python cli/nexus-request.py status --batch <batch-id>
```

**PowerShell (Windows):**
```powershell
.\cli\nexus-request.ps1 submit -Package "flask==3.0.0"
.\cli\nexus-request.ps1 submit -Package "nginx==1.25" -Ecosystem docker
```

**Bash (Linux/Mac):**
```bash
./cli/nexus-request.sh submit -p "flask==3.0.0"
```

The CLI shows progress while scanning:
```
[INFO] Submitting flask==3.0.0 (pypi) to Trust Gateway...
[INFO] Scanning... (45s elapsed)
```

### Gateway CLI (server-side)

The gateway container also has a direct CLI for server-side operations:

```bash
# Scan from inside the gateway container
docker exec gateway python -m gateway.app scan flask==3.0.0,requests==2.32.3

# Scan Docker image
docker exec gateway python -m gateway.app scan nginx==1.25 -e docker

# Bulk scan from file
docker exec gateway python -m gateway.app bulk requirements.txt
```

### API Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `GET` | `/health` | Health check |
| `GET` | `/help` | Endpoint documentation |
| `POST` | `/request` | Scan package(s) — JSON body |
| `POST` | `/request/batch` | Scan from requirements file — multipart upload |
| `POST` | `/webhook/nexus` | Webhook for Nexus component-created events |
| `GET` | `/job/<job_id>` | Query scan job status |
| `GET` | `/batch/<batch_id>/status` | Query batch status |

**Example — API request:**
```bash
curl -X POST http://localhost:5000/request \
  -H "Content-Type: application/json" \
  -d '{"package": "flask==3.0.0", "ecosystem": "pypi", "wait": 120}'
```

## Configuration

All configuration is environment-driven via `.env` (see `example.env` for all variables).

### Scan Policy

Policy is configured via environment variables:

| Variable | Default | Effect |
|----------|---------|--------|
| `POLICY_MAX_CVSS` | `7.0` | Block packages with any CVE above this CVSS score |
| `POLICY_BLOCK_CRITICAL` | `true` | Block CRITICAL severity CVEs |
| `POLICY_BLOCK_HIGH` | `true` | Block HIGH severity CVEs |
| `POLICY_BLOCK_NET` | `true` | Block packages with suspicious network activity during install |
| `POLICY_BLOCK_FS` | `false` | Block packages with suspicious filesystem access |
| `POLICY_BLOCK_MALWARE` | `true` | Block known malware (OSV MAL- entries) |

### Multi-Ecosystem Repository Naming

Every ecosystem uses the same four-tier pattern:

| Ecosystem | Proxy | Trusted | Quarantine | Group (dev-facing) |
|-----------|-------|---------|------------|--------------------|
| PyPI | `pypi-upstream` | `pypi-trusted` | `pypi-quarantine` | `pypi-group` |
| npm | `npm-upstream` | `npm-trusted` | `npm-quarantine` | `npm-group` |
| Docker | `docker-upstream` | `docker-trusted` | `docker-quarantine` | `docker-group` |
| Maven | `maven-upstream` | `maven-trusted` | `maven-quarantine` | `maven-group` |
| NuGet | `nuget-upstream` | `nuget-trusted` | `nuget-quarantine` | `nuget-group` |

## Vulnerability Database

Trivy uses a **local vulnerability database**, not live API queries per scan.

| Scanner | DB Update | How It Works |
|---------|-----------|--------------|
| **Trivy** | Every 6h (auto) | DB published as OCI artifact, trivy-server pulls and caches it |
| **OSV** | Real-time API | Queries `api.osv.dev` per scan (fallback) or local `osv-scanner` binary |
| **OSSF** | N/A | Behavioral analysis — no database, runs the package install in a sandbox |
| **Syft** | N/A | Generates SBOMs from installed files, no vuln DB needed |

The gateway uses **Trivy client-server mode**: the gateway's trivy binary is a thin client that sends scan targets to the `trivy-server`, which maintains the DB centrally. One DB, one update schedule, no duplication.

### Forcing a DB Update

```bash
docker exec trivy-server trivy image --download-db-only
```

### Zero-Day Response Time

| Event | Typical Timing |
|-------|---------------|
| CVE published on NVD | T+0 |
| Trivy DB includes it | T+6h |
| Your trivy-server picks it up | T+6-18h |
| Your next scan detects it | Immediately after DB update |

## Grafana Dashboards

Grafana (http://localhost:3000) is auto-provisioned with:

- **PostgreSQL datasource** — connected to the gateway database
- **Security Overview dashboard** — total scans, pass/fail rates, recent jobs, scan trends

Login with `admin` / password from `GRAFANA_ADMIN_PASSWORD` in `.env`.

## Project Structure

```
Security-Manger/
├── gateway/                    # Core scanning engine
│   ├── app.py                  # Flask API + CLI entry point
│   ├── config.py               # All env-driven configuration
│   ├── pipeline.py             # 7-step scan pipeline (TrustGateway)
│   ├── policy.py               # ScanPolicy + PolicyEvaluator
│   ├── scanners/
│   │   ├── trivy.py            # Trivy client-server scanner
│   │   ├── osv.py              # OSV malware/advisory scanner
│   │   ├── ossf.py             # OSSF behavioral analysis (via worker API)
│   │   └── syft.py             # Syft SBOM generator
│   ├── clients/
│   │   └── nexus.py            # Nexus download/upload/search client
│   ├── models.py               # Job/Batch ORM models
│   ├── db.py                   # PostgreSQL session management
│   ├── storage.py              # MinIO/S3 report storage
│   ├── Dockerfile
│   ├── entrypoint.sh           # Waits for deps, then starts server
│   └── requirements.txt
├── ossf-worker/                # OSSF behavioral analysis microservice
│   ├── app.py                  # Flask API wrapping OSSF analyze binary
│   ├── Dockerfile              # Builds OSSF from source (Go)
│   └── requirements.txt
├── cli/                        # Developer-facing CLI tools
│   ├── nexus-request.py        # Python CLI
│   ├── nexus-request.ps1       # PowerShell wrapper
│   ├── nexus-request.sh        # Bash wrapper
│   └── README.md
├── config/                     # Reference client configurations
│   ├── pip.conf                # Python developer setup
│   ├── npmrc                   # Node.js developer setup
│   ├── settings.xml            # Maven developer setup
│   ├── nuget.config            # .NET developer setup
│   ├── docker-daemon.json      # Docker developer setup
│   └── grafana/                # Auto-provisioned dashboards + datasources
├── docker-compose.yml          # Full stack — one command to run
├── example.env                 # Environment variable template
└── README.md
```

## Architecture Decisions

### Why Nexus OSS?

Battle-tested repository manager that supports every package format (PyPI, npm, Maven, Docker, NuGet, raw). Free, open source, rich API for automation.

### Why Trivy?

Fast, comprehensive vulnerability scanner maintained by Aqua Security. DB updated every 6 hours. Supports filesystem scans, container images, and secrets detection. Client-server mode means one DB for the whole deployment.

### Why a Separate OSSF Worker?

The OSSF package-analysis tool needs to install packages in a sandbox to observe their behavior. Running it as a separate container avoids Docker-in-Docker complexity — the gateway calls the worker's HTTP API, and the worker runs the analysis natively.

### Why Syft?

Generates SBOMs (Software Bill of Materials) in CycloneDX format. Required for regulatory compliance (EO 14028), useful for license auditing and dependency inventory in Grafana.

### Why Multiple Scanners?

Defense in depth. Each scanner has different strengths:

| Scanner | Best At |
|---------|---------|
| **Trivy** | CVE detection, broad vulnerability coverage, secrets |
| **OSV** | Known malware (MAL- entries), GitHub advisories |
| **OSSF** | Zero-day behavioral detection, install-time attacks |
| **Syft** | Dependency inventory, license compliance |

A package must pass **all** scanners to be promoted to trusted.

## Troubleshooting

### Gateway won't start

The entrypoint waits for Nexus and Trivy to be healthy. Check:
```bash
docker compose logs gateway
docker compose ps    # Check healthcheck status
```

### Nexus authentication errors

```bash
# Verify credentials work (use credentials from your .env file)
curl -u $NEXUS_USER:$NEXUS_PASS http://localhost:8081/service/rest/v1/status

# Check NEXUS_USER / NEXUS_PASS in .env match your Nexus admin credentials
```

### Trivy scan failures

```bash
# Check trivy-server is running and healthy
curl http://localhost:8080/healthz

# Check gateway can reach it
docker exec gateway curl http://trivy-server:8080/healthz
```

### Large packages timing out

For large packages like PyTorch, increase timeouts:
```bash
# In .env or docker-compose environment
OSSF_TIMEOUT=600    # 10 minutes for behavioral analysis
```

The CLI shows progress while waiting:
```
[INFO] Scanning... (120s elapsed)
```

## License

MIT License — see [LICENSE](LICENSE) for details.

## Acknowledgments

- [Sonatype Nexus](https://www.sonatype.com/products/nexus-repository) — Repository manager
- [Aqua Trivy](https://github.com/aquasecurity/trivy) — Vulnerability scanner
- [Google OSV-Scanner](https://github.com/google/osv-scanner) — OSV database scanner
- [OpenSSF Package Analysis](https://github.com/ossf/package-analysis) — Behavioral analysis
- [Anchore Syft](https://github.com/anchore/syft) — SBOM generation
