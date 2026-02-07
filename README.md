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

### 1. Start the Gateway

```bash
git clone https://github.com/yourorg/Security-Manger.git
cd Security-Manger

# Create your environment file
cp example.env .env
# Edit .env — change all passwords and set TRUST_GATEWAY_API_KEY

# Start all services
docker compose up -d --build
```

This launches 6 services:

| Service | Port | Purpose |
|---------|------|---------|
| **Nexus** | 8081 | Package/container registry (UI + API) |
| **Trivy Server** | 8080 | Vulnerability + secret scanning |
| **OSSF Worker** | 8090 | Behavioral package analysis |
| **Gateway** | 5002 | Scanning pipeline API |
| **PostgreSQL** | 5432 | Job/batch metadata + Grafana datasource |
| **Grafana** | 3000 | Security dashboards + auditing |

Nexus also exposes Docker registry ports: `9443` (group), `9444` (trusted), `9445` (proxy).

The gateway waits for Nexus, Trivy, and PostgreSQL to be healthy before starting.

### 2. Configure Nexus Repositories

Once Nexus is up (http://localhost:8081), create the repository structure. You can run the automated setup:

```bash
docker compose run --rm nexus-setup
```

Or create manually. Each ecosystem follows the same naming convention:

| Repository | Type | Purpose |
|------------|------|---------|
| `{format}-upstream` | Proxy | Proxies the public registry |
| `{format}-trusted` | Hosted | Scanned and approved artifacts |
| `{format}-quarantine` | Hosted | Failed or flagged artifacts |
| `{format}-group` | Group | Developer-facing, serves from trusted only |

Create these for each ecosystem you use (pypi, npm, docker, maven, nuget).

### 3. Set Up Developer Machines

Each developer needs two things:
1. The `nexus-request` CLI tool
2. Their package manager pointed at Nexus

#### Install the CLI

Copy the `cli/` folder to each developer machine and add it to their PATH.

**Windows:**
```powershell
# Copy cli/ folder to C:\Tools\nexus-request\
# Add C:\Tools\nexus-request to your PATH

# Set environment variables (run once, persists across sessions)
[System.Environment]::SetEnvironmentVariable("TRUST_GATEWAY_URL", "http://your-gateway-server:5002", "User")
[System.Environment]::SetEnvironmentVariable("TRUST_GATEWAY_KEY", "your-api-key", "User")
```

The `nexus-request.cmd` wrapper lets you type `nexus-request` from any shell (cmd, PowerShell, Windows Terminal).

**Linux/macOS:**
```bash
# Copy cli/ folder or symlink nexus-request.sh
sudo ln -s /path/to/cli/nexus-request.sh /usr/local/bin/nexus-request

# Add to ~/.bashrc or ~/.zshrc
export TRUST_GATEWAY_URL=http://your-gateway-server:5002
export TRUST_GATEWAY_KEY=your-api-key
```

Requires Python 3 and `pip install requests`.

#### Configure Package Managers

Point each package manager at the Nexus group repo so installs only serve scanned, trusted packages.

**pip (Python):**
```ini
# Linux/Mac: ~/.config/pip/pip.conf
# Windows:   %APPDATA%\pip\pip.ini
[global]
index-url = http://nexus.internal:8081/repository/pypi-group/simple/
trusted-host = nexus.internal
```

**uv (Python):**
```bash
# Set in your shell profile (~/.bashrc, ~/.zshrc, etc.)
export UV_INDEX_URL=http://nexus.internal:8081/repository/pypi-group/simple/

# Or per-project in pyproject.toml
# [tool.uv]
# index-url = "http://nexus.internal:8081/repository/pypi-group/simple/"
```

**npm (Node.js):**
```bash
# ~/.npmrc or project .npmrc
registry=http://nexus.internal:8081/repository/npm-group/
always-auth=true
```

**Docker:**
```json
// /etc/docker/daemon.json (Linux) or Docker Desktop settings
{
  "registry-mirrors": ["http://nexus.internal:9443"],
  "insecure-registries": ["nexus.internal:9443"]
}
```

**Maven (Java):**

See `config/settings.xml` — add the Nexus group URL as a mirror.

**NuGet (.NET):**

See `config/nuget.config` — add the Nexus group URL as a package source.

Reference configs for all ecosystems are in the `config/` directory.

## Usage

### Scanning Packages

The CLI uses the pattern: `nexus-request scan <ecosystem> <package> [version]`

Version is optional — the gateway resolves the latest version automatically.

```bash
# Python packages
nexus-request scan python requests              # latest version
nexus-request scan python requests==2.32.3      # specific version
nexus-request scan python requests 2.32.3       # same thing

# Docker images
nexus-request scan docker nginx                 # defaults to :latest
nexus-request scan docker nginx:1.25            # specific tag
nexus-request scan docker nginx 1.25            # same thing

# npm packages
nexus-request scan npm express                  # latest
nexus-request scan npm express@4.18.2           # specific version

# Maven
nexus-request scan maven org.apache.commons:commons-lang3:3.14.0

# NuGet
nexus-request scan nuget Newtonsoft.Json 13.0.3

# Batch scan from a file
nexus-request scan python -f requirements.txt
nexus-request scan npm -f package-lock.json
```

Output:
```
Scanning requests (pypi)...
  Job ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
  Scanning a1b2c3d4... 45s
  PASS  requests==2.32.3 (pypi)
```

Exit code `0` = all passed, `1` = something failed/quarantined.

### Checking Status

```bash
nexus-request status <job-id>
nexus-request status --batch <batch-id>
```

### Rescanning for New Vulnerabilities

As new CVEs are published, packages that were previously clean may become vulnerable. The `rescan` command re-scans everything in your trusted repos:

```bash
# Rescan all trusted Python packages
nexus-request rescan python

# Rescan all trusted packages across all ecosystems
nexus-request rescan --all
```

Packages that now fail policy are moved to quarantine. You can schedule this as a cron job:

```bash
# Daily rescan at 2am
0 2 * * * /usr/local/bin/nexus-request rescan --all
```

### API Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `GET` | `/health` | Health check |
| `GET` | `/help` | Endpoint documentation |
| `POST` | `/request` | Scan a package (version optional) |
| `POST` | `/request/batch` | Scan from requirements file |
| `POST` | `/rescan` | Rescan trusted packages for new vulnerabilities |
| `POST` | `/webhook/nexus` | Webhook for Nexus component-created events |
| `GET` | `/job/<job_id>` | Query scan job status |
| `GET` | `/batch/<batch_id>/status` | Query batch status |

All endpoints (except `/health` and `/help`) require an `X-API-Key` header when `TRUST_GATEWAY_API_KEY` is set.

**Example — API request:**
```bash
curl -X POST http://localhost:5002/request \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"package": "flask", "ecosystem": "pypi", "wait": 120}'
```

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

### Why Multiple Scanners?

Defense in depth. Each scanner has different strengths:

| Scanner | Best At |
|---------|---------|
| **Trivy** | CVE detection, broad vulnerability coverage, secrets |
| **OSV** | Known malware (MAL- entries), GitHub advisories |
| **OSSF** | Zero-day behavioral detection, install-time attacks |
| **Syft** | Dependency inventory, license compliance |

A package must pass **all** scanners to be promoted to trusted.

## Configuration

All configuration is environment-driven via `.env` (see `example.env` for all variables).

### Scan Policy

| Variable | Default | Effect |
|----------|---------|--------|
| `POLICY_MAX_CVSS` | `7.0` | Block packages with any CVE above this CVSS score |
| `POLICY_BLOCK_CRITICAL` | `true` | Block CRITICAL severity CVEs |
| `POLICY_BLOCK_HIGH` | `true` | Block HIGH severity CVEs |
| `POLICY_BLOCK_NET` | `true` | Block packages with suspicious network activity during install |
| `POLICY_BLOCK_FS` | `false` | Block packages with suspicious filesystem access |
| `POLICY_BLOCK_MALWARE` | `true` | Block known malware (OSV MAL- entries) |

### Authentication

Set `TRUST_GATEWAY_API_KEY` in your `.env` to require API key authentication on all gateway endpoints. Developers set `TRUST_GATEWAY_KEY` as an environment variable on their machines.

### Multi-Ecosystem Repository Naming

Every ecosystem uses the same four-tier pattern:

| Ecosystem | Proxy | Trusted | Quarantine | Group (dev-facing) |
|-----------|-------|---------|------------|--------------------|
| PyPI | `pypi-upstream` | `pypi-trusted` | `pypi-quarantine` | `pypi-group` |
| npm | `npm-upstream` | `npm-trusted` | `npm-quarantine` | `npm-group` |
| Docker | `docker-upstream` | `docker-trusted` | `docker-quarantine` | `docker-group` |
| Maven | `maven-upstream` | `maven-trusted` | `maven-quarantine` | `maven-group` |
| NuGet | `nuget-upstream` | `nuget-trusted` | `nuget-quarantine` | `nuget-group` |

## Grafana Dashboards

Grafana (http://localhost:3000) is auto-provisioned with two dashboards:

- **Security Overview** — total scans, pass/fail rates, CVE severity breakdown, recent jobs, top vulnerable packages
- **Package Security Detail** — drill-down view with CVE details, SBOM components, license breakdown, policy failure reasons (click into it from the overview)

Login with `admin` / password from `GRAFANA_ADMIN_PASSWORD` in `.env`.

## Vulnerability Database

Trivy uses a **local vulnerability database**, not live API queries per scan.

| Scanner | DB Update | How It Works |
|---------|-----------|--------------|
| **Trivy** | Every 6h (auto) | DB published as OCI artifact, trivy-server pulls and caches it |
| **OSV** | Real-time API | Queries `api.osv.dev` per scan |
| **OSSF** | N/A | Behavioral analysis — no database, runs the package install in a sandbox |
| **Syft** | N/A | Generates SBOMs from installed files, no vuln DB needed |

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
| `nexus-request rescan` detects it | Immediately after DB update |

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
│   ├── Dockerfile
│   ├── entrypoint.sh           # Waits for deps, starts Gunicorn
│   └── requirements.txt
├── ossf-worker/                # OSSF behavioral analysis microservice
│   ├── app.py                  # Flask API wrapping OSSF analyze binary
│   ├── Dockerfile              # Builds OSSF from source (Go)
│   └── requirements.txt
├── cli/                        # Developer-facing CLI tools
│   ├── nexus-request.py        # Python CLI (cross-platform)
│   ├── nexus-request.ps1       # PowerShell CLI
│   ├── nexus-request.cmd       # Windows wrapper (invoke from any shell)
│   ├── nexus-request.sh        # Bash wrapper (delegates to Python)
│   └── README.md
├── config/                     # Reference client configurations
│   ├── pip.conf                # Python pip setup
│   ├── npmrc                   # Node.js npm setup
│   ├── settings.xml            # Maven setup
│   ├── nuget.config            # .NET NuGet setup
│   ├── docker-daemon.json      # Docker daemon setup
│   └── grafana/                # Auto-provisioned dashboards + datasources
├── docker-compose.yml          # Full stack — one command to run
├── example.env                 # Environment variable template
└── README.md
```

## Troubleshooting

### Gateway won't start

The entrypoint waits for Nexus and Trivy to be healthy. Check:
```bash
docker compose logs gateway
docker compose ps    # Check healthcheck status
```

### Nexus authentication errors

```bash
# Verify credentials work
curl -u $NEXUS_USER:$NEXUS_PASS http://localhost:8081/service/rest/v1/status
```

### Trivy scan failures

```bash
# Check trivy-server is running and healthy
curl http://localhost:8080/healthz

# Check gateway can reach it
docker exec gateway curl http://trivy-server:8080/healthz
```

### Large packages timing out

```bash
# In .env — increase the OSSF behavioral analysis timeout
OSSF_TIMEOUT=600
```

The CLI shows progress while waiting:
```
  Scanning a1b2c3d4... 120s
```

## License

MIT License — see [LICENSE](LICENSE) for details.

## Acknowledgments

- [Sonatype Nexus](https://www.sonatype.com/products/nexus-repository) — Repository manager
- [Aqua Trivy](https://github.com/aquasecurity/trivy) — Vulnerability scanner
- [Google OSV-Scanner](https://github.com/google/osv-scanner) — OSV database scanner
- [OpenSSF Package Analysis](https://github.com/ossf/package-analysis) — Behavioral analysis
- [Anchore Syft](https://github.com/anchore/syft) — SBOM generation
