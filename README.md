# Nexus Trust Gateway

**An open-source, security-first package and container management system.**

Nexus Trust Gateway is a CLI-driven orchestrator that sits between public package registries (PyPI, npm, Docker Hub) and your development teams. It automatically scans packages for vulnerabilities, malware, and suspicious behavior before promoting them to a trusted repository — or quarantining them for review.

```
┌─────────────────┐     ┌──────────────────────────────────────────────────────────┐     ┌─────────────────┐
│                 │     │              NEXUS TRUST GATEWAY                         │     │                 │
│   Public        │     │  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐  │     │   Developers    │
│   Registries    │────▶│  │ Nexus   │──▶│ Trivy   │──▶│ OSV     │──▶│ Package │  │     │                 │
│                 │     │  │ Proxy   │   │ Scanner │   │ Scanner │   │ Analysis│  │     │   pip install   │
│  - PyPI         │     │  └─────────┘   └─────────┘   └─────────┘   └─────────┘  │     │   from trusted  │
│  - npm          │     │       │                                         │       │     │   repo only     │
│  - Docker Hub   │     │       ▼                                         ▼       │     │                 │
│                 │     │  ┌──────────────────────────────────────────────────┐   │     └─────────────────┘
└─────────────────┘     │  │              Policy Evaluator                    │   │              ▲
                        │  │  • CRITICAL CVE? → Quarantine                    │   │              │
                        │  │  • Known malware? → Quarantine                   │   │              │
                        │  │  • Suspicious network activity? → Quarantine     │   │              │
                        │  │  • All clear? → Promote to Trusted               │   │              │
                        │  └──────────────────────────────────────────────────┘   │              │
                        │       │                           │                     │              │
                        │       ▼                           ▼                     │              │
                        │  ┌─────────┐                 ┌─────────┐                │              │
                        │  │Quarantine│                │ Trusted │────────────────┼──────────────┘
                        │  │  Repo   │                 │  Repo   │                │
                        │  └─────────┘                 └─────────┘                │
                        └──────────────────────────────────────────────────────────┘
```

## Why?

Supply chain attacks are real. Malicious packages slip into public registries regularly. Your developers shouldn't be one `pip install` away from compromising your infrastructure.

Nexus Trust Gateway provides:

- **Zero-trust package management** — Nothing reaches developers until it's scanned
- **Multi-scanner defense** — Trivy (CVEs), OSV-Scanner (malware), Package Analysis (behavioral)
- **Policy-as-code** — Define your risk tolerance, enforce it automatically
- **Full audit trail** — Every scan generates a JSON report for compliance
- **100% open source** — No vendor lock-in, no license fees, full transparency

## Components

| Component | Purpose | Required? |
|-----------|---------|-----------|
| **Sonatype Nexus OSS** | Repository manager — proxies, stores, and serves packages | Yes |
| **Trivy** | Vulnerability scanner — checks against NVD, GitHub Advisories, etc. | Yes |
| **OSV-Scanner** | Malware detection — checks against Open Source Vulnerabilities database | Recommended |
| **Package Analysis** | Behavioral sandbox — detects suspicious install-time behavior | Optional |
| **Orchestrator** | This project — coordinates scanning and promotion/quarantine | Yes |

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11+
- 8GB RAM minimum (Nexus is hungry)

### 1. Start the Infrastructure

```bash
# Clone this repo
git clone https://github.com/yourorg/nexus-trust-gateway.git
cd nexus-trust-gateway

# Start Nexus and Trivy
docker-compose up -d

# Wait for Nexus to be ready (~60 seconds)
until curl -s http://localhost:9000/service/rest/v1/status | grep -q "\"edition\""; do
  echo "Waiting for Nexus..."
  sleep 5
done
echo "Nexus is ready!"
```

### 2. Configure Nexus Repositories

Run the setup script to create the required repositories and service account:

```bash
./scripts/setup-nexus.sh
```

This creates:
- `pypi-upstream` — Proxy to pypi.org
- `pypi-trusted` — Scanned & approved packages
- `pypi-quarantine` — Failed packages for review
- `pypi-group` — Developer-facing endpoint (serves from trusted only)
- `trust-gateway-svc` — Service account for the orchestrator

### 3. Install the Orchestrator

```bash
pip install -r requirements.txt

# Optional but recommended
brew install osv-scanner
```

### 4. Configure Environment

```bash
export NEXUS_URL=http://localhost:9000
export NEXUS_USER=trust-gateway-svc
export NEXUS_PASS='YourSecurePassword'
export TRIVY_CONTAINER=trivy-server
```

### 5. Scan Your First Package

```bash
python orchestrator.py scan requests 2.31.0
```

Expected output:
```
2026-02-05 13:04:37 [INFO] Processing: requests==2.31.0 (PyPI)
2026-02-05 13:04:37 [INFO] Step 1/6: Downloading package...
2026-02-05 13:04:38 [INFO] Step 2/6: Extracting package...
2026-02-05 13:04:38 [INFO] Step 3/6: Running Trivy vulnerability scan...
2026-02-05 13:04:39 [INFO] Step 4/6: Running Package Analysis (behavioral)...
2026-02-05 13:04:39 [INFO] Step 5/6: Running OSV-Scanner (malware check)...
2026-02-05 13:04:39 [INFO] Step 6/6: Evaluating policy...
2026-02-05 13:04:39 [INFO] ✓ PASSED — Promoting requests==2.31.0 to trusted repo

Verdict: PASS
Report:  scan-reports/scan-report-requests-2.31.0.json
```

## Usage

### Scan a Single Package

```bash
python orchestrator.py scan <package> <version>

# Examples
python orchestrator.py scan flask 3.0.0
python orchestrator.py scan numpy 1.26.4
python orchestrator.py scan django 5.0
```

### Bulk Scan from Requirements File

```bash
# Create a requirements-style file
cat > packages.txt << EOF
flask==3.0.0
django==5.0
numpy==1.26.4
pandas==2.1.4
requests==2.31.0
EOF

# Scan all packages
python orchestrator.py bulk packages.txt
```

### Run as Webhook Listener

For automated scanning when packages are uploaded to Nexus:

```bash
python orchestrator.py serve --port 8090
```

Then configure a Nexus webhook to POST to `http://orchestrator:8090/webhook/nexus`.

### Manual Scan via API

```bash
curl -X POST http://localhost:8090/scan \
  -H "Content-Type: application/json" \
  -d '{"package": "requests", "version": "2.31.0"}'
```

## Configuration

### Scan Policy

Edit the `ScanPolicy` class in `orchestrator.py` to match your organization's risk tolerance:

```python
@dataclass
class ScanPolicy:
    # CVE Severity Thresholds
    max_cvss_score: float = 7.0           # Block if any CVE exceeds this
    block_on_critical: bool = True         # Block CRITICAL severity
    block_on_high: bool = False            # Block HIGH severity (stricter)
    
    # License Compliance
    allowed_licenses: list = field(default_factory=lambda: [
        "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
        "ISC", "PSF-2.0", "Python-2.0", "LGPL-2.1", "LGPL-3.0",
        "MPL-2.0", "Unlicense", "CC0-1.0",
    ])
    
    # Behavioral Analysis
    block_on_network_activity: bool = True    # Suspicious outbound connections
    block_on_file_system_access: bool = False # Many legit packages do this
    
    # Malware Detection
    block_on_known_malware: bool = True       # OSV MAL- entries
```

### Scan Verdicts

| Verdict | Meaning | Action |
|---------|---------|--------|
| `PASS` | No issues found | Promoted to `pypi-trusted` |
| `WARN` | Non-blocking issues (e.g., HIGH CVE when only CRITICAL blocks) | Promoted to `pypi-trusted`, flagged for review |
| `FAIL` | Policy violation | Quarantined in `pypi-quarantine` |
| `ERROR` | Scan infrastructure failure | Not uploaded anywhere, investigate |

## Vulnerability Database Updates

### How Fresh is the Data?

| Scanner | Database Update Frequency | Source |
|---------|---------------------------|--------|
| **Trivy** | Built every 6 hours, Trivy checks every 12 hours | NVD, GitHub Advisories, vendor advisories |
| **OSV-Scanner** | Real-time queries to OSV API | OSV database (includes malware) |
| **Package Analysis** | N/A (behavioral, no database) | Runtime analysis |

### Forcing a Trivy DB Update

```bash
# Inside the Trivy container
docker exec trivy-server trivy image --download-db-only

# Or reset completely
docker exec trivy-server trivy --reset
```

### Zero-Day Response Time

When a new CVE is published:
1. **NVD publishes** — Usually within 24-48 hours of disclosure
2. **Trivy DB updated** — Within 6 hours of NVD publication
3. **Your scans reflect it** — Next scan after Trivy updates its local cache (up to 12 hours)

**Worst case**: ~60 hours from disclosure to detection  
**Typical case**: ~24 hours

For faster response, you can configure Trivy to update more frequently or use `--skip-db-update=false` to force fresh downloads.

## Continuous Re-scanning

**Q: What if a package was clean yesterday but has a new CVE today?**

The orchestrator includes a re-scan capability for exactly this scenario. Run it on a schedule (cron, Kubernetes CronJob, etc.):

```bash
# Re-scan all packages in the trusted repo against fresh vulnerability data
python orchestrator.py rescan --repo pypi-trusted

# Re-scan and automatically quarantine newly-vulnerable packages
python orchestrator.py rescan --repo pypi-trusted --auto-quarantine
```

### Recommended Schedule

| Environment | Re-scan Frequency |
|-------------|-------------------|
| Development | Weekly |
| Staging | Daily |
| Production | Every 6-12 hours |

### Example Cron Job

```bash
# /etc/cron.d/trust-gateway-rescan
0 */6 * * * root /usr/local/bin/python /opt/trust-gateway/orchestrator.py rescan --repo pypi-trusted --auto-quarantine >> /var/log/trust-gateway-rescan.log 2>&1
```

## Scan Reports

Every scan generates a JSON report in `scan-reports/`:

```json
{
  "package": "urllib3",
  "version": "1.26.5",
  "verdict": "warn",
  "reasons": [
    "Known vulnerability (OSV): PYSEC-2023-192",
    "Known vulnerability (OSV): GHSA-v845-jxx5-vc9f"
  ],
  "scanned_at": "2026-02-05T18:04:39.123456+00:00",
  "policy_version": "1.0",
  "scan_details": {
    "trivy": {
      "vulnerabilities_found": 2,
      "secrets_found": 0
    },
    "package_analysis": {
      "skipped": true
    },
    "osv": {
      "vulnerabilities_found": 2
    }
  }
}
```

## Developer Workflow

Once the trust gateway is running, configure developers to use the trusted group:

### pip (Python)

```bash
# ~/.pip/pip.conf
[global]
index-url = http://nexus.internal:9000/repository/pypi-group/simple/
trusted-host = nexus.internal
```

### npm (Node.js)

```bash
npm config set registry http://nexus.internal:9000/repository/npm-group/
```

### Docker

```bash
# /etc/docker/daemon.json
{
  "registry-mirrors": ["http://nexus.internal:9000/repository/docker-group/"]
}
```

## Roadmap

- [x] PyPI package scanning
- [x] Trivy integration
- [x] OSV-Scanner integration
- [x] Package Analysis integration
- [x] Policy-based promotion/quarantine
- [x] CLI and webhook modes
- [ ] npm package scanning
- [ ] Docker image scanning
- [ ] Maven/Gradle (Java) scanning
- [ ] Web UI for quarantine review
- [ ] Slack/Teams notifications
- [ ] SBOM generation (CycloneDX, SPDX)
- [ ] License compliance scanning
- [ ] Continuous re-scanning with auto-quarantine
- [ ] Azure DevOps / GitHub Actions integration

## Architecture Decisions

### Why Nexus OSS?

- Battle-tested repository manager
- Supports multiple package formats (PyPI, npm, Maven, Docker, etc.)
- Free and open source
- Rich API for automation

### Why Trivy?

- Fast, comprehensive vulnerability scanning
- Actively maintained by Aqua Security
- Database updated every 6 hours
- Supports secrets detection too

### Why Multiple Scanners?

Defense in depth. Each scanner has strengths:

| Scanner | Best At |
|---------|---------|
| Trivy | CVE detection, broad coverage |
| OSV-Scanner | Known malware (MAL- entries), GitHub advisories |
| Package Analysis | Zero-day behavioral detection, install-time attacks |

A package must pass **all** scanners to be promoted.

## Troubleshooting

### "Authentication failed"

```bash
# Verify credentials
curl -u trust-gateway-svc:YourPassword \
  "http://localhost:9000/repository/pypi-upstream/simple/requests/"

# If 401, check the user exists and has correct role
curl -s -u admin:AdminPassword \
  "http://localhost:9000/service/rest/v1/security/users" | jq '.[] | select(.userId=="trust-gateway-svc")'
```

### "Trivy container not running"

```bash
# Check container status
docker ps | grep trivy

# If not running, start it
docker-compose up -d trivy-server

# Verify it's working
docker exec trivy-server trivy --version
```

### "pip download timed out"

The package might be large, or Nexus might be slow to proxy from pypi.org on first fetch:

```bash
# Increase timeout in orchestrator.py
timeout=300  # 5 minutes instead of 2

# Or pre-warm the cache
curl -u admin:password "http://localhost:9000/repository/pypi-upstream/packages/numpy/1.26.4/numpy-1.26.4.tar.gz" > /dev/null
```

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License — see [LICENSE](LICENSE) for details.

## Acknowledgments

- [Sonatype Nexus](https://www.sonatype.com/products/nexus-repository) — Repository manager
- [Aqua Trivy](https://github.com/aquasecurity/trivy) — Vulnerability scanner
- [Google OSV-Scanner](https://github.com/google/osv-scanner) — OSV database scanner
- [OpenSSF Package Analysis](https://github.com/ossf/package-analysis) — Behavioral analysis
