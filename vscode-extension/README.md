# Trust Gateway for VS Code

Real-time security scanning for your dependencies, powered by [Nexus Trust Gateway](https://github.com/rahepler2/TrustGateway).

See CVEs, license issues, and policy verdicts inline in your editor — the moment you add or update a dependency.

---

## What It Does

Trust Gateway for VS Code connects to your running Trust Gateway instance and scans every dependency declared in your project. Results appear as:

- **Inline diagnostics** — Red/yellow underlines on vulnerable dependencies
- **Hover cards** — Detailed CVE info, SBOM summary, and policy reasons on hover
- **CodeLens** — Verdict + CVE count above each dependency line
- **Problems panel** — All issues in one place, filterable and sortable
- **Sidebar tree view** — Full dependency security overview per file
- **Status bar** — Workspace-level security posture at a glance

### Example

```
  PASS 0 CVEs | 12 components | MIT, BSD-3-Clause
flask==3.0.0
  FAIL 3 critical, 5 high | 42 components
Django==5.1.5                          <-- red underline
  WARN 1 advisory (PYSEC-2024-001)
urllib3==2.0.7                         <-- yellow underline
```

Hovering over `Django==5.1.5` shows:

> **Django==5.1.5 -- FAIL**
>
> Vulnerabilities: 3 critical, 5 high, 8 medium
> SBOM: 42 components (MIT, BSD-3-Clause, Apache-2.0)
>
> Policy Reasons:
> - CRITICAL CVE: CVE-2024-12345 in django.utils.html (fixed in 5.1.6)
> - HIGH CVE: CVE-2024-12346 in django.middleware.csrf (fixed in 5.1.6)
>
> [View Full Report] [Open in Grafana] [Rescan]

---

## Prerequisites

You need a running **Nexus Trust Gateway** instance. The gateway handles all scanning (Trivy, OSSF, OSV, Syft) — this extension is a lightweight client that displays results.

- Trust Gateway running and accessible (default: `http://localhost:5002`)
- Optional: API key if your gateway has authentication enabled
- Optional: Grafana for "Open in Grafana" links (default: `http://localhost:3000`)

See the [Trust Gateway repo](https://github.com/rahepler2/TrustGateway) for setup instructions.

---

## Installation

### From VS Code Marketplace

1. Open VS Code
2. Go to Extensions (`Cmd+Shift+X` / `Ctrl+Shift+X`)
3. Search for **"Trust Gateway"**
4. Click Install

### From VSIX (local build)

```bash
cd trust-gateway-vscode
npm install
npm run package
code --install-extension trust-gateway-*.vsix
```

---

## Quick Start

1. **Install the extension**
2. **Configure the gateway URL** (if not localhost:5002):
   - Open Settings (`Cmd+,`)
   - Search "Trust Gateway"
   - Set `trustGateway.url` to your gateway address
3. **Set your API key** (if authentication is enabled):
   - Command Palette (`Cmd+Shift+P`) -> `Trust Gateway: Set API Key`
   - Enter your key (stored encrypted, never in plain settings)
4. **Open a project** with a `requirements.txt`, `package.json`, or other dependency file
5. **Dependencies are scanned automatically** on file open and save

---

## Supported Dependency Files

| File | Ecosystem | What's Parsed |
|------|-----------|---------------|
| `requirements.txt` | Python (PyPI) | `package==version` lines |
| `constraints.txt` | Python (PyPI) | Same as requirements.txt |
| `Pipfile` | Python (PyPI) | `[packages]` section |
| `pyproject.toml` | Python (PyPI) | `[project.dependencies]` or `[tool.poetry.dependencies]` |
| `package.json` | Node.js (npm) | `dependencies` + `devDependencies` |
| `pom.xml` | Java (Maven) | `<dependency>` elements |
| `build.gradle` | Java (Maven) | `implementation`/`compile` declarations |
| `*.csproj` | .NET (NuGet) | `<PackageReference>` elements |
| `packages.config` | .NET (NuGet) | `<package>` elements |
| `Dockerfile` | Docker | `FROM image:tag` lines |
| `docker-compose.yml` | Docker | `image:` fields |

---

## Verdicts

The gateway evaluates each package through a 7-step pipeline (download, extract, Trivy scan, OSSF behavioral analysis, OSV advisory check, Syft SBOM, policy evaluation) and returns one of four verdicts:

| Verdict | Meaning | VS Code Display |
|---------|---------|-----------------|
| **PASS** | All scans passed. No known vulnerabilities, no suspicious behavior. Package is promoted to the trusted repository. | Blue info underline (optional, off by default) |
| **WARN** | Non-critical advisory found (e.g., OSV `PYSEC-*` or `GHSA-*`). Package is quarantined for review. | Yellow warning underline |
| **FAIL** | Blocked. Critical/high CVEs, known malware, secrets detected, or suspicious OSSF behavior. Package is quarantined. | Red error underline |
| **ERROR** | Scan could not complete (download failed, scanner crashed, timeout). | Red error underline |

---

## Settings

All settings are prefixed with `trustGateway.`:

### Connection

| Setting | Default | Description |
|---------|---------|-------------|
| `url` | `http://localhost:5002` | Trust Gateway API endpoint |
| `apiKey` | _(empty)_ | API key (use "Set API Key" command instead for secure storage) |

### Behavior

| Setting | Default | Description |
|---------|---------|-------------|
| `autoScan` | `true` | Automatically scan when dependency files are opened |
| `scanOnSave` | `true` | Re-scan when a dependency file is saved |
| `debounceMs` | `2000` | Delay before auto-scanning after edits (ms) |
| `showPassingDeps` | `false` | Show PASS diagnostics (can be noisy on large projects) |

### Display

| Setting | Default | Description |
|---------|---------|-------------|
| `codeLens.enabled` | `true` | Show CodeLens annotations above dependencies |
| `diagnostics.enabled` | `true` | Show inline diagnostics (underlines) |
| `statusBar.enabled` | `true` | Show security status in the status bar |
| `treeView.enabled` | `true` | Show the Trust Gateway sidebar panel |

### Grafana Integration

| Setting | Default | Description |
|---------|---------|-------------|
| `grafanaUrl` | `http://localhost:3000` | Grafana base URL for "Open in Grafana" links |
| `grafanaDashboardUid` | `trust-gateway-detail` | Dashboard UID for package detail view |

---

## Commands

Open the Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`):

| Command | Description |
|---------|-------------|
| `Trust Gateway: Scan All Dependencies` | Scan every dependency file in the workspace |
| `Trust Gateway: Scan Current File` | Scan the active editor's dependency file |
| `Trust Gateway: Clear Cache` | Clear cached results and re-scan everything |
| `Trust Gateway: Set API Key` | Securely store your gateway API key |
| `Trust Gateway: Set Gateway URL` | Configure the gateway endpoint |
| `Trust Gateway: Show Report` | View the full scan report JSON for a package |
| `Trust Gateway: Open in Grafana` | Jump to the Grafana dashboard for a scan |

---

## Quick Fixes

When hovering over a failed/warned dependency, the lightbulb menu offers:

- **Update to fixed version** — If the CVE specifies a `fixed` version, updates the version string in-place
- **View CVE in browser** — Opens the NVD page for the CVE ID
- **Suppress this CVE** — Adds `# trust-gateway: ignore CVE-XXXX-XXXXX` inline comment
- **Rescan package** — Triggers a fresh scan (bypasses cache)

---

## How It Works

```
1. You open requirements.txt
2. Extension parses each "package==version" line
3. POST /request is sent to your Trust Gateway
4. Gateway downloads the package, scans with Trivy/OSSF/OSV/Syft,
   evaluates policy, and returns a verdict
5. Extension maps results to line numbers
6. Diagnostics, CodeLens, hover cards, and tree view update
7. Results are cached (30 min TTL) to avoid redundant scans
```

The extension polls `GET /job/<id>` every 3 seconds while scans are in progress, and shows a spinner in the status bar.

---

## Privacy & Security

- Package names and versions are sent **only** to your configured gateway URL
- No data is sent to any third-party service
- No telemetry is collected
- API keys are stored in VS Code's encrypted `SecretStorage`
- The extension makes no outbound connections other than to your gateway

---

## Development

### Build from source

```bash
git clone https://github.com/rahepler2/trust-gateway-vscode.git
cd trust-gateway-vscode
npm install
npm run compile
```

### Run in development

1. Open the project in VS Code
2. Press `F5` to launch the Extension Development Host
3. Open a project with dependency files in the new window

### Run tests

```bash
npm test
```

### Package

```bash
npm run package
# Produces trust-gateway-<version>.vsix
```

---

## Relationship to Trust Gateway

This extension is a **client** for the [Nexus Trust Gateway](https://github.com/rahepler2/TrustGateway). The gateway is the security scanning engine — it handles:

- Package download from Nexus proxy repositories
- Vulnerability scanning (Trivy)
- Behavioral analysis (OSSF package-analysis)
- Malware/advisory checking (OSV)
- SBOM generation and license analysis (Syft)
- Policy evaluation (fail-closed, zero-trust model)
- Package promotion (trusted) or quarantine

The extension simply calls the gateway's REST API and presents results in VS Code. You can use the gateway without this extension (via CLI or Grafana), and you can use the CLI alongside this extension.

---

## License

MIT
