# Trust Gateway VS Code Extension — Design Document

## Overview

A VS Code extension that integrates with the Nexus Trust Gateway to provide real-time security visibility directly in the editor. Developers see CVE warnings, license issues, and policy verdicts inline — right where they declare their dependencies — without leaving their IDE.

**Name:** `trust-gateway` (marketplace: `trust-gateway-vscode`)

---

## Problem

Developers currently discover security issues only when they:
1. Manually run `nexus-request scan` from the terminal
2. Push code and hit a CI gate
3. Check the Grafana dashboard after the fact

All of these are too late in the feedback loop. By the time a developer learns a dependency is vulnerable, they've already written code against it.

---

## Solution

Bring Trust Gateway scan results into VS Code as first-class diagnostics — squiggly underlines, Problems panel entries, hover cards, and CodeLens annotations — so developers see security issues the moment they add or update a dependency.

---

## Architecture

```
+-------------------+        HTTPS / HTTP        +-------------------+
|                   |  POST /request             |                   |
|   VS Code         |  GET  /job/<id>            |   Trust Gateway   |
|   Extension       | <------------------------> |   API (:5002)     |
|                   |  X-API-Key auth            |                   |
+-------------------+                            +-------------------+
        |                                                |
        | Parses                                         | Scans via
        v                                                v
+-------------------+                            +-------------------+
| requirements.txt  |                            | Trivy, OSSF, OSV  |
| package.json      |                            | Syft (SBOM)       |
| pom.xml           |                            | Nexus (repos)     |
| *.csproj          |                            +-------------------+
+-------------------+
```

The extension is a **thin client**. All scanning logic stays in the gateway. The extension:
1. Detects dependency files in the workspace
2. Parses package names and versions
3. Sends them to the gateway API
4. Maps results back to file locations
5. Displays diagnostics, hovers, and CodeLens

---

## Core Features

### 1. Inline Diagnostics (Squiggly Lines)

When a dependency file is open, the extension underlines each dependency with a diagnostic:

| Verdict | Severity | Appearance |
|---------|----------|------------|
| FAIL    | Error (red) | `Django==5.1.5 — FAIL: 3 critical, 5 high CVEs` |
| WARN    | Warning (yellow) | `requests==2.31.0 — WARN: OSV advisory PYSEC-2024-001` |
| PASS    | Information (blue) | `flask==3.0.0 — PASS` |
| ERROR   | Error (red) | `foo==0.0.1 — ERROR: download failed` |

Diagnostics appear in the **Problems** panel and as underlines in the editor.

### 2. Hover Cards

Hovering over a dependency shows a rich tooltip:

```
Django==5.1.5 — FAIL

Vulnerabilities: 3 critical, 5 high, 8 medium, 0 low
SBOM: 42 components (MIT, BSD-3-Clause, Apache-2.0)
OSSF: skipped (static analysis only)
OSV: 1 advisory

Policy Reasons:
  - CRITICAL CVE: CVE-2024-12345 in django.utils.html (fixed in 5.1.6)
  - HIGH CVE: CVE-2024-12346 in django.middleware.csrf (fixed in 5.1.6)
  - HIGH CVE: CVE-2024-12347 in django.core.mail (fixed in 5.1.7)

[View Full Report]  [View in Grafana]  [Rescan]
```

### 3. CodeLens

Above each dependency line, a CodeLens annotation shows the verdict at a glance:

```
  PASS 0 CVEs | 12 components | MIT
flask==3.0.0
  FAIL 3 critical, 5 high | 42 components
Django==5.1.5
```

Clicking the CodeLens opens the hover card or navigates to the Grafana detail dashboard.

### 4. Status Bar

A persistent status bar item shows the workspace security posture:

```
[shield-icon] 12 deps: 8 pass, 3 fail, 1 warn
```

Clicking it opens the Trust Gateway panel (tree view).

### 5. Tree View (Sidebar Panel)

A dedicated sidebar panel under the Explorer or a custom activity bar icon:

```
TRUST GATEWAY
  requirements.txt
    PASS  flask==3.0.0         0 CVEs
    FAIL  Django==5.1.5        3 critical, 5 high
    PASS  requests==2.31.0     0 CVEs
    WARN  urllib3==2.0.7       1 advisory
  package.json
    PASS  express@4.18.2       0 CVEs
    FAIL  lodash@4.17.20       2 high
```

Each entry is expandable to show CVE details, SBOM summary, and policy reasons.

### 6. File Watcher + Auto-Scan

The extension watches dependency files for changes. When a developer adds or updates a dependency:

1. Parse the changed line
2. Submit a scan to the gateway (debounced, 2-second delay)
3. Show a progress indicator on the line
4. Update diagnostics when the scan completes

### 7. Quick Fix Actions

For FAIL/WARN verdicts, the extension offers quick fixes:

- **"Update to safe version"** — If the CVE has a `fixed` version, offer to update the version string
- **"View CVE details"** — Opens the CVE in the browser (NVD link)
- **"Suppress warning"** — Adds a `# trust-gateway: ignore CVE-2024-12345` comment
- **"Rescan package"** — Re-triggers a fresh scan

### 8. Batch Scan Command

Command palette: `Trust Gateway: Scan All Dependencies`

Submits the entire dependency file as a batch via `POST /request/batch`, shows progress in a notification, and updates all diagnostics when complete.

---

## Supported Dependency Files

| File | Ecosystem | Parser |
|------|-----------|--------|
| `requirements.txt` | pypi | Line-based: `package==version` |
| `constraints.txt` | pypi | Same as requirements.txt |
| `Pipfile` | pypi | TOML `[packages]` section |
| `pyproject.toml` | pypi | `[project.dependencies]` or `[tool.poetry.dependencies]` |
| `package.json` | npm | JSON `dependencies` + `devDependencies` |
| `package-lock.json` | npm | JSON `packages` (for audit, not individual scans) |
| `pom.xml` | maven | XML `<dependency>` elements |
| `build.gradle` | maven | Regex on `implementation`/`compile` strings |
| `*.csproj` | nuget | XML `<PackageReference>` elements |
| `packages.config` | nuget | XML `<package>` elements |
| `Dockerfile` | docker | `FROM image:tag` lines |
| `docker-compose.yml` | docker | `image:` fields |

---

## Configuration (VS Code Settings)

```jsonc
{
  // Gateway connection
  "trustGateway.url": "http://localhost:5002",
  "trustGateway.apiKey": "",

  // Behavior
  "trustGateway.autoScan": true,          // Scan on file open/save
  "trustGateway.scanOnSave": true,        // Trigger scan when dependency file is saved
  "trustGateway.debounceMs": 2000,        // Debounce delay for auto-scan
  "trustGateway.showPassingDeps": false,   // Show PASS verdicts (can be noisy)
  "trustGateway.codeLens.enabled": true,
  "trustGateway.diagnostics.enabled": true,
  "trustGateway.statusBar.enabled": true,
  "trustGateway.treeView.enabled": true,

  // Display
  "trustGateway.severity.fail": "Error",       // VS Code DiagnosticSeverity
  "trustGateway.severity.warn": "Warning",
  "trustGateway.severity.pass": "Information",
  "trustGateway.severity.error": "Error",

  // Grafana integration (optional)
  "trustGateway.grafanaUrl": "http://localhost:3000",
  "trustGateway.grafanaDashboardUid": "trust-gateway-detail"
}
```

---

## API Integration Details

### Authentication

The extension sends the API key as an `X-API-Key` header on every request:

```typescript
const headers: Record<string, string> = {
  "Content-Type": "application/json",
};
if (apiKey) {
  headers["X-API-Key"] = apiKey;
}
```

The API key is stored in VS Code's `SecretStorage` (encrypted), not in plain settings.

### Scan Flow

```
1. Parse dependency file → [{ package, version, line, ecosystem }]
2. POST /request { packages: ["flask==3.0.0", "Django==5.1.5"], ecosystem: "pypi", wait: 0 }
3. Response: { status: "accepted", job_ids: ["uuid1", "uuid2"] }
4. Poll GET /job/<uuid1> every 3s until status != "running"
5. Poll GET /job/<uuid2> every 3s until status != "running"
6. Map results back to line numbers
7. Create diagnostics + update tree view
```

For batch scans (requirements files):

```
1. POST /request/batch (multipart, file upload)
2. Response: { batch_id, jobs: [{job_id, package, version}] }
3. Poll GET /batch/<batch_id>/status every 5s
4. When overall != "running", map all results to lines
```

### Response Mapping

The extension maps the gateway's scan result JSONB to VS Code constructs:

```typescript
interface ScanResult {
  verdict: "pass" | "warn" | "fail" | "error";
  report: string;
  trivy: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
  };
  cves: Array<{
    id: string;          // "CVE-2024-12345"
    severity: string;    // "critical" | "high" | "medium" | "low"
    pkg: string;         // affected sub-package
    installed: string;   // installed version
    fixed: string;       // version with fix
    title: string;       // human-readable description
    target: string;      // file/path target
  }>;
  secrets: number;
  sbom: {
    component_count: number;
    format: string;
    licenses: string[];
    components: Array<{
      name: string;
      version: string;
      type: string;
      license: string;
    }>;
  };
  ossf_skipped: boolean;
  osv_count: number;
  reasons: string[];
}
```

---

## Project Structure

```
trust-gateway-vscode/
  src/
    extension.ts          # Activation, command registration, lifecycle
    gateway/
      client.ts           # HTTP client for Trust Gateway API
      types.ts            # TypeScript interfaces for API responses
      poller.ts           # Job/batch polling with backoff
    parsers/
      index.ts            # Parser registry + auto-detection
      requirements.ts     # requirements.txt / constraints.txt
      packageJson.ts      # package.json
      pyproject.ts        # pyproject.toml
      pomXml.ts           # pom.xml
      csproj.ts           # *.csproj / packages.config
      dockerfile.ts       # Dockerfile / docker-compose.yml
      gradle.ts           # build.gradle
      pipfile.ts          # Pipfile
    providers/
      diagnostics.ts      # DiagnosticCollection management
      codeLens.ts         # CodeLensProvider
      hover.ts            # HoverProvider
      quickFix.ts         # CodeActionProvider (quick fixes)
    views/
      treeView.ts         # TreeDataProvider for sidebar
      statusBar.ts        # Status bar item
    cache.ts              # In-memory result cache (TTL-based)
    config.ts             # Settings wrapper
  test/
    suite/
      parsers.test.ts
      client.test.ts
      diagnostics.test.ts
  package.json            # Extension manifest
  tsconfig.json
  .vscodeignore
  CHANGELOG.md
  LICENSE
  README.md
```

---

## Dependency File Parsing

Each parser returns a common shape:

```typescript
interface ParsedDependency {
  name: string;
  version: string | null;   // null = unpinned (skip or resolve latest)
  line: number;              // 0-based line number in the file
  startChar: number;         // column start for the package==version text
  endChar: number;           // column end
  ecosystem: string;         // pypi | npm | docker | maven | nuget
  raw: string;               // original line text
}
```

Parsers must handle:
- Comments (`#`, `//`, `<!-- -->`)
- Extras (`flask[async]==3.0.0` → package=`flask`)
- Environment markers (`requests==2.31.0; python_version >= "3.8"`)
- Version ranges (`^1.0.0`, `~=3.0`, `>=2.0,<3.0` — use the lower bound)
- Scoped packages (`@types/node@20.0.0`)

---

## Caching Strategy

Results are cached in-memory with a configurable TTL (default: 30 minutes):

```typescript
interface CacheEntry {
  result: ScanResult;
  timestamp: number;
  jobId: string;
}

// Cache key: `${ecosystem}:${name}:${version}`
```

Cache is invalidated when:
- TTL expires
- User manually triggers "Rescan"
- Dependency version changes in the file

The extension does NOT re-scan packages that already have a cached result when a file is opened. This prevents hammering the gateway.

---

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Gateway unreachable | Status bar shows "Gateway offline". Diagnostics show stale cached results (if any). Retry on next save. |
| 401 Unauthorized | Prompt user to enter/update API key via command palette |
| Scan timeout (job never completes) | After 5 minutes of polling, mark as ERROR diagnostic |
| Invalid dependency file | Skip unparseable lines silently |
| Rate limiting (429) | Exponential backoff on polling |

---

## Commands (Command Palette)

| Command | Description |
|---------|-------------|
| `Trust Gateway: Scan All Dependencies` | Batch scan every dependency file in workspace |
| `Trust Gateway: Scan Current File` | Scan dependencies in the active editor |
| `Trust Gateway: Clear Cache` | Clear all cached results and re-scan |
| `Trust Gateway: Set API Key` | Store the gateway API key securely |
| `Trust Gateway: Set Gateway URL` | Configure the gateway endpoint |
| `Trust Gateway: Show Report` | Open the full JSON scan report for a package |
| `Trust Gateway: Open in Grafana` | Open the Grafana detail dashboard for a scan job |

---

## Telemetry / Privacy

- The extension sends package names and versions to the configured gateway URL only
- No data is sent to any third-party service
- No telemetry is collected by the extension itself
- API keys are stored in VS Code's encrypted SecretStorage, never in settings JSON

---

## Future Considerations

- **Multi-root workspace support** — Scan each workspace folder independently
- **Remote development** — Work over SSH/containers via VS Code Remote
- **Pre-commit hook integration** — Block commits if FAIL verdicts exist
- **Dependency graph visualization** — Show transitive dependency tree with CVE propagation
- **Auto-update suggestions** — When a safe version exists, offer a one-click update via CodeAction
- **CI status overlay** — Show if the same package passed/failed in CI (query gateway DB)
