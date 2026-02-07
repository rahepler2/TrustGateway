# Nexus Trust Gateway — Developer CLI

Command-line tool for requesting package and container scans from the Trust Gateway.

## Setup

1. Install Python 3.8+ and the `requests` library:
   ```
   pip install requests
   ```

2. Set environment variables:
   ```bash
   export TRUST_GATEWAY_URL=http://your-gateway-server:5002
   export TRUST_GATEWAY_KEY=your-api-key
   ```

   Or on Windows (PowerShell — persists across sessions):
   ```powershell
   [System.Environment]::SetEnvironmentVariable("TRUST_GATEWAY_URL", "http://your-gateway-server:5002", "User")
   [System.Environment]::SetEnvironmentVariable("TRUST_GATEWAY_KEY", "your-api-key", "User")
   ```

3. Add the `cli/` directory to your PATH, or symlink the script:
   ```bash
   # Linux/macOS
   sudo ln -s /path/to/cli/nexus-request.sh /usr/local/bin/nexus-request

   # Windows — the .cmd wrapper lets you run "nexus-request" from any shell
   # Just add the cli/ folder to your PATH
   ```

## Usage

The CLI uses the pattern: `nexus-request scan <ecosystem> <package> [version]`

Version is optional — the gateway resolves the latest automatically.

### Scanning Packages

```bash
# Python
nexus-request scan python requests              # latest version
nexus-request scan python requests==2.32.3      # specific version
nexus-request scan python requests 2.32.3       # same thing
nexus-request scan python -f requirements.txt   # batch from file

# Docker
nexus-request scan docker nginx                 # defaults to :latest
nexus-request scan docker nginx:1.25
nexus-request scan docker nginx 1.25

# npm
nexus-request scan npm express
nexus-request scan npm express@4.18.2

# Maven
nexus-request scan maven org.apache.commons:commons-lang3:3.14.0

# NuGet
nexus-request scan nuget Newtonsoft.Json 13.0.3
```

### Rescanning

```bash
nexus-request rescan python     # rescan all trusted Python packages
nexus-request rescan --all      # rescan everything
```

### Checking Status

```bash
nexus-request status <job-id>
nexus-request status --batch <batch-id>
```

## How it works

1. You run `nexus-request scan python flask`
2. The Gateway resolves the latest version, downloads it through Nexus, scans it with Trivy + OSSF + OSV + Syft
3. If it passes, it's promoted to the trusted repo
4. You can then `pip install flask` normally — Nexus serves it from the trusted repo

The CLI prints the Job ID and polls the Gateway, showing progress while scanning.

## Ecosystem Aliases

You can use common names — the CLI maps them to the right ecosystem:

| You type | Resolves to |
|----------|-------------|
| `python`, `pip`, `pypi` | pypi |
| `npm`, `node`, `js` | npm |
| `docker`, `container`, `image` | docker |
| `maven`, `java`, `mvn` | maven |
| `nuget`, `dotnet`, `csharp` | nuget |
