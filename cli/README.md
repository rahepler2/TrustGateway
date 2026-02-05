# Nexus Trust Gateway — Developer CLI

Command-line tool for requesting package and container scans from the Trust Gateway.

## Setup

1. Install Python 3.8+ and the `requests` library:
   ```
   pip install requests
   ```

2. Set environment variables:
   ```bash
   export TRUST_GATEWAY_URL=http://your-gateway-server:5000
   # Optional: export TRUST_GATEWAY_KEY=your-api-key
   ```

   Or on Windows (PowerShell):
   ```powershell
   $env:TRUST_GATEWAY_URL = "http://your-gateway-server:5000"
   ```

## Usage

### Python (cross-platform)

```bash
# Submit a PyPI package
python nexus-request.py submit -p "flask==3.0.0" --wait 300

# Submit an npm package
python nexus-request.py submit -p "express==4.18.2" -e npm

# Submit a Docker image
python nexus-request.py submit -p "nginx==1.25" -e docker --wait 600

# Batch scan from requirements.txt
python nexus-request.py submit-batch -r requirements.txt

# Check status
python nexus-request.py status --job <job-id>
python nexus-request.py status --batch <batch-id>
```

### PowerShell (Windows)

```powershell
.\nexus-request.ps1 submit -Package "flask==3.0.0"
.\nexus-request.ps1 submit -Package "nginx==1.25" -Ecosystem docker
.\nexus-request.ps1 submit-batch -Requirements requirements.txt
.\nexus-request.ps1 status -Job "abc-123"
```

### Bash (Linux/Mac)

```bash
./nexus-request.sh submit -p "flask==3.0.0"
./nexus-request.sh submit-batch -r requirements.txt
```

## How it works

1. You submit a package spec (e.g., `flask==3.0.0`)
2. The Gateway downloads it through Nexus, scans it with Trivy + OSSF + OSV
3. If it passes, it's promoted to the trusted repo
4. You can then `pip install` / `npm install` / `docker pull` normally from Nexus

The CLI polls the Gateway and shows progress while scanning is in progress.
