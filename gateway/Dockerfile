FROM python:3.11-slim

# System deps + package managers needed for downloading artifacts
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git gnupg unzip build-essential jq \
    npm docker.io \
    && rm -rf /var/lib/apt/lists/*

# Syft (SBOM generator)
ENV SYFT_VERSION=1.4.1
RUN curl -sSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin syft

# Trivy client (calls the Trivy server, also supports local fs scans)
ENV TRIVY_VERSION=0.58.2
RUN curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    | tar -xz -C /usr/local/bin trivy

WORKDIR /app

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the gateway package
COPY . /app/gateway/

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create data dirs
RUN mkdir -p /data /app/scan-reports

ENV PYTHONUNBUFFERED=1
EXPOSE 5000

ENTRYPOINT ["/entrypoint.sh"]
