FROM python:3.11-slim

# System deps (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git gnupg unzip jq \
    && rm -rf /var/lib/apt/lists/*

# Docker CLI only (not the full engine — we use the host daemon via socket mount)
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then ARCH="aarch64"; else ARCH="x86_64"; fi && \
    curl -fsSL "https://download.docker.com/linux/static/stable/${ARCH}/docker-27.5.1.tgz" \
    | tar -xz --strip-components=1 -C /usr/local/bin docker/docker

# npm (standalone via Node, needed for npm pack downloads)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# Syft (SBOM generator)
ENV SYFT_VERSION=1.4.1
RUN curl -sSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin syft

# Trivy client (thin client — sends scans to trivy-server, no local DB needed)
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
