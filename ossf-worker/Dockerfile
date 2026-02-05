FROM golang:1.22-bookworm AS builder

# Build the OSSF package-analysis 'analyze' binary from source
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/ossf/package-analysis.git /src/package-analysis
WORKDIR /src/package-analysis
RUN go build -o /usr/local/bin/analyze ./cmd/analyze/

# ---------------------------------------------------------------------------
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates strace \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/analyze /usr/local/bin/analyze

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

ENV PYTHONUNBUFFERED=1
EXPOSE 8090

CMD ["python", "app.py"]
