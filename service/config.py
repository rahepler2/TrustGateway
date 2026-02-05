import os

# Database
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://trivy:trivy_pass@postgres:5432/trivydb")

# MinIO / S3
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "http://minio:9000")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "trivy-reports")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")

# Scan workers
SCAN_WORKERS = int(os.getenv("SCAN_WORKERS", "3"))

# Trust gateway / Nexus
NEXUS_URL = os.getenv("NEXUS_URL", "http://nexus:8081")
NEXUS_USER = os.getenv("NEXUS_USER")
NEXUS_PASS = os.getenv("NEXUS_PASS")

# Trivy
TRIVY_SERVER_URL = os.getenv("TRIVY_SERVER_URL", "http://trivy-server:8080")
TRIVY_CONTAINER = os.getenv("TRIVY_CONTAINER", "trivy-server")

# API key (simple protection until LDAP/AD integration)
API_KEY = os.getenv("TRUST_GATEWAY_API_KEY")
