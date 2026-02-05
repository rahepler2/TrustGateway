"""
MinIO / S3-compatible object storage for scan reports and SBOMs.
"""
import boto3
from botocore.client import Config

from .config import MINIO_ENDPOINT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, MINIO_BUCKET

s3 = boto3.client(
    "s3",
    endpoint_url=MINIO_ENDPOINT,
    aws_access_key_id=MINIO_ACCESS_KEY,
    aws_secret_access_key=MINIO_SECRET_KEY,
    config=Config(signature_version="s3v4"),
    region_name="us-east-1",
)


def ensure_bucket():
    try:
        s3.head_bucket(Bucket=MINIO_BUCKET)
    except Exception:
        s3.create_bucket(Bucket=MINIO_BUCKET)


def upload_file(local_path: str, key: str) -> str:
    ensure_bucket()
    s3.upload_file(local_path, MINIO_BUCKET, key)
    return f"{MINIO_ENDPOINT.rstrip('/')}/{MINIO_BUCKET}/{key}"
