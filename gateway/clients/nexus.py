"""
Nexus Repository Manager client.

Handles download (via pip/npm/docker), upload (promote/quarantine),
and search operations against Nexus hosted/proxy/group repos.
"""
from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import quote, urlparse

import requests as http_requests

from ..config import NexusConfig

log = logging.getLogger("trust-gateway")


class NexusClient:
    def __init__(self, config: NexusConfig):
        self.config = config
        self.session = http_requests.Session()
        if config.username and config.password:
            self.session.auth = (config.username, config.password)
        else:
            log.warning("Nexus credentials not provided; API operations will likely fail.")
        self.base = config.base_url.rstrip("/")

    # -- download -------------------------------------------------------------

    def download_package(self, package: str, version: str, dest_dir: str,
                         ecosystem: str = "pypi") -> Optional[Path]:
        """Download a package from the proxy repo. Delegates to ecosystem-specific logic."""
        repos = self.config.repos_for(ecosystem)
        proxy_repo = repos["proxy"]

        if ecosystem.lower() == "pypi":
            return self._download_pypi(package, version, dest_dir, proxy_repo)
        elif ecosystem.lower() == "npm":
            return self._download_npm(package, version, dest_dir, proxy_repo)
        elif ecosystem.lower() == "docker":
            return self._download_docker(package, version, dest_dir)
        elif ecosystem.lower() in ("maven", "nuget"):
            return self._download_generic(package, version, dest_dir, proxy_repo, ecosystem)
        else:
            log.error(f"Unsupported ecosystem for download: {ecosystem}")
            return None

    def _download_pypi(self, package: str, version: str, dest_dir: str,
                       proxy_repo: str) -> Optional[Path]:
        log.info(f"Downloading {package}=={version} from Nexus PyPI proxy '{proxy_repo}'")
        if not self.config.username or not self.config.password:
            log.error("NEXUS_USER and NEXUS_PASS are required for proxy downloads.")
            return None

        test_url = f"{self.base}/repository/{proxy_repo}/simple/"
        try:
            resp = self.session.get(test_url, timeout=10)
            if resp.status_code == 401:
                log.error("Nexus authentication failed (401).")
                return None
            if resp.status_code != 200:
                log.error(f"Nexus returned HTTP {resp.status_code} for {test_url}")
                return None
        except Exception as e:
            log.error(f"Error connecting to Nexus: {e}")
            return None

        parsed = urlparse(self.base)
        encoded_user = quote(self.config.username, safe="")
        encoded_pass = quote(self.config.password, safe="")
        proxy_url = (
            f"{parsed.scheme}://{encoded_user}:{encoded_pass}"
            f"@{parsed.netloc}/repository/{proxy_repo}/simple/"
        )
        host = parsed.netloc.split(":")[0]

        cmd = [
            sys.executable, "-m", "pip", "download",
            f"{package}=={version}",
            "--no-deps", "--dest", dest_dir,
            "--index-url", proxy_url,
            "--trusted-host", host,
        ]
        log.debug(f"Running pip download for {package}=={version}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            log.error("pip download timed out")
            return None

        if result.returncode != 0:
            log.error(f"pip download failed (exit {result.returncode})")
            log.debug(result.stderr[:800])
            return None

        files = list(Path(dest_dir).iterdir())
        if files:
            log.info(f"Downloaded: {files[0].name}")
            return files[0]
        log.error("pip reported success but no files found")
        return None

    def _download_npm(self, package: str, version: str, dest_dir: str,
                      proxy_repo: str) -> Optional[Path]:
        log.info(f"Downloading {package}@{version} from Nexus npm proxy '{proxy_repo}'")
        registry_url = f"{self.base}/repository/{proxy_repo}/"
        cmd = [
            "npm", "pack", f"{package}@{version}",
            "--registry", registry_url,
            "--pack-destination", dest_dir,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            log.error("npm pack timed out")
            return None

        if result.returncode != 0:
            log.error(f"npm pack failed (exit {result.returncode}): {result.stderr[:300]}")
            return None

        files = list(Path(dest_dir).glob("*.tgz"))
        if files:
            log.info(f"Downloaded: {files[0].name}")
            return files[0]
        log.error("npm pack succeeded but no tarball found")
        return None

    def _download_docker(self, image: str, tag: str, dest_dir: str) -> Optional[Path]:
        """Pull a Docker image and save it as a tarball for scanning."""
        log.info(f"Pulling Docker image {image}:{tag}")
        pull_cmd = ["docker", "pull", f"{image}:{tag}"]
        try:
            result = subprocess.run(pull_cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            log.error("docker pull timed out")
            return None
        except Exception as e:
            log.error(f"docker pull exception: {type(e).__name__}: {e}")
            return None
        if result.returncode != 0:
            log.error(f"docker pull failed: {result.stderr[:300]}")
            return None

        safe_name = image.replace("/", "_").replace(":", "_")
        tarball = Path(dest_dir) / f"{safe_name}-{tag}.tar"
        save_cmd = ["docker", "save", "-o", str(tarball), f"{image}:{tag}"]
        try:
            result = subprocess.run(save_cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            log.error("docker save timed out")
            return None
        except Exception as e:
            log.error(f"docker save exception: {type(e).__name__}: {e}")
            return None
        if result.returncode != 0:
            log.error(f"docker save failed: {result.stderr[:300]}")
            return None

        log.info(f"Saved image to {tarball.name}")
        return tarball

    def _download_generic(self, package: str, version: str, dest_dir: str,
                          proxy_repo: str, ecosystem: str) -> Optional[Path]:
        """Generic download via Nexus search API + direct artifact fetch."""
        log.info(f"Downloading {package}:{version} from '{proxy_repo}' ({ecosystem})")
        search_url = f"{self.base}/service/rest/v1/search/assets"
        params = {"repository": proxy_repo, "name": package, "version": version}
        try:
            resp = self.session.get(search_url, params=params, timeout=30)
            if resp.status_code != 200:
                log.error(f"Nexus search failed ({resp.status_code})")
                return None
            items = resp.json().get("items", [])
            if not items:
                log.error(f"No assets found for {package}:{version} in {proxy_repo}")
                return None
            download_url = items[0].get("downloadUrl")
            if not download_url:
                log.error("No downloadUrl in search result")
                return None
            dl_resp = self.session.get(download_url, timeout=120, stream=True)
            dl_resp.raise_for_status()
            filename = download_url.split("/")[-1]
            dest_path = Path(dest_dir) / filename
            with open(dest_path, "wb") as f:
                for chunk in dl_resp.iter_content(chunk_size=8192):
                    f.write(chunk)
            log.info(f"Downloaded: {dest_path.name}")
            return dest_path
        except Exception as e:
            log.error(f"Download error: {e}")
            return None

    # -- upload ---------------------------------------------------------------

    def upload_to_repo(self, repo_name: str, package_file: Path,
                       ecosystem: str = "pypi") -> bool:
        """Upload an artifact to a Nexus hosted repo."""
        if not self.config.username or not self.config.password:
            log.error("NEXUS_USER and NEXUS_PASS required to upload artifacts.")
            return False

        if ecosystem.lower() == "pypi":
            return self._upload_pypi(repo_name, package_file)
        if ecosystem.lower() == "docker":
            return self._upload_docker(repo_name, package_file)
        return self._upload_raw(repo_name, package_file)

    def _upload_pypi(self, repo_name: str, package_file: Path) -> bool:
        upload_url = f"{self.base}/repository/{repo_name}/"
        filename = package_file.name
        pkg_name, pkg_version = self._parse_package_filename(filename)

        try:
            with open(package_file, "rb") as f:
                data = {
                    ":action": "file_upload",
                    "protocol_version": "1",
                    "name": pkg_name,
                    "version": pkg_version,
                    "filetype": "bdist_wheel" if filename.endswith(".whl") else "sdist",
                }
                files = {"content": (filename, f, "application/octet-stream")}
                resp = self.session.post(upload_url, data=data, files=files, timeout=30)
        except Exception as e:
            log.error(f"Upload exception: {e}")
            return False

        if resp.status_code in (200, 201, 204):
            log.info(f"Uploaded {filename} to {repo_name}")
            return True

        log.warning(f"Upload returned {resp.status_code}; trying components API fallback")
        return self._upload_via_components_api(repo_name, package_file)

    def _upload_via_components_api(self, repo_name: str, package_file: Path) -> bool:
        url = f"{self.base}/service/rest/v1/components?repository={repo_name}"
        try:
            with open(package_file, "rb") as f:
                files = {"pypi.asset": (package_file.name, f, "application/octet-stream")}
                resp = self.session.post(url, files=files, timeout=30)
        except Exception as e:
            log.error(f"Components API upload exception: {e}")
            return False

        if resp.status_code in (200, 201, 204):
            log.info("Fallback upload succeeded")
            return True
        log.error(f"Fallback upload failed ({resp.status_code}): {resp.text[:300]}")
        return False

    def _upload_docker(self, repo_name: str, package_file: Path) -> bool:
        """Push a Docker image to a Nexus Docker hosted repo via docker tag + push."""
        # Resolve the Nexus Docker registry port for this repo
        port_map = {
            self.config.docker_trusted_repo: self.config.docker_trusted_port,
            self.config.docker_quarantine_repo: self.config.docker_quarantine_port,
            self.config.docker_group_repo: self.config.docker_group_port,
        }
        port = port_map.get(repo_name)
        if not port:
            log.warning(f"No Docker port configured for repo '{repo_name}', skipping push")
            return False

        # Extract the original image:tag from the tarball filename (e.g. nginx-1.25.tar)
        stem = package_file.stem  # "nginx-1.25" or "grafana_grafana-10.4.1"
        # Reconstruct image:tag — the tarball was saved by _download_docker
        # Format: {safe_name}-{tag}.tar where safe_name = image.replace("/","_").replace(":","_")
        # We need the original image reference, so read it from the tarball
        try:
            import json as _json
            import tarfile
            with tarfile.open(package_file, "r:") as tf:
                manifest = _json.loads(tf.extractfile("manifest.json").read())
                repo_tags = manifest[0].get("RepoTags", [])
                if repo_tags:
                    original_ref = repo_tags[0]
                else:
                    log.error("No RepoTags in Docker tarball manifest")
                    return False
        except Exception as e:
            log.error(f"Failed to read Docker tarball manifest: {e}")
            return False

        # Get Nexus host (use hostname from base_url)
        nexus_host = urlparse(self.base).hostname
        target_ref = f"{nexus_host}:{port}/{original_ref}"

        log.info(f"Tagging {original_ref} → {target_ref}")
        tag_cmd = ["docker", "tag", original_ref, target_ref]
        try:
            result = subprocess.run(tag_cmd, capture_output=True, text=True, timeout=30)
        except Exception as e:
            log.error(f"docker tag exception: {type(e).__name__}: {e}")
            return False
        if result.returncode != 0:
            log.error(f"docker tag failed: {result.stderr[:300]}")
            return False

        log.info(f"Pushing {target_ref}")
        push_cmd = ["docker", "push", target_ref]
        try:
            result = subprocess.run(push_cmd, capture_output=True, text=True, timeout=600)
        except Exception as e:
            log.error(f"docker push exception: {type(e).__name__}: {e}")
            return False
        if result.returncode != 0:
            log.error(f"docker push failed: {result.stderr[:300]}")
            return False

        log.info(f"Pushed {original_ref} to {repo_name} (port {port})")
        return True

    def _upload_raw(self, repo_name: str, package_file: Path) -> bool:
        """Upload non-PyPI artifacts via the Nexus components API."""
        url = f"{self.base}/service/rest/v1/components?repository={repo_name}"
        try:
            with open(package_file, "rb") as f:
                files = {"raw.asset1": (package_file.name, f, "application/octet-stream")}
                data = {
                    "raw.directory": "/",
                    "raw.asset1.filename": package_file.name,
                }
                resp = self.session.post(url, files=files, data=data, timeout=60)
        except Exception as e:
            log.error(f"Raw upload exception: {e}")
            return False

        if resp.status_code in (200, 201, 204):
            log.info(f"Uploaded {package_file.name} to {repo_name}")
            return True
        log.error(f"Raw upload failed ({resp.status_code}): {resp.text[:300]}")
        return False

    # -- search ---------------------------------------------------------------

    def check_package_exists(self, repo_name: str, package: str, version: str) -> bool:
        url = f"{self.base}/service/rest/v1/search"
        params = {"repository": repo_name, "name": package, "version": version}
        try:
            resp = self.session.get(url, params=params, timeout=10)
        except Exception as e:
            log.error(f"Nexus search error: {e}")
            return False
        if resp.status_code == 200:
            return len(resp.json().get("items", [])) > 0
        return False

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def _parse_package_filename(filename: str) -> Tuple[str, str]:
        basename = filename
        for ext in [".whl", ".tar.gz", ".tar.bz2", ".zip", ".tgz"]:
            if basename.endswith(ext):
                basename = basename[: -len(ext)]
                break
        parts = basename.split("-")
        if len(parts) >= 2:
            return parts[0], parts[1]
        return basename, "unknown"
