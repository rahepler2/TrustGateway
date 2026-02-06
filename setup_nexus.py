#!/usr/bin/env python3
"""
Nexus Trust Gateway — Automated Setup Script
=============================================
Creates all repositories, roles, users, and permissions needed for
the Trust Gateway across all supported ecosystems:

    PyPI, npm, Docker, Maven, NuGet

Handles the full first-boot flow:
  1. Read the initial admin password from nexus-data/admin.password
  2. Change the admin password to your chosen password
  3. Create all repos, roles, users, and security settings

Usage:
    # First boot — reads initial password, changes it, sets everything up
    python setup_nexus.py --admin-pass <new-admin-password>

    # From inside docker compose network
    docker compose run --rm nexus-setup

    # Dry run
    python setup_nexus.py --admin-pass <pw> --dry-run

Environment (alternative to CLI flags):
    NEXUS_URL            default: http://localhost:8081
    NEXUS_ADMIN_PASS     the password you want for the admin account
    NEXUS_INITIAL_PASS   override auto-detection of initial password
    GATEWAY_SVC_PASS     password for trust-gateway-svc account
    DEVELOPER_PASS       password for dev-user account
"""

import argparse
import json
import os
import sys
import time

import requests
from requests.auth import HTTPBasicAuth


# =============================================================================
# Ecosystem definitions — the single source of truth
# =============================================================================

ECOSYSTEMS = {
    "pypi": {
        "format": "pypi",
        "upstream": "pypi-upstream",
        "trusted": "pypi-trusted",
        "quarantine": "pypi-quarantine",
        "group": "pypi-group",
        "remote_url": "https://pypi.org",
        "ports": {},
    },
    "npm": {
        "format": "npm",
        "upstream": "npm-upstream",
        "trusted": "npm-trusted",
        "quarantine": "npm-quarantine",
        "group": "npm-group",
        "remote_url": "https://registry.npmjs.org",
        "ports": {},
    },
    "docker": {
        "format": "docker",
        "upstream": "docker-upstream",
        "trusted": "docker-trusted",
        "quarantine": "docker-quarantine",
        "group": "docker-group",
        "remote_url": "https://registry-1.docker.io",
        "ports": {
            "group": 9443,
            "trusted": 9444,
            "upstream": 9445,
            "quarantine": 9446,
        },
    },
    "maven": {
        "format": "maven2",                 # privilege format
        "api_format": "maven",              # REST API path
        "upstream": "maven-upstream",
        "trusted": "maven-trusted",
        "quarantine": "maven-quarantine",
        "group": "maven-group",
        "remote_url": "https://repo1.maven.org/maven2/",
        "ports": {},
    },
    "nuget": {
        "format": "nuget",
        "upstream": "nuget-upstream",
        "trusted": "nuget-trusted",
        "quarantine": "nuget-quarantine",
        "group": "nuget-group",
        "remote_url": "https://api.nuget.org/v3/index.json",
        "ports": {},
    },
}

# Paths to check for the Nexus initial admin password file.
# Inside the nexus-setup container it's at /nexus-data/admin.password.
# From the host it might be in a docker volume or local path.
INITIAL_PASSWORD_PATHS = [
    "/nexus-data/admin.password",
    "./nexus-data/admin.password",
]


# =============================================================================
# Nexus REST API Client
# =============================================================================

class NexusSetup:
    """Automates Nexus 3 setup via the REST API."""

    def __init__(self, base_url, username, password, dry_run=False):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.dry_run = dry_run
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.headers.update({"Content-Type": "application/json"})

    def _api(self, method, path, **kwargs):
        url = f"{self.base_url}/service/rest/{path}"
        return self.session.request(method, url, **kwargs)

    def _set_auth(self, username, password):
        self.session.auth = HTTPBasicAuth(username, password)

    # -------------------------------------------------------------------------
    # Initial admin password handling
    # -------------------------------------------------------------------------

    def try_change_admin_password(self, new_password, initial_password=None):
        """
        Handle the Nexus first-boot admin password flow.

        On first startup Nexus generates a random password and writes it to
        /nexus-data/admin.password. The admin must change it before the
        instance is usable.

        Flow:
          1. Try authenticating with new_password (already changed?)
          2. If that fails, try initial_password or read from admin.password file
          3. Change the password via the REST API
          4. Re-authenticate with the new password
        """
        print("Checking admin password state...")

        # Already using the desired password?
        resp = self._api("GET", "v1/status/check")
        if resp.status_code == 200:
            # Verify we're actually authenticated (not just anonymous)
            auth_check = self._api("GET", "v1/security/users")
            if auth_check.status_code == 200:
                print("  OK    Admin password already set to desired value")
                return True

        # Need to find the initial password
        init_pass = initial_password
        if not init_pass:
            for path in INITIAL_PASSWORD_PATHS:
                try:
                    with open(path) as f:
                        init_pass = f.read().strip()
                    print(f"  OK    Read initial password from {path}")
                    break
                except (FileNotFoundError, PermissionError):
                    continue

        if not init_pass:
            print("  FAIL  Cannot find initial admin password.")
            print("        Provide --initial-pass or mount nexus-data volume.")
            return False

        # Authenticate with initial password
        self._set_auth(self.username, init_pass)
        resp = self._api("GET", "v1/security/users")
        if resp.status_code != 200:
            print(f"  FAIL  Initial password rejected (HTTP {resp.status_code})")
            return False
        print("  OK    Authenticated with initial password")

        if self.dry_run:
            print("  DRY   Would change admin password")
            self._set_auth(self.username, new_password)
            return True

        # Change admin password via API
        resp = self._api(
            "PUT", f"v1/security/users/{self.username}/change-password",
            data=new_password,
            headers={"Content-Type": "text/plain"},
        )
        if resp.status_code in (200, 204):
            print("  OK    Admin password changed")
            self._set_auth(self.username, new_password)
            return True

        print(f"  FAIL  Password change failed (HTTP {resp.status_code}): {resp.text[:200]}")
        return False

    # -------------------------------------------------------------------------
    # Connection check
    # -------------------------------------------------------------------------

    def check_connection(self):
        print("Checking Nexus connection...")
        try:
            resp = self._api("GET", "v1/status")
        except requests.ConnectionError:
            print(f"  FAIL  Cannot reach Nexus at {self.base_url}")
            return False
        if resp.status_code != 200:
            print(f"  FAIL  Nexus returned HTTP {resp.status_code}")
            return False
        print(f"  OK    Nexus reachable at {self.base_url}")

        resp = self._api("GET", "v1/security/users")
        if resp.status_code == 200:
            print(f"  OK    Authenticated")
            return True
        print(f"  FAIL  Authentication failed (HTTP {resp.status_code})")
        return False

    # -------------------------------------------------------------------------
    # Repository creation — generic per format
    # -------------------------------------------------------------------------

    def _repo_exists(self, name):
        resp = self._api("GET", f"v1/repositories/{name}")
        return resp.status_code == 200

    def _api_fmt(self, eco):
        """API path format — differs from privilege format for Maven."""
        return eco.get("api_format", eco["format"])

    def create_proxy_repo(self, eco):
        fmt = eco["format"]
        api_fmt = self._api_fmt(eco)
        name = eco["upstream"]
        remote = eco["remote_url"]
        port = eco["ports"].get("upstream")

        print(f"  Creating {api_fmt} proxy: {name}  ->  {remote}")
        if self.dry_run:
            return True
        if self._repo_exists(name):
            print(f"    SKIP  already exists")
            return True

        payload = {
            "name": name,
            "online": True,
            "storage": {
                "blobStoreName": "default",
                "strictContentTypeValidation": True,
            },
            "proxy": {
                "remoteUrl": remote,
                "contentMaxAge": 1440,
                "metadataMaxAge": 1440,
            },
            "negativeCache": {"enabled": True, "timeToLive": 1440},
            "httpClient": {"blocked": False, "autoBlock": True},
        }

        if fmt == "docker":
            payload["docker"] = {"v1Enabled": False, "forceBasicAuth": True}
            if port:
                payload["docker"]["httpPort"] = port
            payload["dockerProxy"] = {"indexType": "HUB", "useTrustStoreForIndexAccess": False}

        if fmt == "nuget":
            payload["nugetProxy"] = {"queryCacheItemMaxAge": 3600, "nugetVersion": "V3"}

        if fmt == "maven2":
            payload["maven"] = {"versionPolicy": "MIXED", "layoutPolicy": "PERMISSIVE"}

        resp = self._api("POST", f"v1/repositories/{api_fmt}/proxy", json=payload)
        return self._check_create(resp, name)

    def create_hosted_repo(self, eco, tier):
        fmt = eco["format"]
        api_fmt = self._api_fmt(eco)
        name = eco[tier]
        port = eco["ports"].get(tier)

        print(f"  Creating {api_fmt} hosted: {name}")
        if self.dry_run:
            return True
        if self._repo_exists(name):
            print(f"    SKIP  already exists")
            return True

        payload = {
            "name": name,
            "online": True,
            "storage": {
                "blobStoreName": "default",
                "strictContentTypeValidation": True,
                "writePolicy": "ALLOW",
            },
        }

        if fmt == "docker":
            payload["docker"] = {"v1Enabled": False, "forceBasicAuth": True}
            if port:
                payload["docker"]["httpPort"] = port

        if fmt == "maven2":
            payload["maven"] = {"versionPolicy": "MIXED", "layoutPolicy": "PERMISSIVE"}

        resp = self._api("POST", f"v1/repositories/{api_fmt}/hosted", json=payload)
        return self._check_create(resp, name)

    def create_group_repo(self, eco):
        fmt = eco["format"]
        api_fmt = self._api_fmt(eco)
        name = eco["group"]
        members = [eco["trusted"]]
        port = eco["ports"].get("group")

        print(f"  Creating {api_fmt} group: {name}  members={members}")
        if self.dry_run:
            return True
        if self._repo_exists(name):
            print(f"    SKIP  already exists")
            return True

        payload = {
            "name": name,
            "online": True,
            "storage": {
                "blobStoreName": "default",
                "strictContentTypeValidation": True,
            },
            "group": {"memberNames": members},
        }

        if fmt == "docker":
            payload["docker"] = {"v1Enabled": False, "forceBasicAuth": True}
            if port:
                payload["docker"]["httpPort"] = port

        resp = self._api("POST", f"v1/repositories/{api_fmt}/group", json=payload)
        return self._check_create(resp, name)

    def _check_create(self, resp, name):
        if resp.status_code == 201:
            print(f"    OK    {name}")
            return True
        if resp.status_code == 400 and "already exists" in resp.text.lower():
            print(f"    SKIP  {name} already exists")
            return True
        print(f"    FAIL  {name} (HTTP {resp.status_code}): {resp.text[:200]}")
        return False

    # -------------------------------------------------------------------------
    # Roles
    # -------------------------------------------------------------------------

    def _priv(self, fmt, repo, action):
        return f"nx-repository-view-{fmt}-{repo}-{action}"

    def _gateway_privileges(self):
        privs = []
        for eco in ECOSYSTEMS.values():
            fmt = eco["format"]
            privs.append(self._priv(fmt, eco["upstream"], "read"))
            privs.append(self._priv(fmt, eco["upstream"], "browse"))
            for action in ("read", "browse", "add", "edit"):
                privs.append(self._priv(fmt, eco["trusted"], action))
            for action in ("read", "browse", "add", "edit"):
                privs.append(self._priv(fmt, eco["quarantine"], action))
        privs.extend(["nx-search-read", "nx-component-upload"])
        return privs

    def _developer_privileges(self):
        privs = []
        for eco in ECOSYSTEMS.values():
            fmt = eco["format"]
            privs.append(self._priv(fmt, eco["group"], "read"))
            privs.append(self._priv(fmt, eco["group"], "browse"))
        privs.append("nx-search-read")
        return privs

    def _reviewer_privileges(self):
        privs = []
        for eco in ECOSYSTEMS.values():
            fmt = eco["format"]
            privs.append(self._priv(fmt, eco["quarantine"], "*"))
            for action in ("read", "browse", "add"):
                privs.append(self._priv(fmt, eco["trusted"], action))
        privs.append("nx-search-read")
        return privs

    def create_role(self, role_id, name, description, privileges, roles=None):
        print(f"  Creating role: {role_id} ({len(privileges)} privileges)")
        if self.dry_run:
            return True

        payload = {
            "id": role_id,
            "name": name,
            "description": description,
            "privileges": privileges,
            "roles": roles or [],
        }

        resp = self._api("POST", "v1/security/roles", json=payload)
        if resp.status_code == 200:
            print(f"    OK    {role_id}")
            return True
        if resp.status_code == 400 and "already exists" in resp.text.lower():
            print(f"    EXISTS updating {role_id}...")
            resp = self._api("PUT", f"v1/security/roles/{role_id}", json=payload)
            if resp.status_code in (200, 204):
                print(f"    OK    updated {role_id}")
                return True
        print(f"    FAIL  {role_id} (HTTP {resp.status_code})")
        return False

    # -------------------------------------------------------------------------
    # Users
    # -------------------------------------------------------------------------

    def create_user(self, user_id, first_name, last_name, email, password, roles):
        print(f"  Creating user: {user_id}  roles={roles}")
        if self.dry_run:
            return True

        payload = {
            "userId": user_id,
            "firstName": first_name,
            "lastName": last_name,
            "emailAddress": email,
            "password": password,
            "status": "active",
            "roles": roles,
        }

        resp = self._api("POST", "v1/security/users", json=payload)
        if resp.status_code == 200:
            print(f"    OK    {user_id}")
            return True
        if "already exists" in resp.text.lower() or "duplicate" in resp.text.lower():
            print(f"    SKIP  {user_id} already exists — updating roles...")
            return self._update_user_roles(user_id, roles)
        print(f"    FAIL  {user_id} (HTTP {resp.status_code}): {resp.text[:200]}")
        return False

    def _update_user_roles(self, user_id, roles):
        """Update an existing user's roles."""
        resp = self._api("GET", f"v1/security/users?userId={user_id}")
        if resp.status_code != 200:
            print(f"    FAIL  cannot fetch user {user_id}")
            return False
        users = resp.json()
        if not users:
            print(f"    FAIL  user {user_id} not found")
            return False
        user = users[0]
        user["roles"] = roles
        resp = self._api("PUT", f"v1/security/users/{user_id}", json=user)
        if resp.status_code in (200, 204):
            print(f"    OK    updated roles for {user_id}")
            return True
        print(f"    FAIL  cannot update {user_id} (HTTP {resp.status_code})")
        return False

    # -------------------------------------------------------------------------
    # Security settings
    # -------------------------------------------------------------------------

    def disable_anonymous_access(self):
        print("  Disabling anonymous access...")
        if self.dry_run:
            return True
        payload = {"enabled": False, "userId": "anonymous", "realmName": "NexusAuthorizingRealm"}
        resp = self._api("PUT", "v1/security/anonymous", json=payload)
        if resp.status_code in (200, 204):
            print("    OK    anonymous access disabled")
            return True
        print(f"    FAIL  HTTP {resp.status_code}")
        return False

    def enable_docker_bearer_token_realm(self):
        print("  Enabling Docker Bearer Token realm...")
        if self.dry_run:
            return True
        resp = self._api("GET", "v1/security/realms/active")
        if resp.status_code != 200:
            print(f"    FAIL  cannot read active realms (HTTP {resp.status_code})")
            return False
        realms = resp.json()
        docker_realm = "DockerToken"
        if docker_realm in realms:
            print("    SKIP  already active")
            return True
        realms.append(docker_realm)
        resp = self._api("PUT", "v1/security/realms/active", json=realms)
        if resp.status_code in (200, 204):
            print("    OK    Docker Bearer Token realm activated")
            return True
        print(f"    FAIL  HTTP {resp.status_code}")
        return False

    # -------------------------------------------------------------------------
    # Full setup
    # -------------------------------------------------------------------------

    def run_full_setup(self, admin_pass, svc_password, dev_password,
                       initial_pass=None):
        print("=" * 64)
        print("  NEXUS TRUST GATEWAY - AUTOMATED SETUP")
        print("=" * 64)

        if self.dry_run:
            print("\n  *** DRY RUN — no changes will be made ***\n")

        # -- Step 0: Admin password --
        print(f"\n{'='*64}")
        print("  STEP 0: Admin Password")
        print(f"{'='*64}\n")

        if not self.try_change_admin_password(admin_pass, initial_pass):
            print("\nCannot authenticate to Nexus. Aborting.")
            return False

        # -- Verify connection --
        if not self.dry_run and not self.check_connection():
            print("\nCannot connect to Nexus. Aborting.")
            return False

        # -- Step 1: Repositories --
        print(f"\n{'='*64}")
        print("  STEP 1: Create Repositories")
        print(f"{'='*64}")
        print("""
  For each ecosystem we create four repos:

    {name}-upstream    proxy      mirrors public registry
    {name}-trusted     hosted     vetted packages (promoted here)
    {name}-quarantine  hosted     failed/blocked packages
    {name}-group       group      developer endpoint (trusted only)
""")

        for key, eco in ECOSYSTEMS.items():
            print(f"\n  --- {key.upper()} ({eco['format']}) ---")
            self.create_proxy_repo(eco)
            self.create_hosted_repo(eco, "trusted")
            self.create_hosted_repo(eco, "quarantine")
            self.create_group_repo(eco)

        if not self.dry_run:
            print("\n  Waiting 3s for privilege generation...")
            time.sleep(3)

        # -- Step 2: Security realms --
        print(f"\n{'='*64}")
        print("  STEP 2: Security Realms")
        print(f"{'='*64}\n")

        self.enable_docker_bearer_token_realm()

        # -- Step 3: Roles --
        print(f"\n{'='*64}")
        print("  STEP 3: Create Roles")
        print(f"{'='*64}\n")

        self.create_role(
            "trust-gateway-role",
            "Trust Gateway Service",
            "Service account for the scanning gateway. "
            "Read from all upstream repos, write to all trusted/quarantine repos.",
            self._gateway_privileges(),
        )

        self.create_role(
            "developer-role",
            "Developer (Read-Only)",
            "Developer role: read-only access to all group repos.",
            self._developer_privileges(),
        )

        self.create_role(
            "security-reviewer-role",
            "Security Reviewer",
            "Full quarantine access + promote to trusted. Inherits developer role.",
            self._reviewer_privileges(),
            roles=["developer-role"],
        )

        # -- Step 4: Users --
        print(f"\n{'='*64}")
        print("  STEP 4: Create Service Accounts")
        print(f"{'='*64}\n")

        self.create_user(
            "trust-gateway-svc", "Trust Gateway", "Service Account",
            "trust-gateway@internal.local", svc_password,
            ["trust-gateway-role"],
        )

        self.create_user(
            "dev-user", "Developer", "User",
            "dev@internal.local", dev_password,
            ["developer-role"],
        )

        # -- Step 5: Disable anonymous --
        print(f"\n{'='*64}")
        print("  STEP 5: Security Hardening")
        print(f"{'='*64}\n")

        self.disable_anonymous_access()

        # -- Step 6: Webhook instructions --
        print(f"\n{'='*64}")
        print("  STEP 6: Webhook Configuration (manual)")
        print(f"{'='*64}")
        print(f"""
  Configure in the Nexus UI:
    {self.base_url}/#admin/system/capabilities

  For each upstream proxy repo, create a Webhook: Component capability:

    Repository           Event     URL
    ------------------   -------   -------------------------------------------""")
        for key, eco in ECOSYSTEMS.items():
            print(f"    {eco['upstream']:<20} CREATED   http://gateway:5000/webhook/nexus")
        print("""
  This notifies the gateway whenever a new package is cached
  in any upstream proxy, triggering an automatic scan.
""")

        # -- Summary --
        docker_eco = ECOSYSTEMS["docker"]
        print(f"{'='*64}")
        print("  SETUP COMPLETE")
        print(f"{'='*64}")
        print(f"""
  Repositories ({len(ECOSYSTEMS)} ecosystems x 4 = {len(ECOSYSTEMS)*4} repos):""")
        for key, eco in ECOSYSTEMS.items():
            print(f"    {key:<8} {eco['upstream']}, {eco['trusted']}, {eco['quarantine']}, {eco['group']}")

        print(f"""
  Docker registry ports:
    {docker_eco['ports']['group']}  docker-group    (developer pull)
    {docker_eco['ports']['trusted']}  docker-trusted  (gateway push)
    {docker_eco['ports']['upstream']}  docker-upstream (proxy to Docker Hub)

  Service accounts:
    trust-gateway-svc  ->  trust-gateway-role
    dev-user           ->  developer-role

  Update your .env:
    NEXUS_USER=trust-gateway-svc
    NEXUS_PASS=<svc-password-you-set>

  Developer pip.conf:
    [global]
    index-url = {self.base_url}/repository/pypi-group/simple/

  Developer .npmrc:
    registry={self.base_url}/repository/npm-group/

  Developer Docker:
    docker login localhost:{docker_eco['ports']['group']}
""")
        return True


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Nexus Trust Gateway — create repos, roles, and users for all ecosystems",
    )
    parser.add_argument("--url", default=os.getenv("NEXUS_URL", "http://localhost:8081"),
                        help="Nexus base URL (default: $NEXUS_URL or http://localhost:8081)")
    parser.add_argument("--admin-user", default=os.getenv("NEXUS_ADMIN_USER", "admin"),
                        help="Nexus admin username (default: admin)")
    parser.add_argument("--admin-pass", default=os.getenv("NEXUS_ADMIN_PASS"),
                        help="Desired admin password (or $NEXUS_ADMIN_PASS)")
    parser.add_argument("--initial-pass", default=os.getenv("NEXUS_INITIAL_PASS"),
                        help="Nexus first-boot password (auto-read from admin.password if omitted)")
    parser.add_argument("--svc-pass", default=os.getenv("GATEWAY_SVC_PASS", "ChangeMeGateway!2025"),
                        help="Password for trust-gateway-svc account")
    parser.add_argument("--dev-pass", default=os.getenv("DEVELOPER_PASS", "ChangeMeDeveloper!2025"),
                        help="Password for dev-user account")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview what would be created without making changes")

    args = parser.parse_args()

    if not args.admin_pass:
        print("ERROR: --admin-pass is required (or set $NEXUS_ADMIN_PASS)")
        print("       This is the password you WANT the admin account to have.")
        sys.exit(2)

    setup = NexusSetup(
        base_url=args.url,
        username=args.admin_user,
        password=args.admin_pass,
        dry_run=args.dry_run,
    )

    success = setup.run_full_setup(
        admin_pass=args.admin_pass,
        svc_password=args.svc_pass,
        dev_password=args.dev_pass,
        initial_pass=args.initial_pass,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
