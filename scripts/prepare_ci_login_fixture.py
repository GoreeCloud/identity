"""Generate synthetic OIDC client/user only in disposable GoreeCloud Identity CI.

NEVER run against live services or reuse real accounts. The fixture temporarily
modifies the checked-out realm import file before container startup. Generated
passwords are not displayed, uploaded, tracked, or stored outside the runner.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets

from smoke_backup_restore import assert_ci_environment, assert_isolated_compose, docker

ROOT = Path(__file__).resolve().parents[1]
REALM_FILE = ROOT / "realm" / "goreecloud-realm.json"
SECRET_FILE = Path("/tmp/goreecloud-identity-ci-login.json")
CLIENT_ID = "goreecloud-ci-public"
CALLBACK_URI = "http://127.0.0.1:8765/oidc/callback"


def build_fixture(base: dict, username: str, password: str) -> dict:
    if (not isinstance(base, dict) or base.get("realm") != "goreecloud"
            or base.get("clients") != [] or base.get("users") != []
            or not base.get("enabled") or base.get("registrationAllowed") is not False):
        raise ValueError("refusing to modify a non-pristine development realm")
    if not username.startswith("gc-ci-") or len(password) < 32:
        raise ValueError("test-only credentials required")
    data = dict(base)
    data["clients"] = [{
        "clientId": CLIENT_ID,
        "name": "GoreeCloud CI disposable public OIDC client",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": True,
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "redirectUris": [CALLBACK_URI],
        "webOrigins": [],
        "attributes": {"pkce.code.challenge.method": "S256"},
    }]
    data["users"] = [{
        "username": username,
        "enabled": True,
        "email": "synthetic-ci-login@example.test",
        "emailVerified": True,
        "firstName": "Synthetic",
        "lastName": "CI",
        "requiredActions": [],
        "credentials": [{"type": "password", "value": password, "temporary": False}],
    }]
    return data


def main() -> None:
    # Fail closed before any filesystem mutation or Docker interaction.
    assert_ci_environment()
    assert_isolated_compose(json.loads(docker("config", "--format", "json")))
    if SECRET_FILE.exists():
        raise RuntimeError("refusing to overwrite an existing CI secret file")

    original = REALM_FILE.read_text(encoding="utf-8")
    base = json.loads(original)
    username = "gc-ci-" + secrets.token_hex(8)
    password = "Ci9!" + secrets.token_urlsafe(38)
    fixture = build_fixture(base, username, password)
    secret = {"username": username, "password": password, "client_id": CLIENT_ID}

    fd = os.open(SECRET_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(secret, stream)
        REALM_FILE.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")
    except BaseException:
        SECRET_FILE.unlink(missing_ok=True)
        REALM_FILE.write_text(original, encoding="utf-8")
        raise
    print("PASS: generated disposable, password-protected OIDC test fixture (secrets hidden)")


if __name__ == "__main__":
    main()
