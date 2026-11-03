"""Offline preflight for development-only GoreeCloud Identity repository."""
from __future__ import annotations

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    try:
        realm = json.loads((root / "realm/goreecloud-realm.json").read_text(encoding="utf-8"))
        if realm.get("realm") != "goreecloud" or not realm.get("enabled"):
            errors.append("realm must be enabled and named goreecloud")
        if realm.get("loginTheme") != "goreecloud":
            errors.append("GoreeCloud login theme must be selected")
        if realm.get("registrationAllowed") is not False:
            errors.append("public self-registration must default to disabled")
        if realm.get("bruteForceProtected") is not True:
            errors.append("brute-force protection must be enabled")
        if realm.get("users") or realm.get("clients"):
            errors.append("initial realm must not contain accounts or OAuth clients")
    except (OSError, ValueError, TypeError):
        errors.append("invalid or unreadable realm configuration")

    try:
        compose = (root / "compose.yaml").read_text(encoding="utf-8")
        checks = ('127.0.0.1:8080:8080', 'start-dev', 'POSTGRES_PASSWORD:?', 'KC_BOOTSTRAP_ADMIN_PASSWORD:?')
        if any(mark not in compose for mark in checks):
            errors.append("development compose missing required isolation or secret parameters")
        if "ports:\n      - \"0.0.0.0" in compose or ":latest" in compose:
            errors.append("public listener or unpinned latest image detected")
        if "postgres:" not in compose or "keycloak/keycloak:" not in compose:
            errors.append("expected database and identity engine not declared")
    except OSError:
        errors.append("compose.yaml missing")

    env = root / ".env"
    if env.exists():
        if os.name == "posix" and (env.stat().st_mode & 0o077):
            errors.append(".env permissions must not permit group or other access")
        values: dict[str, str] = {}
        for line in env.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                values[key] = value
        for key in ("POSTGRES_PASSWORD", "KC_BOOTSTRAP_ADMIN_PASSWORD"):
            if len(values.get(key, "")) < 32:
                errors.append(f"{key} must contain a generated long secret")
        if values.get("KC_BOOTSTRAP_ADMIN_USERNAME") != "admin":
            errors.append("unexpected development bootstrap username")
    return errors


if __name__ == "__main__":
    failures = check()
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        raise SystemExit(1)
    print("PASS: static configuration preflight (not a runtime security assessment)")
