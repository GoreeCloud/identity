"""Verify a disposable PostgreSQL backup and restore ONLY in GoreeCloud GitHub CI.

This script intentionally refuses local, VPS, and production execution. Never
use this as a production backup/restore runbook or general database admin tool.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def assert_ci_environment(env: dict[str, str] | None = None) -> None:
    env = dict(os.environ) if env is None else env
    if not (
        env.get("GITHUB_ACTIONS") == "true"
        and env.get("GITHUB_REPOSITORY") == "GoreeCloud/identity"
        and env.get("CI") == "true"
    ):
        raise RuntimeError("refusing database backup/restore outside GoreeCloud GitHub CI")


def assert_isolated_compose(config: Any) -> None:
    if not isinstance(config, dict):
        raise RuntimeError("missing Compose configuration")
    services = config.get("services")
    if not isinstance(services, dict) or set(services) != {"db", "identity"}:
        raise RuntimeError("unexpected Compose services")
    identity, db = services["identity"], services["db"]
    ports = identity.get("ports")
    if not isinstance(ports, list) or len(ports) != 1 or (
        ports[0].get("host_ip") != "127.0.0.1"
        or str(ports[0].get("published")) != "8080"
    ):
        raise RuntimeError("identity service is not loopback-only")
    if db.get("ports"):
        raise RuntimeError("database is exposed on a host port")
    if identity.get("command") != ["start-dev", "--import-realm"]:
        raise RuntimeError("this is not the disposable development configuration")
    if db.get("environment", {}).get("POSTGRES_DB") != "goreecloud_identity":
        raise RuntimeError("unexpected database name")
    if identity.get("environment", {}).get("KC_HOSTNAME") != "http://localhost:8080":
        raise RuntimeError("unexpected identity hostname")


def docker(*args: str, input_file: Any = None, output_file: Any = None) -> str:
    cmd = ["docker", "compose", *args]
    result = subprocess.run(
        cmd, check=True, stdin=input_file, stdout=output_file or subprocess.PIPE,
        stderr=subprocess.PIPE, cwd=ROOT, timeout=120, text=False,
    )
    return result.stdout.decode("utf-8", errors="replace") if output_file is None else ""


def db(*args: str, input_file: Any = None, output_file: Any = None) -> str:
    return docker("exec", "-T", "db", *args, input_file=input_file, output_file=output_file)


def main() -> int:
    assert_ci_environment()  # must precede ANY Docker call
    config = json.loads(docker("config", "--format", "json"))
    assert_isolated_compose(config)

    database = "gc_restore_smoke_" + secrets.token_hex(8)  # SQL identifier is generated, not user input
    with tempfile.TemporaryDirectory(prefix="gc-identity-backup-") as directory:
        archive = Path(directory) / "identity.dump"
        created = False
        try:
            fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                db("pg_dump", "-U", "identity", "-d", "goreecloud_identity", "--format=custom",
                   "--no-owner", "--no-acl", output_file=stream)
            if archive.stat().st_size < 1024:
                raise RuntimeError("backup archive is unexpectedly small")

            with archive.open("rb") as stream:
                listing = db("pg_restore", "--list", input_file=stream)
            if "TABLE" not in listing:
                raise RuntimeError("backup did not contain tables")

            db("psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "identity", "-d", "postgres",
               "-c", f'CREATE DATABASE "{database}";')
            created = True
            with archive.open("rb") as stream:
                db("pg_restore", "--no-owner", "--no-privileges", "--exit-on-error",
                   "-U", "identity", "-d", database, input_file=stream)
            verified = db("psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1",
                          "-U", "identity", "-d", database,
                          "-c", "SELECT name FROM public.realm WHERE name='goreecloud' LIMIT 1;")
            if verified.strip() != "goreecloud":
                raise RuntimeError("restored database lacks expected GoreeCloud realm")
            print("PASS: disposable PostgreSQL archive, restore and realm data verification")
        finally:
            if created:
                db("psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "identity", "-d", "postgres",
                   "-c", f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE);')
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f"FAIL: disposable backup/restore smoke ({type(exc).__name__})")
        raise SystemExit(1) from None
