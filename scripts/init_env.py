"""Generate fresh local development secrets; never print or overwrite them."""
from __future__ import annotations

import os
from pathlib import Path
import secrets

ROOT = Path(__file__).resolve().parents[1]


def create_env(path: Path) -> bool:
    if path.exists():
        return False
    body = (
        "# Local development secrets. Never commit, share or expose this file.\n"
        "KC_BOOTSTRAP_ADMIN_USERNAME=admin\n"
        f"KC_BOOTSTRAP_ADMIN_PASSWORD={secrets.token_urlsafe(36)}\n"
        f"POSTGRES_PASSWORD={secrets.token_urlsafe(36)}\n"
    )
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(body)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return True


if __name__ == "__main__":
    destination = ROOT / ".env"
    if create_env(destination):
        print("Generated private development secrets in .env (not displayed).")
    else:
        print("Existing .env preserved; no secrets changed.")
