#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = (
    "README.md",
    "PROJECT-SPECIFICATIONS.md",
    "PROJECT-RECORD.md",
    "FEATURES.md",
    "IMPLEMENTED-FEATURES.md",
    "PLANNED-FEATURES.md",
    "BENEFITS.md",
    "COMPETITIVE-OBJECTIVES.md",
    "BRANDING.md",
    "USER-MANUAL.md",
    "CHANGELOGS.md",
    "ARCHITECTURE.md",
    "SECURITY.md",
    "PRIVACY.md",
    "PLATFORM-INTEGRATIONS.md",
    ".gitignore",
    ".editorconfig",
    "goreecloud.platform.yaml",
    "go.mod",
    "cmd/goreecloud-identity/main.go",
    "internal/app/server.go",
    "internal/app/server_test.go",
    "internal/config/config.go",
    "internal/config/config_test.go",
    "internal/registration/policy.go",
    "internal/registration/policy_test.go",
    "internal/account/lifecycle.go",
    "internal/account/lifecycle_test.go",
    ".github/workflows/ci.yml",
    ".github/workflows/vulnerability.yml",
    ".github/workflows/repository-governance.yml",
    "scripts/validate_repository_governance.py",
)

SYSTEMS = (
    "GoreeCloud Manager",
    "Privacy Shield",
    "Wardveil Security",
    "Everkeep",
    "Glaze UI",
    "GoreeCloud Mesh",
    "GoreeCloud Identity",
    "GoreeCloud Policy",
    "GoreeCloud Observability",
)

def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)

def main() -> int:
    errors = 0

    for relative in REQUIRED:
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            fail(f"required repository file is missing or invalid: {relative}")
            errors += 1

    if (ROOT / "FEATURE-ROADMAP.md").exists():
        fail("retired FEATURE-ROADMAP.md must remain absent")
        errors += 1

    integrations = (ROOT / "PLATFORM-INTEGRATIONS.md").read_text(encoding="utf-8")
    for system in SYSTEMS:
        if system not in integrations:
            fail(f"PLATFORM-INTEGRATIONS.md is missing {system}")
            errors += 1

    policy = (ROOT / "internal/registration/policy.go").read_text(encoding="utf-8")
    for marker in (
        "PublicRegistrationEnabled bool",
        "case MethodAdministrator:",
        "case MethodInvitation:",
        "case MethodPublic:",
        "default:",
        "return false",
    ):
        if marker not in policy:
            fail(f"registration policy is missing fail-closed marker: {marker!r}")
            errors += 1

    tests = (ROOT / "internal/registration/policy_test.go").read_text(encoding="utf-8")
    for marker in (
        "TestPolicyDefaultsFailClosedForPublicRegistration",
        "TestPolicyRejectsUnknownMethod",
    ):
        if marker not in tests:
            fail(f"registration policy tests are missing: {marker}")
            errors += 1


    lifecycle = (ROOT / "internal/account/lifecycle.go").read_text(encoding="utf-8")
    for marker in (
        "StateActive",
        "StateDeactivated",
        "StateDeleted",
        "OperationPermanentDelete",
        "PermanentDeletionConfirmed bool",
        "ErrPermanentDeletionConfirmation",
        "ErrDeletedAccountTerminal",
    ):
        if marker not in lifecycle:
            fail(f"account lifecycle is missing required marker: {marker!r}")
            errors += 1

    lifecycle_tests = (ROOT / "internal/account/lifecycle_test.go").read_text(encoding="utf-8")
    for marker in (
        "TestDeactivateAndReactivateAreReversible",
        "TestPermanentDeleteRequiresExplicitConfirmation",
        "TestDeletedAccountIsTerminal",
        "TestUnknownStateAndOperationFailClosed",
    ):
        if marker not in lifecycle_tests:
            fail(f"account lifecycle tests are missing: {marker}")
            errors += 1

    ignored = {
        line.strip()
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    }
    for pattern in (".env", ".env.*", "secrets/", "*.key", "*.pem"):
        if pattern not in ignored:
            fail(f".gitignore is missing sensitive-file pattern: {pattern}")
            errors += 1

    if errors:
        print(f"Identity repository governance validation failed with {errors} error(s).", file=sys.stderr)
        return 1

    print("Identity repository governance validation passed.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
