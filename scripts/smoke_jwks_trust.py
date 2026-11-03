"""GitHub CI-only public signing-key trust smoke against disposable Keycloak.

No real users, tokens or private keys. Only the fixed localhost development issuer
may be contacted; the verifier never consults incoming JWT URL fields.
"""
from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from goreecloud_identity.jwks_trust import JWKSUnavailable, PinnedIssuerKeys
from goreecloud_identity.oidc import ClientConfig, StrictTransport
from prepare_ci_login_fixture import assert_ci_environment


def main() -> None:
    assert_ci_environment()
    issuer = "http://localhost:8080/realms/goreecloud"
    config = ClientConfig(
        issuer, "goreecloud-ci-public",
        "http://127.0.0.1:8765/oidc/callback", allow_local_dev=True,
    )
    metadata = StrictTransport(config).jwks()
    candidates = [
        key for key in metadata["keys"]
        if key.get("kty") == "RSA"
        and key.get("use", "sig") == "sig"
        and key.get("alg", "RS256") == "RS256"
    ]
    if not candidates:
        raise JWKSUnavailable("no disposable Keycloak signing key available")
    expected = candidates[0]["kid"]
    provider = PinnedIssuerKeys(issuer, ttl_seconds=60)
    first = provider.for_key(expected)
    second = provider.for_key(expected)
    if first != second or not any(k.get("kid") == expected for k in first["keys"]):
        raise JWKSUnavailable("issuer-pinned cache does not match actual signing key")
    try:
        provider.for_key("some-unknown-ci-key")
    except JWKSUnavailable:
        pass
    else:
        raise JWKSUnavailable("unknown signing key unexpectedly trusted")
    print("PASS: disposable Keycloak issuer-pinned JWKS fetch, cached RS256 key and unknown-key rejection")


if __name__ == "__main__":
    main()
