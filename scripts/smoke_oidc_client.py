"""Read-only smoke for the new OIDC client against disposable local Keycloak.

Does not register a client, authenticate a user or exchange a code.
"""
from pathlib import Path
import sys
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from goreecloud_identity.oidc import (
    ClientConfig, StrictTransport, begin_authorization, validate_metadata
)


def main():
    config = ClientConfig(
        "http://localhost:8080/realms/goreecloud",
        "unregistered-ci-smoke-client",
        "http://127.0.0.1:8765/oidc/callback",
        allow_local_dev=True,
    )
    transport = StrictTransport(config)
    metadata = validate_metadata(transport.discovery(), config)
    jwks = transport.jwks()
    authorization_url, flow = begin_authorization(config, metadata)
    parameters = parse_qs(urlsplit(authorization_url).query)
    assert parameters["code_challenge_method"] == ["S256"]
    assert parameters["state"] == [flow.state]
    assert parameters["nonce"] == [flow.nonce]
    assert jwks["keys"]
    print("PASS: pinned OIDC discovery, public JWKS and S256 PKCE initiation")
    print("Not verified: browser login, live code exchange, sessions or Gateway SSO")


if __name__ == "__main__":
    main()
