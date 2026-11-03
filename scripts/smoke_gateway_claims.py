"""CI-only verification that REAL Keycloak issues Gateway-required OAuth claims.

One disposable public PKCE client and randomly credentialed synthetic user.
Never prints an access token, ID token, authorization code, callback URI,
credentials or user identifier; never contacts production identity services.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

import jwt

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from goreecloud_identity.oidc import (
    ClientConfig, StrictTransport, begin_authorization, parse_callback,
    validate_id_token, validate_metadata,
)
from goreecloud_identity.tokens import verify_access_token, VerificationError
from prepare_ci_login_fixture import (
    assert_ci_environment, CLIENT_ID, CALLBACK_URI, SECRET_FILE,
)
from smoke_login import authorize_browser, ISSUER


def check_gateway_claims(payload: dict, client_id: str) -> None:
    if not isinstance(payload, dict):
        raise ValueError("missing verified Keycloak claims")
    audience = payload.get("aud")
    valid_audiences = [audience] if isinstance(audience, str) else audience
    if (
        not isinstance(valid_audiences, list)
        or "goreecloud-gateway-console" not in valid_audiences
        or payload.get("typ") != "Bearer"
        or payload.get("azp") != client_id
        or payload.get("goreecloud_tenant") != "family"
        or "gateway:read" not in payload.get("scope", "").split()
        or "gateway-reader" not in payload.get("realm_access", {}).get("roles", [])
    ):
        raise ValueError("Keycloak access token is missing Gateway's required trust claims")


def main() -> None:
    assert_ci_environment()
    if not SECRET_FILE.is_file():
        raise RuntimeError("CI synthetic identity fixture missing")
    credentials = json.loads(SECRET_FILE.read_text(encoding="utf-8"))
    if credentials.get("client_id") != CLIENT_ID:
        raise ValueError("untrusted test client")

    config = ClientConfig(ISSUER, CLIENT_ID, CALLBACK_URI, allow_local_dev=True)
    transport = StrictTransport(config)
    meta = validate_metadata(transport.discovery(), config)
    keys = transport.jwks()
    auth_url, flow = begin_authorization(config, meta)
    callback = authorize_browser(
        auth_url, credentials["username"], credentials["password"]
    )
    state, code = parse_callback(callback, config)
    flow.consume(state)
    tokens = transport.exchange(meta, code, flow.verifier)
    if str(tokens.get("token_type", "")).lower() != "bearer":
        raise ValueError("token endpoint returned unexpected token class")
    access_token, id_token = tokens.get("access_token"), tokens.get("id_token")
    identity = validate_id_token(id_token, access_token, flow.nonce, config, keys)
    verified = verify_access_token(
        access_token, issuer=ISSUER,
        audience="goreecloud-gateway-console",
        authorized_party=CLIENT_ID, tenant_id="family", jwks=keys,
        required_scopes=["gateway:read"], max_lifetime_seconds=3600,
    )
    if identity.sub != verified.subject.subject_id or (
        "gateway-reader" not in verified.subject.roles
    ):
        raise ValueError("synthetic identity lacks expected Gateway role")
    # Only after the same token has passed signature, issuer, audience,
    # client, token-class and scope verification do we inspect the additional
    # signed custom tenant claim. NEVER use unverified claims for access.
    verified_claims = jwt.decode(access_token, options={"verify_signature": False})
    check_gateway_claims(verified_claims, CLIENT_ID)

    try:
        verify_access_token(
            access_token, issuer=ISSUER, audience="another-service",
            authorized_party=CLIENT_ID, tenant_id="family", jwks=keys,
            required_scopes=["gateway:read"],
        )
    except VerificationError:
        pass
    else:
        raise ValueError("access token unexpectedly valid for another resource")

    print("PASS: real disposable Keycloak access token contains verified Gateway audience, client, role, tenant and scope")
    print("NOT TESTED: real Go Gateway process, MFA, token introspection, production session revocation or Android")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Static error category only; never echo tokens, URLs, signed user
        # claims or user/session secrets into public GitHub Actions logs.
        print(f"FAIL: disposable Gateway claim contract ({type(exc).__name__})")
        raise SystemExit(1) from None
