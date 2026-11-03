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
    validate_id_token, validate_metadata, _rsa_signing_key,
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


def classify_verified_gateway_claims(claims: dict, client_id: str) -> str:
    """Return ONLY static category names from an independently verified JWT."""
    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience
    roles = claims.get("realm_access")
    roles = roles.get("roles") if isinstance(roles, dict) else None
    scope = claims.get("scope")
    checks = {
        "audience": isinstance(audiences, list) and "goreecloud-gateway-console" in audiences,
        "client": claims.get("azp") == client_id,
        "tenant": claims.get("goreecloud_tenant") == "family",
        "scope": isinstance(scope, str) and "gateway:read" in scope.split(),
        "role": isinstance(roles, list) and "gateway-reader" in roles,
        "type": claims.get("typ") == "Bearer",
    }
    return ",".join(key for key, passes in checks.items() if not passes) or "none"


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
    try:
        verified = verify_access_token(
            access_token, issuer=ISSUER,
            audience="goreecloud-gateway-console",
            authorized_party=CLIENT_ID, tenant_id="family", jwks=keys,
            required_scopes=["gateway:read"], max_lifetime_seconds=3600,
        )
    except VerificationError as error:
        # Only static, audited verification-failure categories are printed.
        # Never include raw JWTs, claims, URLs or provider exception strings.
        categories = {
            "invalid or non-HTTPS issuer": "issuer_configuration",
            "missing trusted identity configuration": "identity_configuration",
            "trusted JWKS is unavailable": "key_source",
            "ambiguous or unknown signing key": "signing_kid",
            "JWT signature or registered claims invalid": "signature_or_audience",
            "ID token or unexpected token type rejected": "token_class",
            "unexpected authorized OAuth client": "oauth_client",
            "signed tenant claim mismatch": "tenant",
            "required API scope missing": "scope",
            "invalid role container": "roles",
            "invalid scope claim": "scope_format",
        }
        print("DIAG: gateway_verifier_reason=" + categories.get(str(error), "other"))
        # This diagnostic may run ONLY after independently verifying the
        # SAME access token's RS256 signature and pinned issuer. Never use
        # decoded diagnostic claims to grant access or expose raw values.
        try:
            signed = jwt.decode(
                access_token, _rsa_signing_key(access_token, keys),
                algorithms=["RS256"], issuer=ISSUER,
                options={"verify_aud": False, "require": ["iss", "sub", "iat", "exp"]},
                leeway=30,
            )
            print("DIAG: verified_gateway_missing=" +
                  classify_verified_gateway_claims(signed, CLIENT_ID))
        except Exception as diagnostic_error:
            # The exception class is selected from a short allowlist only.
            allowed = {
                "OIDCError", "InvalidIssuerError", "InvalidSignatureError",
                "InvalidAudienceError", "MissingRequiredClaimError",
                "ExpiredSignatureError", "ImmatureSignatureError",
                "DecodeError", "InvalidKeyError",
            }
            kind = type(diagnostic_error).__name__
            print("DIAG: verified_gateway_unavailable=" +
                  (kind if kind in allowed else "other"))
        raise
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
