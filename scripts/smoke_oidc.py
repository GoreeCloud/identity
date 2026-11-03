"""Non-production OIDC discovery/JWKS smoke check against loopback-only Keycloak.

Run only after starting local compose. No login, real users, network probing,
secrets or production infrastructure are involved. Does not validate JWTs.
"""
from __future__ import annotations

import json
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, ProxyHandler, Request

ISSUER = "http://localhost:8080/realms/goreecloud"
DISCOVERY = ISSUER + "/.well-known/openid-configuration"
REQUIRED = {
    "authorization_endpoint": "/protocol/openid-connect/auth",
    "token_endpoint": "/protocol/openid-connect/token",
    "jwks_uri": "/protocol/openid-connect/certs",
}


class BlockRedirects(HTTPRedirectHandler):
    def redirect_request(self, request: Request, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


def is_local_endpoint(url: str, issuer: str = ISSUER) -> bool:
    parsed = urlsplit(url)
    known = urlsplit(issuer)
    try:
        return (
            parsed.scheme == "http"
            and parsed.hostname == known.hostname == "localhost"
            and parsed.port == known.port == 8080
            and parsed.username is None
            and parsed.password is None
            and parsed.query == ""
            and parsed.fragment == ""
            and parsed.path.startswith(known.path + "/protocol/openid-connect/")
        )
    except ValueError:
        return False


def validate_discovery(data: Any, issuer: str = ISSUER) -> str:
    if not isinstance(data, dict) or data.get("issuer") != issuer:
        raise ValueError("unexpected OIDC issuer")
    for key, suffix in REQUIRED.items():
        endpoint = data.get(key)
        if not isinstance(endpoint, str):
            raise ValueError(f"missing endpoint: {key}")
        if endpoint != issuer + suffix or not is_local_endpoint(endpoint, issuer):
            raise ValueError(f"invalid endpoint: {key}")
    if not isinstance(data.get("response_types_supported"), list) or (
        "code" not in data["response_types_supported"]
    ):
        raise ValueError("authorization code flow not advertised")
    return data["jwks_uri"]


def validate_jwks(data: Any) -> None:
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        raise ValueError("invalid JWKS")
    if not data["keys"]:
        raise ValueError("JWKS is empty")
    for key in data["keys"]:
        if not isinstance(key, dict) or key.get("kty") not in ("RSA", "EC", "OKP"):
            raise ValueError("invalid public JWK")
        if any(private in key for private in ("d", "p", "q", "dp", "dq", "qi", "k")):
            raise ValueError("JWKS exposed private key material")


def read_json(url: str) -> Any:
    if url != DISCOVERY and url != ISSUER + REQUIRED["jwks_uri"]:
        raise ValueError("unapproved network address")
    opener = build_opener(ProxyHandler({}), BlockRedirects)
    request = Request(url, headers={"Accept": "application/json"})
    with opener.open(request, timeout=5) as response:
        if response.status != 200:
            raise ValueError("unexpected response status")
        content = response.read(262145)
        if len(content) > 262144:
            raise ValueError("response too large")
        return json.loads(content)


def main() -> int:
    end = time.monotonic() + 240
    last_error = "server unavailable"
    while time.monotonic() < end:
        try:
            jwks_url = validate_discovery(read_json(DISCOVERY))
            validate_jwks(read_json(jwks_url))
            print("PASS: local OIDC discovery issuer/endpoints and public JWKS")
            return 0
        except (HTTPError, URLError, ValueError, OSError, json.JSONDecodeError) as exc:
            last_error = exc.__class__.__name__
            time.sleep(3)
    print(f"FAIL: local OIDC discovery not ready/valid ({last_error})")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
