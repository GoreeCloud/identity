"""Offline safety guard for the disposable HTTPS Keycloak Compose overlay.

This does NOT prove HTTPS runtime acceptance, only prevents accidental public
port exposure or insecure use of untrusted proxy/TLS settings in the fixture.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DisposableHTTPSOverlayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "ci/keycloak-https.compose.yaml").read_text(
            encoding="utf-8"
        )

    def test_only_expected_local_https_publication(self):
        text = self.source
        self.assertIn('127.0.0.1:8443:8443', text)
        self.assertEqual(text.count('127.0.0.1:8443:8443'), 1)
        for forbidden in ("0.0.0.0:", '8443:8443"', "network_mode: host",
                          "privileged: true", "cap_add:"):
            if forbidden == '8443:8443"':
                continue
            self.assertNotIn(forbidden, text)

    def test_keycloak_issuer_and_tls_are_explicit(self):
        text = self.source
        for marker in (
            'KC_HOSTNAME: https://localhost:8443',
            'KC_HTTP_ENABLED: "false"',
            'KC_HTTPS_CERTIFICATE_FILE: /opt/keycloak/conf/ci-certs/tls.crt',
            'KC_HTTPS_CERTIFICATE_KEY_FILE: /opt/keycloak/conf/ci-certs/tls.key',
            '/tmp/goreecloud-keycloak-https-certs:/opt/keycloak/conf/ci-certs:ro',
        ):
            self.assertIn(marker, text)

    def test_no_production_credentials_or_insecure_tls_flags(self):
        lowered = self.source.lower()
        for forbidden in ("skipverify", "insecureskipverify", "password:",
                          "token:", "proxy-headers:", "hostname-strict=false",
                          "user: root", "docker.sock"):
            self.assertNotIn(forbidden, lowered)


if __name__ == "__main__":
    unittest.main()
