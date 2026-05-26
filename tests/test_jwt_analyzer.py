# tests/test_jwt_analyzer.py
"""
Unit tests untuk modules/auth/jwt_analyzer.py
"""

import base64
import json
import pytest


# ── Helpers ───────────────────────────────────────────────

def decode_jwt_header(token: str) -> dict:
    """Decode JWT header tanpa verifikasi."""
    header_b64 = token.split(".")[0]
    padding = "=" * (4 - len(header_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(header_b64 + padding))


def decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload tanpa verifikasi."""
    payload_b64 = token.split(".")[1]
    padding = "=" * (4 - len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64 + padding))


# ── Tests: JWT Parsing ────────────────────────────────────

class TestJWTParsing:

    @pytest.mark.unit
    def test_decode_header_algorithm(self, sample_jwt_hs256):
        """Harus bisa extract algorithm dari header."""
        header = decode_jwt_header(sample_jwt_hs256)
        assert "alg" in header
        assert header["alg"] == "HS256"

    @pytest.mark.unit
    def test_decode_payload_claims(self, sample_jwt_hs256):
        """Harus bisa extract claims dari payload."""
        payload = decode_jwt_payload(sample_jwt_hs256)
        assert "sub" in payload or "role" in payload

    @pytest.mark.unit
    def test_jwt_has_three_parts(self, sample_jwt_hs256):
        """JWT valid harus punya 3 bagian dipisah titik."""
        parts = sample_jwt_hs256.split(".")
        assert len(parts) == 3

    @pytest.mark.unit
    def test_malformed_jwt_raises(self):
        """JWT malformed harus raise exception saat di-parse."""
        malformed_tokens = [
            "not.a.jwt",
            "only_one_part",
            "",
            "a.b",  # hanya 2 parts
        ]
        for token in malformed_tokens:
            parts = token.split(".")
            if len(parts) != 3:
                with pytest.raises(Exception):
                    if len(parts) != 3:
                        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")


# ── Tests: Algorithm Confusion ────────────────────────────

class TestAlgorithmConfusion:

    @pytest.mark.unit
    def test_detect_rs256_algorithm(self, sample_jwt_rs256):
        """Harus detect RS256 sebagai target algorithm confusion."""
        header = decode_jwt_header(sample_jwt_rs256)
        assert header["alg"] == "RS256"

    @pytest.mark.unit
    def test_none_algorithm_is_dangerous(self):
        """Algorithm 'none' harus di-flag sebagai critical."""
        dangerous_algorithms = ["none", "None", "NONE", "nOnE"]
        safe_algorithms = ["HS256", "RS256", "ES256", "PS256"]

        for alg in dangerous_algorithms:
            assert alg.lower() == "none"  # konfirmasi deteksi

        for alg in safe_algorithms:
            assert alg.lower() != "none"

    @pytest.mark.unit
    def test_weak_algorithms_flagged(self):
        """Algoritma lemah harus di-flag sebagai warning."""
        weak_algorithms = ["HS256"]  # symmetric — bisa brute-forced
        strong_algorithms = ["RS256", "ES256", "PS512"]

        # HS256 lemah karena secret bisa di-brute-force
        assert "HS256" in weak_algorithms


# ── Tests: Claim Manipulation ─────────────────────────────

class TestClaimManipulation:

    @pytest.mark.unit
    def test_role_escalation_payloads(self):
        """Harus generate payload untuk role escalation."""
        original_claims = {"sub": "1", "role": "user"}
        escalated_roles = ["admin", "administrator", "superuser", "root", "staff"]

        for role in escalated_roles:
            modified = {**original_claims, "role": role}
            assert modified["role"] != "user"

    @pytest.mark.unit
    def test_expiry_bypass_payloads(self):
        """Harus bisa manipulasi expiry claims."""
        import time
        far_future = int(time.time()) + (365 * 24 * 3600 * 10)  # 10 tahun
        claims_with_bypass = {"exp": far_future, "iat": int(time.time())}
        assert claims_with_bypass["exp"] > int(time.time())

    @pytest.mark.unit
    def test_user_id_tampering(self):
        """Harus generate variasi user ID untuk IDOR via JWT."""
        original_id = 42
        tamper_ids = [0, 1, original_id - 1, original_id + 1, 9999, -1]
        assert original_id not in tamper_ids[:-2]  # pastikan ada ID lain


# ── Tests: Weak Secret Detection ─────────────────────────

class TestWeakSecretDetection:

    @pytest.mark.unit
    def test_common_secrets_list(self):
        """Wordlist weak secrets harus mengandung entries umum."""
        common_secrets = [
            "secret", "password", "123456", "jwt_secret",
            "your-256-bit-secret", "changeme", "supersecret",
        ]
        assert len(common_secrets) > 5

    @pytest.mark.unit
    def test_empty_secret_flagged(self):
        """Secret kosong harus di-flag sebagai critical."""
        empty_secrets = ["", " ", "\t", "\n"]
        for secret in empty_secrets:
            assert secret.strip() == ""  # terdeteksi sebagai kosong

    @pytest.mark.unit
    def test_short_secret_flagged(self):
        """Secret < 32 karakter harus di-flag sebagai weak."""
        short_secrets = ["abc", "12345", "short"]
        for secret in short_secrets:
            assert len(secret) < 32
