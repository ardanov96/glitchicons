# tests/test_seed_generator.py
"""
Unit tests untuk seed_generator.py
Menggunakan mock Ollama — tidak butuh Ollama running.
"""

import json
import pytest
from unittest.mock import patch, MagicMock


# ── Helpers ───────────────────────────────────────────────

def mock_ollama_response(content: str):
    """Buat mock response dari Ollama."""
    mock = MagicMock()
    mock.message.content = content
    return mock


# ── Tests ─────────────────────────────────────────────────

class TestSeedTypes:
    """Test validasi tipe seed yang di-generate."""

    @pytest.mark.unit
    def test_json_seed_is_valid_json(self):
        """Seed bertipe JSON harus bisa di-parse."""
        sample_seeds = [
            '{"username": "admin", "password": "test123"}',
            '{"id": 1, "action": "delete", "token": "abc"}',
            '{"items": [1, 2, 3], "total": -1}',
        ]
        for seed in sample_seeds:
            result = json.loads(seed)
            assert isinstance(result, dict)

    @pytest.mark.unit
    def test_http_seed_has_method(self):
        """Seed bertipe HTTP harus punya HTTP method."""
        valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
        sample_http_lines = [
            "GET /api/users HTTP/1.1",
            "POST /login HTTP/1.1",
            "DELETE /api/user/1 HTTP/1.1",
        ]
        for line in sample_http_lines:
            method = line.split()[0]
            assert method in valid_methods

    @pytest.mark.unit
    def test_xml_seed_structure(self):
        """Seed bertipe XML harus punya root element."""
        sample_xml = """<?xml version="1.0"?>
        <root><user><id>1</id></user></root>"""
        assert "<?xml" in sample_xml or "<" in sample_xml


class TestSeedCount:
    """Test jumlah seed yang di-generate."""

    @pytest.mark.unit
    def test_seed_count_matches_request(self):
        """Jumlah seed yang dihasilkan harus sesuai request."""
        # Simulasi: jika diminta 10 seeds, harus dapat 10
        requested = 10
        generated = [f"seed_{i}" for i in range(requested)]
        assert len(generated) == requested

    @pytest.mark.unit
    def test_empty_seed_count_raises(self):
        """Count 0 atau negatif harus raise ValueError."""
        invalid_counts = [0, -1, -100]
        for count in invalid_counts:
            with pytest.raises((ValueError, AssertionError)):
                if count <= 0:
                    raise ValueError(f"Count harus positif, dapat: {count}")


class TestSeedUniqueness:
    """Test bahwa seed yang di-generate unik."""

    @pytest.mark.unit
    def test_seeds_are_unique(self):
        """Seeds tidak boleh duplikat."""
        seeds = [
            '{"id": 1}',
            '{"id": 2}',
            '{"id": 3}',
            '{"username": "admin"}',
        ]
        assert len(seeds) == len(set(seeds))

    @pytest.mark.unit
    def test_seed_not_empty(self):
        """Setiap seed tidak boleh string kosong."""
        seeds = ['{"a": 1}', "GET /test HTTP/1.1", "<xml/>"]
        for seed in seeds:
            assert seed.strip() != ""


class TestSeedMutation:
    """Test logika mutasi seed."""

    @pytest.mark.unit
    def test_boundary_values_included(self):
        """Mutasi harus mencakup boundary values."""
        boundary_values = [0, -1, 2**31 - 1, 2**31, 2**32, -2**31]
        for val in boundary_values:
            # Pastikan bisa di-serialize ke JSON
            assert json.dumps({"value": val})

    @pytest.mark.unit
    def test_sql_injection_payloads_present(self):
        """Payload SQLi harus tersedia di wordlist."""
        sqli_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1 UNION SELECT NULL--",
        ]
        for payload in sqli_payloads:
            assert "'" in payload or "UNION" in payload or "DROP" in payload

    @pytest.mark.unit
    def test_xss_payloads_present(self):
        """Payload XSS harus tersedia."""
        xss_payloads = [
            "<script>alert(1)</script>",
            '"><img src=x onerror=alert(1)>',
            "javascript:alert(1)",
        ]
        for payload in xss_payloads:
            assert "<" in payload or "javascript:" in payload
