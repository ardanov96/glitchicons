# tests/conftest.py
"""
Shared pytest fixtures untuk GLITCHICONS test suite.
"""

import json
import pytest
import responses as responses_lib


# ── HTTP Mock Fixtures ────────────────────────────────────

@pytest.fixture
def mock_http():
    """Activate responses mock untuk HTTP calls."""
    with responses_lib.RequestsMock() as rsps:
        yield rsps


@pytest.fixture
def mock_login_endpoint(mock_http):
    """Mock login endpoint dengan lockout simulation."""
    attempts = {"count": 0}

    def login_callback(request):
        attempts["count"] += 1
        body = request.body or ""
        if "password=correct_password" in body:
            return (200, {}, json.dumps({"status": "ok", "token": "abc123"}))
        elif attempts["count"] > 5:
            return (429, {}, json.dumps({"error": "Too many attempts"}))
        else:
            return (401, {}, json.dumps({"error": "Invalid credentials"}))

    mock_http.add_callback(
        responses_lib.POST,
        "https://target.example.com/login",
        callback=login_callback,
        content_type="application/json",
    )
    return mock_http


@pytest.fixture
def mock_api_endpoint(mock_http):
    """Mock REST API endpoint."""
    mock_http.add(
        responses_lib.GET,
        "https://target.example.com/api/user/1",
        json={"id": 1, "name": "Alice", "role": "user"},
        status=200,
    )
    mock_http.add(
        responses_lib.GET,
        "https://target.example.com/api/user/2",
        json={"id": 2, "name": "Admin", "role": "admin"},
        status=200,
    )
    mock_http.add(
        responses_lib.GET,
        "https://target.example.com/api/user/999",
        json={"error": "Not found"},
        status=404,
    )
    return mock_http


# ── Sample Data Fixtures ──────────────────────────────────

@pytest.fixture
def sample_jwt_hs256():
    """JWT signed dengan HS256 dan weak secret."""
    # Token: {"alg":"HS256","typ":"JWT"} / {"sub":"1","role":"user"} / secret="password"
    return (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxIiwicm9sZSI6InVzZXIifQ."
        "HVdm6uHlP7eJjRTFVPVDjAVtAGapLqRGgMjFkOxIqSo"
    )


@pytest.fixture
def sample_jwt_rs256():
    """JWT signed dengan RS256 (algorithm confusion target)."""
    return (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0."
        "signature_placeholder"
    )


@pytest.fixture
def sample_http_response_xss():
    """HTTP response yang reflect input tanpa sanitasi."""
    return """
    <html>
    <body>
        <h1>Search Results for: <script>alert(1)</script></h1>
        <p>No results found.</p>
    </body>
    </html>
    """


@pytest.fixture
def sample_sqli_error_response():
    """HTTP response dengan SQL error message."""
    return """
    <html>
    <body>
        <p>Error: You have an error in your SQL syntax; check the manual that
        corresponds to your MySQL server version for the right syntax to use near
        ''' at line 1</p>
    </body>
    </html>
    """


@pytest.fixture
def target_url():
    return "https://target.example.com"


@pytest.fixture
def sample_crash_output():
    """Contoh output GDB crash untuk triage testing."""
    return """
    Program received signal SIGSEGV, Segmentation fault.
    0x00007ffff7a3b2c1 in __strcpy_sse2_unaligned ()
    #0  0x00007ffff7a3b2c1 in __strcpy_sse2_unaligned ()
    #1  0x0000000000401186 in vulnerable_function (input=0x603260 'A' <repeats 200 times>...)
    #2  0x00000000004011d8 in main (argc=2, argv=0x7fffffffe338)
    """
