"""
GLITCHICONS ⬡ — JWT Analyzer v1.0
Tests: algorithm confusion, weak secrets, claim manipulation
"""

import json
import base64
import hmac
import hashlib
import sys
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "test",
    "key", "jwt", "token", "changeme", "letmein",
    "qwerty", "abc123", "master", "root", "default"
]

def b64_decode(data):
    """Base64url decode."""
    padding = 4 - len(data) % 4
    data += "=" * padding
    return base64.urlsafe_b64decode(data)

def b64_encode(data):
    """Base64url encode."""
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def decode_jwt(token):
    """Decode JWT without verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None, None, None
        header  = json.loads(b64_decode(parts[0]))
        payload = json.loads(b64_decode(parts[1]))
        return header, payload, parts[2]
    except Exception as e:
        return None, None, None

def test_none_algorithm(token):
    """Test algorithm confusion: RS256 -> none."""
    parts = token.split(".")
    if len(parts) != 3:
        return None

    # Modify header to use alg:none
    header = json.loads(b64_decode(parts[0]))
    original_alg = header.get("alg", "")
    header["alg"] = "none"

    new_header  = b64_encode(json.dumps(header, separators=(",", ":")))
    forged_token = f"{new_header}.{parts[1]}."
    return forged_token, original_alg

def test_weak_secret(token):
    """Brute force weak HMAC secrets."""
    parts = token.split(".")
    if len(parts) != 3:
        return None

    message   = f"{parts[0]}.{parts[1]}".encode()
    signature = b64_decode(parts[2])

    for secret in WEAK_SECRETS:
        for alg_name, alg_func in [
            ("HS256", hashlib.sha256),
            ("HS384", hashlib.sha384),
            ("HS512", hashlib.sha512),
        ]:
            computed = hmac.new(
                secret.encode(), message, alg_func
            ).digest()
            if hmac.compare_digest(computed, signature):
                return secret, alg_name
    return None

def test_claim_manipulation(token):
    """Generate tokens with manipulated claims."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}

    payload = json.loads(b64_decode(parts[1]))
    manipulations = {}

    # Admin escalation
    if "role" in payload:
        admin_payload = payload.copy()
        admin_payload["role"] = "admin"
        new_payload = b64_encode(json.dumps(
            admin_payload, separators=(",", ":")
        ))
        manipulations["role_admin"] = \
            f"{parts[0]}.{new_payload}.{parts[2]}"

    # User ID manipulation
    for id_field in ["user_id", "sub", "id", "uid"]:
        if id_field in payload:
            for test_id in [1, 2, 0, 999, "admin"]:
                manip = payload.copy()
                manip[id_field] = test_id
                new_payload = b64_encode(json.dumps(
                    manip, separators=(",", ":")
                ))
                manipulations[f"{id_field}_{test_id}"] = \
                    f"{parts[0]}.{new_payload}.{parts[2]}"
            break

    # Expiry manipulation
    if "exp" in payload:
        never_expire = payload.copy()
        never_expire["exp"] = 9999999999
        new_payload = b64_encode(json.dumps(
            never_expire, separators=(",", ":")
        ))
        manipulations["never_expire"] = \
            f"{parts[0]}.{new_payload}.{parts[2]}"

    return manipulations

def analyze(token, output_dir=None):
    """Full JWT analysis."""
    console.print(Panel(
        "[bold purple]⬡ GLITCHICONS JWT ANALYZER[/bold purple]",
        border_style="purple"
    ))

    header, payload, sig = decode_jwt(token)
    if not header:
        console.print("[red]Invalid JWT token[/red]")
        return

    # Display decoded token
    console.print("\n[bold]Decoded Header:[/bold]")
    console.print(json.dumps(header, indent=2))
    console.print("\n[bold]Decoded Payload:[/bold]")
    console.print(json.dumps(payload, indent=2))

    findings = []

    # Test 1: Algorithm none
    console.print("\n[bold]→ Testing: Algorithm Confusion[/bold]")
    result = test_none_algorithm(token)
    if result:
        forged, orig_alg = result
        if orig_alg in ["RS256", "RS384", "RS512", "ES256"]:
            console.print(
                f"  [red]⚠ POTENTIAL: alg:{orig_alg} → none[/red]"
            )
            console.print(
                f"  Forged token: {forged[:60]}..."
            )
            findings.append({
                "type"  : "ALG_CONFUSION",
                "detail": f"Original: {orig_alg}, Forged: none",
                "token" : forged
            })
        else:
            console.print(
                f"  [green]OK: {orig_alg} (HMAC-based, none attack N/A)[/green]"
            )

    # Test 2: Weak secret
    console.print("\n[bold]→ Testing: Weak Secret[/bold]")
    alg = header.get("alg", "")
    if alg.startswith("HS"):
        result = test_weak_secret(token)
        if result:
            secret, alg_name = result
            console.print(
                f"  [red]⚠ CRITICAL: Weak secret found: '{secret}' ({alg_name})[/red]"
            )
            findings.append({
                "type"  : "WEAK_SECRET",
                "secret": secret,
                "alg"   : alg_name
            })
        else:
            console.print("  [green]OK: Secret not in common wordlist[/green]")
    else:
        console.print(f"  [dim]Skipped: {alg} is not HMAC-based[/dim]")

    # Test 3: Claim manipulation
    console.print("\n[bold]→ Testing: Claim Manipulation[/bold]")
    manipulations = test_claim_manipulation(token)
    if manipulations:
        console.print(
            f"  Generated [bold]{len(manipulations)}[/bold] "
            f"manipulated tokens:"
        )
        for name, tok in manipulations.items():
            console.print(f"  [yellow]  {name}[/yellow]: {tok[:60]}...")
        findings.append({
            "type"         : "CLAIM_MANIPULATION",
            "tokens_generated": len(manipulations),
            "variants"     : list(manipulations.keys())
        })
    else:
        console.print("  [dim]No manipulable claims found[/dim]")

    # Summary
    console.print(f"\n[bold]⬡ Analysis Complete[/bold]")
    console.print(f"  Findings: [bold {'red' if findings else 'green'}]"
                  f"{len(findings)}[/bold {'red' if findings else 'green'}]")

    # Save report
    if output_dir and findings:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        f    = out / f"jwt_analysis_{ts}.json"
        f.write_text(json.dumps({
            "header"  : header,
            "payload" : payload,
            "findings": findings
        }, indent=2))
        console.print(f"  Report: {f}")

    return findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 jwt_analyzer.py <token> [output_dir]")
        sys.exit(1)
    token      = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None
    analyze(token, output_dir)
