"""
GLITCHICONS ⬡ — Cloud Assets v1.0
Detects: exposed S3, Azure Blob, GCS buckets
"""
import requests, sys
from rich.console import Console
from rich.panel import Panel

console = Console()

def check_s3(domain):
    """Check for exposed S3 buckets."""
    console.print(f"\n[bold]→ S3 Bucket Check[/bold]: {domain}")
    base   = domain.replace("www.", "").replace(".com","")
    names  = [
        base, f"{base}-backup", f"{base}-dev",
        f"{base}-prod", f"{base}-assets",
        f"{base}-media", f"{base}-static",
        f"{base}-uploads", f"{base}-files",
    ]
    found  = []
    for name in names:
        urls = [
            f"https://{name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{name}",
        ]
        for url in urls:
            try:
                r = requests.get(url, timeout=5, verify=False)
                if r.status_code in [200, 403]:
                    status = "PUBLIC" if r.status_code == 200 \
                             else "EXISTS(403)"
                    console.print(
                        f"  [{'red' if r.status_code==200 else 'yellow'}]"
                        f"⚠ S3 {status}: {url}[/]"
                    )
                    found.append({
                        "type"  : "S3_BUCKET",
                        "url"   : url,
                        "status": r.status_code,
                        "public": r.status_code == 200
                    })
            except Exception:
                continue
    if not found:
        console.print("  [green]No exposed S3 buckets[/green]")
    return found

def check_azure(domain):
    """Check Azure Blob storage."""
    console.print(f"\n[bold]→ Azure Blob Check[/bold]")
    base  = domain.replace("www.","").split(".")[0]
    names = [base, f"{base}storage", f"{base}backup"]
    found = []
    for name in names:
        url = f"https://{name}.blob.core.windows.net"
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code in [200, 400, 403, 404]:
                if "StorageErrorCode" in r.text or \
                   "BlobService" in r.text:
                    console.print(
                        f"  [yellow]⚠ Azure Blob: {url} "
                        f"({r.status_code})[/yellow]"
                    )
                    found.append({
                        "type"  : "AZURE_BLOB",
                        "url"   : url,
                        "status": r.status_code
                    })
        except Exception:
            continue
    return found

def run(domain, output_dir=None):
    """Run cloud asset discovery."""
    console.print(Panel(
        "[bold purple]⬡ CLOUD ASSETS[/bold purple]\n"
        f"[dim]Domain: {domain}[/dim]",
        border_style="purple"
    ))
    import warnings; warnings.filterwarnings("ignore")

    findings  = check_s3(domain)
    findings += check_azure(domain)

    if output_dir and findings:
        import json
        from pathlib import Path
        from datetime import datetime
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        f   = out / f"cloud_assets_{ts}.json"
        f.write_text(json.dumps(findings, indent=2))
        console.print(f"\nReport: {f}")

    console.print(
        f"\n[bold]Total: {len(findings)} cloud assets found[/bold]"
    )
    return findings

if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "example.com")
