"""ARGUS — 1-Click Pilot Team Onboarding CLI Tool (Phase 7.5 / 7.6)

Usage:
  python src/onboard_pilot.py <tenant-slug> "<Company / Team Name>"

Example:
  python src/onboard_pilot.py acme-corp "Acme Corp Engineering"

What this tool does:
1. Provisions the new isolated tenant in PostgreSQL under 2-Week Shadow Mode.
2. Generates a one-time, single-use GitHub App installation claim link.
3. Generates a one-time, single-use Slack Bot installation claim link.
4. Generates the live Standup Radar web console link for the Tech Lead.
5. Prints a complete, ready-to-send onboarding invite message.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import timezone

# Default public Render service URL
DEFAULT_BASE_URL = os.environ.get(
    "ARGUS_PUBLIC_BASE_URL", "https://argus-backend-2nv0.onrender.com"
).rstrip("/")

# Admin secret (defaults to dev or env variable)
DEFAULT_ADMIN_SECRET = os.environ.get(
    "ARGUS_ADMIN_SECRET", "dev-admin-secret-change-me"
)


def api_post(url: str, headers: dict, data: dict) -> dict:
    body = json.dumps(data).encode("utf-8") if data else b"{}"
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            **headers,
        },
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def onboard_pilot(slug: str, display_name: str, base_url: str, admin_secret: str):
    print(f"🚀 Provisioning pilot team '{display_name}' ({slug}) on {base_url}...")
    
    # 14 days shadow mode window
    shadow_until = (
        datetime.datetime.now(timezone.utc) + datetime.timedelta(days=14)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    admin_headers = {"x-admin-key": admin_secret}

    # 1. Create Tenant
    tenant_payload = {
        "slug": slug,
        "display_name": display_name,
        "shadow_until": shadow_until,
    }
    try:
        tenant_res = api_post(
            f"{base_url}/v1/admin/tenants", admin_headers, tenant_payload
        )
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8")
        if e.code == 409:
            print(f"⚠️  Tenant '{slug}' already exists. Re-generating fresh install links...")
            tenant_res = {"slug": slug, "api_key": "(existing)", "id": "(existing)"}
        else:
            print(f"❌ Error creating tenant: {e.code} {err}")
            sys.exit(1)

    # 2. Mint GitHub Install Link
    try:
        gh_res = api_post(
            f"{base_url}/v1/admin/tenants/{slug}/github/install-link",
            admin_headers,
            {},
        )
        gh_link = gh_res["install_url"]
    except Exception as e:
        gh_link = f"(Error generating GitHub link: {e})"

    # 3. Mint Slack Install Link
    try:
        slack_res = api_post(
            f"{base_url}/v1/admin/tenants/{slug}/slack/install-link",
            admin_headers,
            {},
        )
        slack_link = slack_res["install_url"]
    except Exception as e:
        slack_link = f"(Error generating Slack link: {e})"

    # 4. Console Link
    api_key = tenant_res.get("api_key", "YOUR_API_KEY")
    console_link = f"{base_url}/src/dashboard/index.html?base={base_url}&key={api_key}"

    print("\n" + "=" * 70)
    print(f"✅ PILOT PROVISIONED: {display_name} ({slug})")
    print("=" * 70)
    print(f"• Tenant Status:     SHADOW MODE (2 Weeks — Active until {shadow_until[:10]})")
    print(f"• Tenant API Key:    {api_key}")
    print(f"• GitHub Install:    {gh_link}")
    print(f"• Slack Install:     {slack_link}")
    print("=" * 70)
    print("\n📬 COPY & PASTE INVITE MESSAGE FOR THE PILOT TECH LEAD:\n")

    msg = f"""Hi team,

Welcome to the ARGUS Delivery Stall Radar closed beta! 

To connect ARGUS for {display_name}, please complete these two 1-click authorization links (takes ~60 seconds):

1️⃣ Connect GitHub (Read-only PR/Review metadata):
{gh_link}

2️⃣ Connect Slack (Direct-message delivery bot only; zero channel reading):
{slack_link}

🛡️ Privacy & Security:
• Zero Code Storage: ARGUS inspects PR metadata/timestamps only and never clones or stores proprietary code.
• 2-Week Silent Shadow Mode: For the first 14 days, ARGUS runs in complete silence (0 messages sent to developers) while we calibrate thresholds.
• 1-Click Micro-Triage: Once active, developers resolve flagged stalls in 2 seconds via interactive Slack buttons.

If you have any questions, I'm right here!
"""
    print(msg)
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Provision a pilot team with 1-click install links."
    )
    parser.add_argument("slug", help="Unique tenant slug (e.g. acme-corp)")
    parser.add_argument("name", help="Display name (e.g. 'Acme Corp Engineering')")
    parser.add_argument(
        "--url",
        default=DEFAULT_BASE_URL,
        help=f"ARGUS Backend URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--admin-key",
        default=DEFAULT_ADMIN_SECRET,
        help="Admin secret for /v1/admin endpoints",
    )

    args = parser.parse_args()
    onboard_pilot(args.slug, args.name, args.url, args.admin_key)


if __name__ == "__main__":
    main()
