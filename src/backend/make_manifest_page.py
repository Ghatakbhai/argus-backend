"""ARGUS Phase 7.2 — generates the one-click "Create ARGUS GitHub App" page.

GitHub's App-manifest flow works by POSTing a form to github.com with the
manifest JSON in a field, which means it cannot be a link — it has to be a
real form submission from a real page. This script writes that page.

Deliberately takes the base URL and setup secret as ARGUMENTS rather than
reading config.py: this runs in Claude's sandbox, where neither value is (or
should be) set, while the real values live only in Render's environment. The
GENERATED page contains the setup secret, so it belongs in `secrets/` and
never in the repository that gets deployed — same discipline as every other
credential in this project (D-087).

Run from the `src/` directory, so `backend` is importable as a package:

    python -m backend.make_manifest_page <base_url> <setup_secret> <output_path>
"""
from __future__ import annotations

import html
import json
import sys
import urllib.parse

from .github_app import build_manifest

TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Create the ARGUS GitHub App</title>
<style>
  :root {{
    --bg: #f6f7f9; --card: #ffffff; --ink: #14171a; --muted: #5b6572;
    --line: #dfe3e8; --accent: #1f6feb; --accent-ink: #ffffff;
    --ok-bg: #e8f5ec; --ok-line: #b7dfc4; --ok-ink: #17612f;
    --warn-bg: #fff6e0; --warn-line: #f0d9a0; --warn-ink: #6b4e00;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg: #0f1216; --card: #171b21; --ink: #e8ecf1; --muted: #9aa4b2;
      --line: #2a313a; --accent: #4c8dff; --accent-ink: #0b0e12;
      --ok-bg: #12301d; --ok-line: #2c5c3c; --ok-ink: #9fe0b5;
      --warn-bg: #2e2612; --warn-line: #5c4a1f; --warn-ink: #f0d9a0;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 32px 20px 64px; background: var(--bg); color: var(--ink);
    font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }}
  .wrap {{ max-width: 680px; margin: 0 auto; }}
  .card {{
    background: var(--card); border: 1px solid var(--line); border-radius: 12px;
    padding: 28px; margin-bottom: 20px;
  }}
  h1 {{ font-size: 25px; margin: 0 0 6px; letter-spacing: -0.01em; }}
  h2 {{ font-size: 15px; margin: 0 0 12px; text-transform: uppercase;
       letter-spacing: 0.06em; color: var(--muted); font-weight: 600; }}
  p {{ margin: 0 0 14px; }}
  .sub {{ color: var(--muted); margin-bottom: 0; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 15px; }}
  td {{ padding: 8px 0; border-bottom: 1px solid var(--line); vertical-align: top; }}
  tr:last-child td {{ border-bottom: 0; }}
  td.k {{ color: var(--muted); width: 42%; padding-right: 16px; }}
  code {{
    font: 13.5px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    background: var(--bg); border: 1px solid var(--line); border-radius: 5px;
    padding: 1px 5px; word-break: break-all;
  }}
  .pill {{
    display: inline-block; font-size: 12.5px; font-weight: 600; padding: 2px 9px;
    border-radius: 999px; background: var(--ok-bg); color: var(--ok-ink);
    border: 1px solid var(--ok-line); letter-spacing: 0.02em;
  }}
  button {{
    font: 600 17px/1 inherit; background: var(--accent); color: var(--accent-ink);
    border: 0; border-radius: 9px; padding: 16px 26px; cursor: pointer; width: 100%;
  }}
  button:hover {{ filter: brightness(1.08); }}
  .choice {{ display: flex; gap: 12px; align-items: center; margin-bottom: 16px;
            flex-wrap: wrap; font-size: 15px; }}
  .choice label {{ display: flex; gap: 7px; align-items: center; cursor: pointer; }}
  input[type=text] {{
    font: 15px/1 inherit; padding: 9px 11px; border: 1px solid var(--line);
    border-radius: 7px; background: var(--bg); color: var(--ink); flex: 1; min-width: 190px;
  }}
  input[type=text]:disabled {{ opacity: 0.45; }}
  .note {{
    background: var(--warn-bg); border: 1px solid var(--warn-line); color: var(--warn-ink);
    border-radius: 9px; padding: 14px 16px; font-size: 14.5px; margin: 0;
  }}
  ol {{ margin: 0; padding-left: 22px; }}
  ol li {{ margin-bottom: 9px; }}
  ol li:last-child {{ margin-bottom: 0; }}
</style>
</head>
<body>
<div class="wrap">

  <div class="card">
    <h1>Create the ARGUS GitHub App</h1>
    <p class="sub">One click. This page hands GitHub a pre-filled description of
    the app — you review GitHub's own confirmation screen, and GitHub sends the
    credentials straight back to your Render service.</p>
  </div>

  <div class="card">
    <h2>What ARGUS is asking for</h2>
    <table>
      <tr><td class="k">Repository contents</td><td><span class="pill">Read only</span></td></tr>
      <tr><td class="k">Issues</td><td><span class="pill">Read only</span></td></tr>
      <tr><td class="k">Pull requests</td><td><span class="pill">Read only</span></td></tr>
      <tr><td class="k">Metadata</td><td><span class="pill">Read only</span></td></tr>
    </table>
    <p style="margin:16px 0 0;font-size:14.5px;color:var(--muted)">
    Every permission is read-only — there is no write access of any kind in this
    list. ARGUS cannot comment, close, merge, assign, or change anything in your
    repositories, which is the same rule the project has held since day one.</p>
  </div>

  <div class="card">
    <h2>Where it will send events</h2>
    <table>
      <tr><td class="k">Webhook</td><td><code>{base}/v1/webhooks/github</code></td></tr>
      <tr><td class="k">After creation</td><td><code>{base}/v1/admin/github/callback</code></td></tr>
      <tr><td class="k">After install</td><td><code>{base}/v1/github/setup</code></td></tr>
      <tr><td class="k">Visibility</td><td>Private — only you can install it</td></tr>
    </table>
  </div>

  <div class="card">
    <h2>Create it</h2>
    <form method="post" action="https://github.com/settings/apps/new?state={state}"
          id="f-personal">
      <input type="hidden" name="manifest" value="{manifest}">
    </form>
    <form method="post" action="" id="f-org">
      <input type="hidden" name="manifest" value="{manifest}">
    </form>

    <div class="choice">
      <label><input type="radio" name="acct" value="personal" checked> My account
        (<code>Ghatakbhai</code>)</label>
      <label><input type="radio" name="acct" value="org"> An organization:</label>
      <input type="text" id="org" placeholder="organization name" disabled>
    </div>

    <button type="button" id="go">Create ARGUS GitHub App on GitHub &rarr;</button>
  </div>

  <div class="card">
    <h2>What happens after you click</h2>
    <ol>
      <li>GitHub shows you its own confirmation page listing exactly the
      permissions above. Nothing is created until you confirm there.</li>
      <li>GitHub creates the app and redirects to your Render service, which
      shows four secrets <strong>once</strong>.</li>
      <li>Copy those four into Render &rarr; Environment, then restart the
      service. Send me a message and I'll take it from there.</li>
    </ol>
  </div>

  <div class="card" style="padding:18px 20px">
    <p class="note"><strong>Keep this file to yourself.</strong> It carries the
    one-time setup key that authorises creating the app. Don't upload it to
    GitHub, and delete it once the app exists — it has no further use.</p>
  </div>

</div>
<script>
  var org = document.getElementById('org');
  document.querySelectorAll('input[name=acct]').forEach(function (r) {{
    r.addEventListener('change', function () {{
      org.disabled = document.querySelector('input[name=acct]:checked').value !== 'org';
      if (!org.disabled) org.focus();
    }});
  }});
  document.getElementById('go').addEventListener('click', function () {{
    if (document.querySelector('input[name=acct]:checked').value === 'personal') {{
      document.getElementById('f-personal').submit();
      return;
    }}
    var name = org.value.trim();
    if (!name) {{ org.focus(); return; }}
    var f = document.getElementById('f-org');
    f.action = 'https://github.com/organizations/' + encodeURIComponent(name)
             + '/settings/apps/new?state={state}';
    f.submit();
  }});
</script>
</body>
</html>
"""


def main() -> None:
    if len(sys.argv) != 4:
        print(__doc__)
        raise SystemExit(2)
    base_url, setup_secret, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    base_url = base_url.rstrip("/")

    page = TEMPLATE.format(
        base=html.escape(base_url),
        state=urllib.parse.quote(setup_secret, safe=""),
        manifest=html.escape(json.dumps(build_manifest(base_url), separators=(",", ":")),
                             quote=True),
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"wrote {out_path} ({len(page)} bytes)")


if __name__ == "__main__":
    main()
