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

from . import web_theme
from .github_app import build_manifest

PAGE_CSS = """\
/* Page-specific only — everything else comes from web_theme.CSS. */
.choice{display:flex;gap:var(--s3);align-items:center;flex-wrap:wrap;margin:0 0 var(--s4)}
.choice label{display:flex;gap:7px;align-items:center;cursor:pointer;font-size:13px;
              color:var(--text-secondary)}
input[type=text]{
  font-family:var(--font);font-size:13px;height:36px;padding:0 11px;flex:1;min-width:190px;
  border:1px solid var(--border-subtle);border-radius:var(--radius-sm);
  background:var(--bg-primary);color:var(--text-primary);
}
input[type=text]:focus{border-color:var(--border-active);outline:none}
input[type=text]:disabled{opacity:.4}
input[type=radio]{accent-color:var(--info-solid)}
"""

TEMPLATE = """<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Create the ARGUS GitHub App</title>
<style>
{css}
{page_css}</style>
</head>
<body>
<div class="wrap">
{brandbar}

  <div class="card card--info">
    <span class="badge badge-info"><span class="dot"></span>Step 1 of 2</span>
    <h1 style="margin-top:var(--s3)">Create the ARGUS GitHub App</h1>
    <p class="sub">One click. This page hands GitHub a pre-filled description of
    the app &mdash; you review GitHub&rsquo;s own confirmation screen, and GitHub sends
    the credentials straight back to your Render service.</p>
  </div>

  <div class="card">
    <h2>What ARGUS is asking for</h2>
    <table>
      <tr><td class="k">Repository contents</td><td><span class="badge badge-ok">Read only</span></td></tr>
      <tr><td class="k">Issues</td><td><span class="badge badge-ok">Read only</span></td></tr>
      <tr><td class="k">Pull requests</td><td><span class="badge badge-ok">Read only</span></td></tr>
      <tr><td class="k">Metadata</td><td><span class="badge badge-ok">Read only</span></td></tr>
    </table>
    <p style="margin-top:var(--s4)">Every permission is read-only &mdash; there is no
    write access of any kind in this list. ARGUS cannot comment, close, merge, assign,
    or change anything in your repositories, which is the same rule the project has
    held since day one.</p>
  </div>

  <div class="card">
    <h2>Where it will send events</h2>
    <table>
      <tr><td class="k">Webhook</td><td><code>{base}/v1/webhooks/github</code></td></tr>
      <tr><td class="k">After creation</td><td><code>{base}/v1/admin/github/callback</code></td></tr>
      <tr><td class="k">After install</td><td><code>{base}/v1/github/setup</code></td></tr>
      <tr><td class="k">Visibility</td><td>Private &mdash; only you can install it</td></tr>
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

    <button type="button" id="go" class="btn btn-primary btn-lg">
      Create ARGUS GitHub App on GitHub &rarr;</button>
  </div>

  <div class="card">
    <h2>What happens after you click</h2>
    <ol>
      <li>GitHub shows you its own confirmation page listing exactly the
      permissions above. Nothing is created until you confirm there.</li>
      <li>GitHub creates the app and redirects to your Render service, which
      shows four secrets <strong>once</strong>.</li>
      <li>Copy those four into Render &rarr; Environment, then restart the
      service. Send me a message and I&rsquo;ll take it from there.</li>
    </ol>
  </div>

  <div class="warn"><b>Keep this file to yourself.</b> It carries the one-time setup
  key that authorises creating the app. Don&rsquo;t upload it to GitHub, and delete it
  once the app exists &mdash; it has no further use.</div>

{footer}
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


def render(base_url: str, setup_secret: str) -> str:
    """The page as a string. Split out of `main()` so the styling can be
    checked without writing a file that carries a live setup secret."""
    base_url = base_url.rstrip("/")
    return TEMPLATE.format(
        css=web_theme.CSS,
        page_css=PAGE_CSS,
        brandbar=web_theme.brandbar("github app"),
        footer=web_theme.FOOTER_HTML,
        base=html.escape(base_url),
        state=urllib.parse.quote(setup_secret, safe=""),
        manifest=html.escape(json.dumps(build_manifest(base_url), separators=(",", ":")),
                             quote=True),
    )


def main() -> None:
    if len(sys.argv) != 4:
        print(__doc__)
        raise SystemExit(2)
    base_url, setup_secret, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    page = render(base_url, setup_secret)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"wrote {out_path} ({len(page)} bytes)")


if __name__ == "__main__":
    main()
