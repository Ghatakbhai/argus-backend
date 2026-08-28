"""ARGUS Phase 7.3 — generates the "Create the ARGUS Slack app" setup page.

The 7.2 counterpart (`make_manifest_page.py`) had to be a real HTML form
because GitHub's manifest flow is a POST, not a link. Slack's is neither: you
paste a manifest into a box on api.slack.com. Slack's published documentation
describes exactly one route — "Your Apps → Create New App → from a manifest" —
and no URL that pre-fills one, so this page does not invent one. It gives the
manifest, a copy button, and the four values to bring back.

TWO REAL DIFFERENCES FROM THE GITHUB PAGE, BOTH WORTH KNOWING:

  * This page contains NO secret. The GitHub page embedded the live setup
    secret, which is why it had to live in `secrets/` and be deleted after
    use. A Slack manifest is public information — it is exactly what a pilot
    team's security reviewer should be able to read — so this page is safe to
    keep, safe to track, and safe to re-generate.
  * The credentials flow the OTHER way. GitHub handed its App's credentials
    back to the backend automatically. Slack shows them on its own settings
    screen, so four values have to be carried from Slack into Render by hand,
    once. The page lists them in the order Slack's own UI shows them.

Run from `src/`, so `backend` is importable as a package:

    python -m backend.make_slack_app_page <base_url> <output_path>
"""
from __future__ import annotations

import html
import json
import sys

from . import web_theme
from .slack_app import build_manifest

PAGE_CSS = """\
/* Page-specific only — everything else comes from web_theme.CSS. */
#copied{margin-left:10px;font-size:12px;color:var(--ok-text)}
pre{max-height:520px}
"""

TEMPLATE = """<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Create the ARGUS Slack app</title>
<style>
{css}
{page_css}</style>
</head>
<body>
<div class="wrap">
{brandbar}

  <div class="card card--info">
    <span class="badge badge-info"><span class="dot"></span>Setup</span>
    <h1 style="margin-top:var(--s3)">Create the ARGUS Slack app</h1>
    <p class="lede">One app, installed by every pilot team's workspace. This
    takes about three minutes and nothing here can break the running
    backend.</p>
    <div class="note"><b>Nothing on this page is a secret.</b> The manifest
    below is exactly what a pilot team's security reviewer should be able to
    read: which permissions ARGUS asks for and which URLs it talks to. Keep
    it, share it, re-generate it whenever.</div>
    <p>Backend this manifest points at: <code>{base_url}</code></p>
  </div>

  <div class="card">
    <h2>Step 1 &mdash; create the app</h2>
    <ol>
      <li>Open <a href="https://api.slack.com/apps" target="_blank"
          rel="noopener">api.slack.com/apps</a> and click <b>Create New
          App</b>.</li>
      <li>Choose <b>From a manifest</b>, then pick any workspace (this only
          decides where the app is <i>developed</i> &mdash; pilot teams install
          it separately).</li>
      <li>Choose the <b>JSON</b> tab, paste the manifest below, and click
          <b>Next</b> then <b>Create</b>.</li>
    </ol>
    <p><button class="btn btn-primary" onclick="copyManifest()">Copy the manifest</button>
       <span id="copied"></span></p>
    <pre id="manifest">{manifest_html}</pre>
  </div>

  <div class="card">
    <h2>Step 2 &mdash; bring four values back to Render</h2>
    <p>Slack shows these on the app's own settings pages. Paste each one into
    Render &rarr; your <code>argus-backend</code> service &rarr;
    <b>Environment</b>, then restart the service.</p>
    <table>
      <tr><th>Render variable</th><th>Where Slack shows it</th></tr>
      <tr><td><code>ARGUS_SLACK_CLIENT_ID</code></td>
          <td><b>Basic Information</b> &rarr; App Credentials &rarr; Client ID</td></tr>
      <tr><td><code>ARGUS_SLACK_CLIENT_SECRET</code></td>
          <td><b>Basic Information</b> &rarr; App Credentials &rarr; Client Secret
              (click <i>Show</i>)</td></tr>
      <tr><td><code>ARGUS_SLACK_SIGNING_SECRET</code></td>
          <td><b>Basic Information</b> &rarr; App Credentials &rarr; Signing Secret</td></tr>
      <tr><td><code>ARGUS_SLACK_TOKEN_KEY</code></td>
          <td>Not from Slack &mdash; click <b>Generate Value</b> in Render. This is
              what encrypts every workspace's token before it is stored.</td></tr>
    </table>
    <div class="warn"><b>The signing secret is the one that matters most.</b>
    It is how ARGUS proves an incoming button click really came from Slack.
    Until it is set, every Slack request is refused &mdash; which is the correct
    way round for it to fail, but it does mean nothing will work until you
    paste it.</div>
  </div>

  <div class="card">
    <h2>Step 3 &mdash; check the two URLs went in</h2>
    <p>The manifest sets these, but Slack sometimes wants the Events URL
    re-verified after the app exists. If either shows as unverified, click
    <b>Retry</b> &mdash; the backend answers Slack's challenge automatically.</p>
    <table>
      <tr><th>Event Subscriptions</th><td><code>{base_url}/v1/slack/events</code></td></tr>
      <tr><th>Interactivity</th><td><code>{base_url}/v1/slack/interactions</code></td></tr>
      <tr><th>OAuth redirect</th><td><code>{base_url}/v1/slack/oauth/callback</code></td></tr>
    </table>
  </div>

  <div class="card">
    <h2>What happens after this</h2>
    <p>Nothing is installed anywhere yet. Creating the app just makes it
    <i>installable</i>. For each pilot team, ARGUS mints a one-time
    &ldquo;Add to Slack&rdquo; link tied to that team and nobody else's &mdash;
    the workspace never gets to say which ARGUS team it belongs to, and the
    link only works once.</p>
  </div>

{footer}
</div>
<script>
function copyManifest() {{
  navigator.clipboard.writeText(document.getElementById('manifest').textContent)
    .then(function () {{ document.getElementById('copied').textContent = 'Copied.'; }})
    .catch(function () {{
      document.getElementById('copied').textContent =
        'Copy failed — select the text above and copy it by hand.';
    }});
}}
</script>
</body>
</html>
"""


def render(base_url: str) -> str:
    manifest = json.dumps(build_manifest(base_url), indent=2)
    return TEMPLATE.format(css=web_theme.CSS,
                           page_css=PAGE_CSS,
                           brandbar=web_theme.brandbar("slack app"),
                           footer=web_theme.FOOTER_HTML,
                           base_url=html.escape(base_url.rstrip("/")),
                           manifest_html=html.escape(manifest))


def main() -> None:
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[-1].strip(), file=sys.stderr)
        raise SystemExit(2)
    base_url, out_path = sys.argv[1], sys.argv[2]
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(render(base_url))
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
