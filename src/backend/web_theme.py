"""ARGUS — the one stylesheet every user-facing web page in this codebase uses.

WHY THIS MODULE EXISTS.

Before it, ARGUS had three different-looking front doors. `src/dashboard/
index.html` (Phase 7.4) is a dark, high-density Linear/Vercel-grade console
built strictly on `docs/DESIGN_SYSTEM.md`'s tokens. The two setup-page
generators (`make_manifest_page.py`, `make_slack_app_page.py`) each carried
their own hand-rolled light-mode palette with a `prefers-color-scheme` dark
fallback that shared no token, no radius, and no type scale with the console.
And the install/OAuth pages inside `app.py` had no styling at all — raw `<h1>`
and `<p>` on a white browser default, which is what a pilot team's first ever
sight of ARGUS looked like.

Those pages are all read by the same person within about ten minutes of each
other: they create the app, install it, land on a claim page, and then open
the console. Three visual identities across four screens reads as three
different products, so this module makes them one.

WHAT IS AND IS NOT ALLOWED IN HERE.

Section 1's token block is lifted VERBATIM from `docs/DESIGN_SYSTEM.md` §1 —
the same values, in the same order, that `src/dashboard/index.html` inlines at
its own `:root`. If a token changes in the design doc it changes in both
places or the uniformity this module exists to create quietly rots. Section 2
adds only what standalone document-shaped pages need and the console already
had privately (spacing scale, radii, font stacks, easing) — never a new
colour. Section 3's components are the design doc's §3 recipes, plus the
document-flow elements (`table`, `pre`, `ol`) the console never needed because
it renders no prose.

Deliberately dependency-free and framework-free: `make_manifest_page.py` runs
as a standalone script with no FastAPI import and no environment, so anything
this module reaches for would have to exist there too.
"""
from __future__ import annotations

import html
import re

# ===========================================================================
# 1. Tokens — verbatim from docs/DESIGN_SYSTEM.md §1.
# ===========================================================================

TOKENS_CSS = """\
:root{
  --bg-primary:#090a0f;
  --bg-surface:#11141a;
  --bg-surface-elevated:#181d26;
  --border-subtle:#222936;
  --border-active:#3b465a;

  --text-primary:#f3f4f6;
  --text-secondary:#9ca3af;
  --text-muted:#6b7280;

  --urgent-bg:rgba(239,68,68,.12);
  --urgent-border:rgba(239,68,68,.35);
  --urgent-text:#f87171;
  --urgent-solid:#ef4444;

  --warn-bg:rgba(245,158,11,.12);
  --warn-border:rgba(245,158,11,.35);
  --warn-text:#fbbf24;
  --warn-solid:#f59e0b;

  --ok-bg:rgba(16,185,129,.12);
  --ok-border:rgba(16,185,129,.35);
  --ok-text:#34d399;
  --ok-solid:#10b981;

  --info-bg:rgba(59,130,246,.12);
  --info-border:rgba(59,130,246,.35);
  --info-text:#60a5fa;
  --info-solid:#3b82f6;

  --suppressed-bg:rgba(107,114,128,.08);
  --suppressed-border:rgba(107,114,128,.25);
  --suppressed-text:#9ca3af;

  /* Additive, and identical to the private scale src/dashboard/index.html
     already declares under its own "added for 7.4" comment. */
  --s1:4px; --s2:8px; --s3:12px; --s4:16px; --s5:24px; --s6:32px; --s7:48px;
  --radius-sm:6px; --radius:8px; --radius-lg:10px;
  --font:"Inter","Geist Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --shadow-pop:0 12px 32px rgba(0,0,0,.55);
  --ease:cubic-bezier(.2,.7,.3,1);
}
"""

# ===========================================================================
# 2. Base + components.
#
# One departure from the console worth naming: these pages are prose at
# reading width, not a 1440px data grid, so the base font size is 14px and the
# measure is capped at 680px. Everything else — colour, radius, border,
# letter-spacing, the type scale in §2 of the design doc — is the console's.
# ===========================================================================

BASE_CSS = """\
*,*::before,*::after{box-sizing:border-box}
html{color-scheme:dark}
body{
  margin:0;padding:var(--s7) var(--s5) 72px;
  background:var(--bg-primary);color:var(--text-primary);
  font-family:var(--font);font-size:14px;line-height:1.55;
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;
}
/* The console's single quiet light source at the top of the page, so a
   near-black page does not read as a flat void. Purely decorative. */
body::before{
  content:"";position:fixed;inset:0 0 auto 0;height:340px;pointer-events:none;
  background:radial-gradient(90% 100% at 50% 0%,rgba(59,130,246,.055),transparent 70%);
  z-index:0;
}
.wrap{position:relative;z-index:1;width:100%;max-width:680px;margin:0 auto}
.wrap--wide{max-width:860px}

a{color:var(--info-text);text-decoration:none}
a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--info-solid);outline-offset:2px;border-radius:3px}
::selection{background:rgba(59,130,246,.35)}
.mono{font-family:var(--mono);font-variant-ligatures:none}
.num{font-variant-numeric:tabular-nums}
.muted{color:var(--text-muted)}

/* ---- brand lockup ---------------------------------------------------- */
.brandbar{
  display:flex;align-items:center;gap:9px;
  margin:0 0 var(--s5);padding-bottom:var(--s4);
  border-bottom:1px solid var(--border-subtle);
}
.brandbar svg{display:block;flex:none}
.brandbar b{font-size:13px;font-weight:650;letter-spacing:.14em;text-transform:uppercase}
.brandbar .tag{
  font-family:var(--mono);font-size:10px;color:var(--text-muted);
  border:1px solid var(--border-subtle);border-radius:4px;padding:1px 5px;
}
.brandbar .spacer{flex:1}
.brandbar .whoami{font-size:11px;color:var(--text-muted)}

/* ---- card (DESIGN_SYSTEM §3A, widened for prose) --------------------- */
.card{
  background:var(--bg-surface);border:1px solid var(--border-subtle);
  border-radius:var(--radius-lg);padding:var(--s5) var(--s5) var(--s4);
  margin:0 0 var(--s4);
  transition:border-color .15s var(--ease),background .15s var(--ease);
}
.card--ok{border-left:3px solid var(--ok-solid)}
.card--warn{border-left:3px solid var(--warn-solid)}
.card--urgent{border-left:3px solid var(--urgent-solid)}
.card--info{border-left:3px solid var(--info-solid)}
.card--muted{border-left:3px solid var(--text-muted)}
/* The glow is what makes the status read at a glance without shouting; it is
   the card's own accent at 6%, never a second colour. */
.card--ok{box-shadow:0 0 0 1px rgba(16,185,129,.06),0 18px 44px rgba(0,0,0,.45)}
.card--warn{box-shadow:0 0 0 1px rgba(245,158,11,.06),0 18px 44px rgba(0,0,0,.45)}
.card--urgent{box-shadow:0 0 0 1px rgba(239,68,68,.06),0 18px 44px rgba(0,0,0,.45)}
.card--info{box-shadow:0 0 0 1px rgba(59,130,246,.06),0 18px 44px rgba(0,0,0,.45)}

/* ---- type scale (DESIGN_SYSTEM §2) ----------------------------------- */
h1{font-size:24px;font-weight:700;letter-spacing:-.025em;margin:0 0 var(--s2);line-height:1.25}
h2{
  font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;
  color:var(--text-muted);margin:0 0 var(--s3);
}
h3{font-size:15px;font-weight:600;letter-spacing:-.01em;margin:var(--s4) 0 var(--s2)}
p{margin:0 0 var(--s3);color:var(--text-secondary)}
p.lede,p.sub{color:var(--text-secondary);font-size:14px}
p:last-child{margin-bottom:0}
b,strong{color:var(--text-primary);font-weight:600}
ol,ul{margin:0 0 var(--s3);padding-left:20px;color:var(--text-secondary)}
li{margin:0 0 var(--s2)}
li::marker{color:var(--text-muted)}

/* ---- badge (DESIGN_SYSTEM §3C) --------------------------------------- */
.badge,.pill{
  display:inline-flex;align-items:center;gap:5px;
  font-size:11px;font-weight:600;padding:2px 8px;border-radius:9999px;
  text-transform:uppercase;letter-spacing:.04em;white-space:nowrap;
  background:var(--suppressed-bg);color:var(--suppressed-text);
  border:1px solid var(--suppressed-border);
}
.badge-urgent{background:var(--urgent-bg);color:var(--urgent-text);border-color:var(--urgent-border)}
.badge-warn{background:var(--warn-bg);color:var(--warn-text);border-color:var(--warn-border)}
.badge-ok,.pill{background:var(--ok-bg);color:var(--ok-text);border-color:var(--ok-border)}
.badge-info{background:var(--info-bg);color:var(--info-text);border-color:var(--info-border)}
.badge-muted{background:var(--suppressed-bg);color:var(--suppressed-text);border-color:var(--suppressed-border)}
.dot{width:7px;height:7px;border-radius:50%;flex:none;display:inline-block;background:currentColor}

/* ---- code / monospace ------------------------------------------------ */
code{
  font-family:var(--mono);font-size:12.5px;
  background:var(--bg-surface-elevated);border:1px solid var(--border-subtle);
  border-radius:5px;padding:1px 5px;color:var(--text-primary);
  /* `break-word`, not `break-all`: an env var name split as ARGUS_SLACK_CLIENT_I
     / D is unreadable and, worse, un-copyable by eye. This wraps between words
     and only breaks inside one when a single token genuinely cannot fit. */
  word-break:normal;overflow-wrap:break-word;
}
pre{
  font-family:var(--mono);font-size:12.5px;line-height:1.6;
  background:var(--bg-primary);border:1px solid var(--border-subtle);
  border-radius:var(--radius);padding:var(--s4);
  margin:0 0 var(--s3);overflow:auto;max-height:460px;color:var(--text-secondary);
}
pre code{background:none;border:0;padding:0}
textarea{
  width:100%;font-family:var(--mono);font-size:12.5px;line-height:1.55;
  background:var(--bg-primary);color:var(--text-primary);
  border:1px solid var(--border-subtle);border-radius:var(--radius-sm);
  padding:var(--s2) var(--s3);resize:vertical;
}
textarea:focus{border-color:var(--border-active);outline:none}

/* ---- tables ---------------------------------------------------------- */
table{width:100%;border-collapse:collapse;font-size:13px;margin:0 0 var(--s3)}
th{
  text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;
  letter-spacing:.05em;color:var(--text-muted);
  padding:var(--s2) var(--s3) var(--s2) 0;border-bottom:1px solid var(--border-subtle);
  white-space:nowrap;vertical-align:top;
}
td{
  padding:var(--s3) var(--s3) var(--s3) 0;border-bottom:1px solid var(--border-subtle);
  vertical-align:top;color:var(--text-secondary);
}
tr:last-child td{border-bottom:0}
td.k{color:var(--text-muted);width:40%}

/* ---- buttons --------------------------------------------------------- */
.actions{display:flex;flex-wrap:wrap;gap:var(--s2);margin-top:var(--s4)}
.btn,button{
  display:inline-flex;align-items:center;justify-content:center;gap:7px;
  font-family:var(--font);font-size:13px;font-weight:600;letter-spacing:-.005em;
  height:36px;padding:0 var(--s4);cursor:pointer;
  border:1px solid var(--border-subtle);border-radius:var(--radius-sm);
  background:var(--bg-surface-elevated);color:var(--text-primary);
  transition:background .15s var(--ease),border-color .15s var(--ease);
  text-decoration:none;
}
.btn:hover,button:hover{background:#1f2531;border-color:var(--border-active);text-decoration:none}
.btn-primary{
  background:var(--info-solid);border-color:var(--info-solid);color:#fff;
  box-shadow:0 0 0 1px rgba(59,130,246,.25),0 8px 24px rgba(59,130,246,.18);
}
.btn-primary:hover{background:#2f74e0;border-color:#2f74e0}
.btn-lg{height:44px;font-size:15px;padding:0 var(--s5);width:100%}
.btn:disabled,button:disabled{opacity:.55;cursor:default}

/* ---- notes ----------------------------------------------------------- */
.note,.warn{
  border-radius:var(--radius);padding:var(--s3) var(--s4);
  margin:0 0 var(--s3);font-size:13px;
}
.note{background:var(--ok-bg);border:1px solid var(--ok-border);color:var(--ok-text)}
.warn{background:var(--warn-bg);border:1px solid var(--warn-border);color:var(--warn-text)}
.info{background:var(--info-bg);border:1px solid var(--info-border);color:var(--info-text);
      border-radius:var(--radius);padding:var(--s3) var(--s4);margin:0 0 var(--s3);font-size:13px}
.note b,.warn b,.info b{color:inherit}

/* ---- footer ---------------------------------------------------------- */
.pagefoot{
  margin-top:var(--s5);padding-top:var(--s4);border-top:1px solid var(--border-subtle);
  font-size:11px;color:var(--text-muted);
  display:flex;align-items:center;gap:var(--s2);flex-wrap:wrap;
}

@media (max-width:640px){
  body{padding:var(--s5) var(--s4) 56px}
  .card{padding:var(--s4)}
  .actions .btn{flex:1 1 100%}
}
"""

CSS = TOKENS_CSS + "\n" + BASE_CSS

# ===========================================================================
# 3. The brand mark — the same radar glyph src/dashboard/index.html draws in
#    its topbar, at the same stroke weights, so the console and the install
#    pages are recognisably one product.
# ===========================================================================

BRAND_SVG = (
    '<svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">'
    '<circle cx="9" cy="9" r="7.25" stroke="#3b465a" stroke-width="1.2"/>'
    '<circle cx="9" cy="9" r="3.4" stroke="#6b7280" stroke-width="1.2"/>'
    '<circle cx="9" cy="9" r="1.5" fill="#ef4444"/>'
    '<path d="M9 1.75V4M9 14v2.25M1.75 9H4M14 9h2.25" stroke="#3b465a"'
    ' stroke-width="1.2" stroke-linecap="round"/>'
    "</svg>"
)

FOOTER_HTML = (
    '<div class="pagefoot">' + BRAND_SVG +
    "<span>ARGUS &mdash; engineering stall radar</span></div>"
)


def brandbar(tag: str = "", whoami: str = "") -> str:
    """The topbar lockup: radar mark, wordmark, optional mono tag."""
    tag_html = f'<span class="tag">{html.escape(tag)}</span>' if tag else ""
    right = f'<span class="spacer"></span><span class="whoami">{whoami}</span>' if whoami else ""
    return f'<div class="brandbar">{BRAND_SVG}<b>Argus</b>{tag_html}{right}</div>'


# ===========================================================================
# 4. Page shells.
# ===========================================================================

_DOC = """<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>{title}</title>
<style>
{css}
{extra_css}</style>
</head>
<body>
<div class="{wrap_class}">
{body}
{footer}
</div>
{scripts}</body>
</html>
"""


def document(title: str, body: str, *, tag: str = "", extra_css: str = "",
             scripts: str = "", wide: bool = False, footer: bool = True,
             brand: bool = True) -> str:
    """A complete standalone ARGUS page. `body` is trusted HTML — every caller
    in this codebase builds it from escaped values, and this function does not
    escape it a second time (that would mangle the markup callers pass in).
    `title` IS escaped, because it is the one argument that is sometimes a
    user- or Slack-supplied string."""
    return _DOC.format(
        title=html.escape(title),
        css=CSS,
        extra_css=(extra_css + "\n") if extra_css else "",
        wrap_class="wrap wrap--wide" if wide else "wrap",
        body=(brandbar(tag) if brand else "") + "\n" + body,
        footer=FOOTER_HTML if footer else "",
        scripts=(scripts + "\n") if scripts else "",
    )


#: What each status kind renders as: card accent + pill styling + pill label.
_KINDS = {
    "ok":     ("card--ok",     "badge-ok",     "Connected"),
    "warn":   ("card--warn",   "badge-warn",   "Action needed"),
    "urgent": ("card--urgent", "badge-urgent", "Not connected"),
    "info":   ("card--info",   "badge-info",   "In progress"),
    "muted":  ("card--muted",  "badge-muted",  "Nothing changed"),
}


def plain_title(markup: str) -> str:
    """`"&#9989; ARGUS is now connected"` -> `"ARGUS is now connected"`.

    Headings on these pages carry entities and the odd `<b>` because they are
    written as HTML, but a browser tab title is plain text — rendering the raw
    markup there is how a tab ends up reading `&#9989; ARGUS ...`. Strips tags,
    resolves entities, and drops any leading emoji, since the tab already has
    the favicon's job covered.
    """
    text = html.unescape(re.sub(r"<[^>]+>", "", markup)).strip()
    return re.sub(r"^[^\w(]+", "", text).strip() or "ARGUS"


def action_button(label: str, href: str, *, primary: bool = False) -> str:
    """One `[Open Standup Radar]`-style action. Returns "" for a falsy href so
    a caller can offer a button only when the URL it needs is configured,
    without branching at every call site."""
    if not href:
        return ""
    cls = "btn btn-primary" if primary else "btn"
    return f'<a class="{cls}" href="{html.escape(href, quote=True)}">{label}</a>'


def status_page(kind: str, title: str, body: str, *, pill: str | None = None,
                actions: str = "", detail: str = "", tag: str = "") -> str:
    """The shape every install / OAuth / claim outcome shares.

    One card, one status pill, one sentence of what happened, one sentence of
    what to do next, and at most two buttons — the same information hierarchy
    a radar card in the console uses (badge, title, evidence, actions), so the
    page a pilot contact lands on after installing reads like the product they
    are about to open, not like an error from a different decade.
    """
    card_cls, pill_cls, default_pill = _KINDS.get(kind, _KINDS["info"])
    pill_text = html.escape(pill if pill is not None else default_pill)
    detail_html = f'<div class="info mono">{detail}</div>' if detail else ""
    actions_html = f'<div class="actions">{actions}</div>' if actions else ""
    inner = (
        f'<div class="card {card_cls}">'
        f'<span class="badge {pill_cls}"><span class="dot"></span>{pill_text}</span>'
        f"<h1 style=\"margin-top:var(--s3)\">{title}</h1>"
        f"{body}"
        f"{detail_html}"
        f"{actions_html}"
        "</div>"
    )
    return document(plain_title(title), inner, tag=tag)
