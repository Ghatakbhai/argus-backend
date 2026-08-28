# ARGUS Design System Tokens & Style Recipes (Linear / Vercel Aesthetic)

**Design Philosophy:** High-density, dark-mode-first, mission-critical engineering interface. High contrast, precise typography, zero clutter.

---

## 1. Color Palette Tokens

### Dark Mode (Default)
```css
:root {
  --bg-primary: #090a0f;
  --bg-surface: #11141a;
  --bg-surface-elevated: #181d26;
  --border-subtle: #222936;
  --border-active: #3b465a;
  
  --text-primary: #f3f4f6;
  --text-secondary: #9ca3af;
  --text-muted: #6b7280;
  
  /* Semantic Status Colors */
  --urgent-bg: rgba(239, 68, 68, 0.12);
  --urgent-border: rgba(239, 68, 68, 0.35);
  --urgent-text: #f87171;
  --urgent-solid: #ef4444;
  
  --warn-bg: rgba(245, 158, 11, 0.12);
  --warn-border: rgba(245, 158, 11, 0.35);
  --warn-text: #fbbf24;
  
  --ok-bg: rgba(16, 185, 129, 0.12);
  --ok-border: rgba(16, 185, 129, 0.35);
  --ok-text: #34d399;
  
  --info-bg: rgba(59, 130, 246, 0.12);
  --info-border: rgba(59, 130, 246, 0.35);
  --info-text: #60a5fa;
  
  --suppressed-bg: rgba(107, 114, 128, 0.08);
  --suppressed-border: rgba(107, 114, 128, 0.25);
  --suppressed-text: #9ca3af;
}
```

---

## 2. Typography & Hierarchy

* **Primary Font:** `Inter`, `Geist Sans`, or system `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`.
* **Monospace Font:** `JetBrains Mono`, `ui-monospace`, `Menlo`, `monospace`.
* **Scale:**
  * **24px / Bold (`letter-spacing: -0.025em`)**: Primary KPI metric numbers.
  * **15px / Semi-bold**: Actionable radar row titles / PR headers.
  * **13px / Regular**: Contextual blocker descriptions and audit text.
  * **11px / Medium / Uppercase (`letter-spacing: 0.05em`)**: Status badges, category pills, and table headers.

---

## 3. Component Style Recipes

### A. The Actionable Radar Card
```css
.radar-card {
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-left: 3px solid var(--urgent-solid);
  border-radius: 8px;
  padding: 14px 16px;
  transition: all 0.15s ease;
}
.radar-card:hover {
  background: var(--bg-surface-elevated);
  border-color: var(--border-active);
}
```

### B. KPI Stat Tile
```css
.kpi-tile {
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: 10px;
  padding: 14px 18px;
  flex: 1;
}
.kpi-tile b {
  display: block;
  font-size: 26px;
  font-weight: 700;
  color: var(--text-primary);
  letter-spacing: -0.03em;
}
.kpi-tile span {
  font-size: 12px;
  color: var(--text-muted);
}
```

### C. Semantic Status Badge
```css
.badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 11px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 9999px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.badge-urgent {
  background: var(--urgent-bg);
  color: var(--urgent-text);
  border: 1px solid var(--urgent-border);
}
.badge-warn {
  background: var(--warn-bg);
  color: var(--warn-text);
  border: 1px solid var(--warn-border);
}
.badge-ok {
  background: var(--ok-bg);
  color: var(--ok-text);
  border: 1px solid var(--ok-border);
}
```

---

## 4. Where These Tokens Actually Live

The tokens above have exactly two implementations, and both are copies of §1
verbatim. Change a value here and you must change it in both, or the surfaces
drift apart again:

| Surface | Implementation |
| --- | --- |
| Web Standup Radar console | `src/dashboard/index.html` (inline `:root`) |
| Every other HTML page ARGUS serves or generates | `src/backend/web_theme.py` |

`web_theme.py` is the single stylesheet behind the OAuth / install / claim
pages in `src/backend/app.py`, the GitHub App creation page
(`make_manifest_page.py`), and the Slack app setup page
(`make_slack_app_page.py`). It exports `CSS`, the `BRAND_SVG` radar mark,
`brandbar()`, `document()` for a full page, and `status_page()` for the
one-card outcome screens the install flow is made of.

### Status page vocabulary

Every mid-install outcome renders as one card with one pill, using the
semantic colours from §1 and nothing else:

| Kind | Card accent | Used for |
| --- | --- | --- |
| `ok` | `--ok-solid` | connected, installed, app created |
| `warn` | `--warn-solid` | already connected, not configured yet |
| `urgent` | `--urgent-solid` | expired or invalid claim token, missing token |
| `info` | `--info-solid` | in-progress / step pages |
| `muted` | `--text-muted` | the user cancelled; nothing happened |

## 5. The Same Hierarchy in Slack

Slack has no CSS, so "the same design system" there means the same
**information hierarchy**, not the same tokens. `slack_dispatcher.
compose_blocks` builds a triage DM in the exact order a radar card is drawn in
the console, using the only four tools Block Kit offers:

| Console element | Block Kit equivalent |
| --- | --- |
| Severity pill (`.badge-urgent` / `.badge-warn`) | `context` block, coloured emoji + bold label (`PATTERN_BADGE`) |
| Row title, 15px semi-bold | `section`, `*bold*` + linked item key |
| AI summary panel | `section`, `>` quote block prefixed `📝 *AI summary:*` |
| Muted metadata strip | `context` block: idle time · reviewer state · cycle deadline |
| Evidence / audit text, 13px | `context` block, `_italic_`, `sprint_filter`'s string verbatim |
| Triage buttons | `actions`, `✅ Handled offline` (primary) · `⏰ Snooze 7d` · `🚫 Blocked on…` |

Only three severity emoji are ever used — 🔴 urgent, 🟡 warn, 🔵 info —
matching the console's three accents. A fourth would be inventing a status the
dashboard cannot display.

**One constraint worth knowing before editing that function:** the number of
`section` blocks is load-bearing. `test_slack_dispatcher.py::
test_no_cached_copilot_renders_exactly_as_before` pins it at two (title, ask)
when no LLM enrichment is cached — that is the Fail-Safe Fallback Invariant's
proof. Additions to the message must therefore be `context` or `divider`
blocks, so new decoration can never masquerade as new substance.
