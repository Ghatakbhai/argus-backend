# ARGUS

### Autonomous engineering coordination & real-time stall radar.

ARGUS is a continuous blocker radar for high-velocity software teams. It connects GitHub, Jira, Linear, and Slack to identify delivery bottlenecks before they derail your sprints.

---

## Why we built this

Most engineering teams run into the same frustration every sprint:
1. **Pull requests sit approved for days** because nobody knows who has the final sign-off.
2. **Reviews stall in silence** when an engineer gets pulled into an incident or goes on PTO.
3. **Standups waste 25 minutes** going around the room reciting status updates instead of solving blockers.

Existing tools don't solve this. Jira and Linear show what was *planned*, not where code is physically stuck. DORA dashboards give you retrospective charts about last month, which doesn't help you unblock a PR this morning. And daily standup bots force developers to fill out tedious text forms that everyone ignores.

We built ARGUS around a simple principle: **Management by Exception**. 

ARGUS runs silently in the background, suppresses normal in-flight development, and only surfaces the few items that actually require human intervention.

---

## How it works

ARGUS fuses activity across your engineering stack into a single real-time model:

```
 GitHub PR Activity ──┐
 Jira / Linear Scope  ├──► [ ARGUS Engine ] ──► 9:00 AM Standup Blocker Digest
 Slack Presence / PTO ┘
```

### 1. Real-Time Stall Detection
ARGUS tracks two high-friction failure modes:
* **Approved but Unmerged**: Pull requests that passed CI and received all required approvals, but sit unmerged in an active sprint.
* **Ghosted Reviews**: PRs where a review was explicitly requested, but the reviewer has been inactive on the thread.

### 2. Built-in Noise Suppression
Alert fatigue kills developer trust. ARGUS runs multiple filtering stages before sending any notification:
* **Sprint Awareness**: Automatically ignores backlog tickets, draft PRs, and work not scheduled for the current sprint.
* **Absence & PTO Checks**: Senses when an engineer is on vacation or away and stops sending them review reminders.
* **Smart Throttling**: Limits proactive pings and escalates cleanly to the tech lead if something remains stuck.

### 3. 1-Click Slack Micro-Triage
When a genuine stall occurs, ARGUS sends a single private DM to the responsible engineer with 1-click resolution buttons:
* `[Handled Offline]` — Resolves the alert immediately without requiring extra Git commits.
* `[Blocked on X]` — Lets the developer name the external blocker (e.g., *Waiting on Legal* or *Staging pipeline down*).
* `[Snooze]` — Pauses alerts for long-running architectural changes.

### 4. 9:00 AM Executive Radar
Every morning before standup, Tech Leads and Engineering Managers receive a concise digest outlining:
* **Explicit Blockers**: PRs where developers identified cross-team dependencies.
* **PTO Bottlenecks**: Reviews stalled behind an absent engineer, allowing instant reassignment.
* **Unresponsive Items**: PRs that need manual lead intervention.

---

## Our Engineering Approach to AI

We don't believe in using AI where simple code works better. 

ARGUS uses a **hybrid architecture**:
1. **Deterministic Core (95% of operations)**: High-speed, rule-based pipeline checks that evaluate Git state, sprint boundaries, and PTO status in milliseconds with zero token cost and zero hallucination risk.
2. **Targeted Semantic Intelligence (5% of operations)**: Small, fast micro-inference passes used strictly for human intent extraction—such as translating messy, free-form developer chat into structured blocker reasons and drafting crisp 1-sentence summaries for the morning digest.

This gives engineering leads high-precision operational intelligence while keeping the system lightweight, deterministic, and dependable.

---

## Security & Architecture

ARGUS is built for enterprise security and multi-tenant isolation:

* **PostgreSQL Row-Level Security (RLS)**: Physical database-kernel isolation ensures one team can never query or access another team's data.
* **Read-Only Scope**: The ARGUS GitHub App requires strictly read-only permissions (Pull Requests, Issues, Metadata). It cannot edit code, merge branches, or alter your repository.
* **At-Rest Token Encryption**: All third-party OAuth credentials and bot tokens are encrypted at rest using AES-256 (Fernet) with out-of-band key management.
* **HMAC Request Signatures**: Inbound webhooks from GitHub and Slack are verified against raw byte-stream SHA-256 signatures before processing.

---

## Status

ARGUS is currently in a private pilot with select engineering teams.

* **Supported Integrations**: GitHub, Jira Cloud, Linear, Slack.
* **Deployment**: 1-click install via GitHub App and Slack OAuth.

---

<div align="center">
  <sub>© 2026 ARGUS. All rights reserved.</sub>
</div>
