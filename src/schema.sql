-- ARGUS — normalised entity and event model
-- Phase 2.1 · 2026-08-19 · Decisions D-006, D-014, D-020, D-057, D-061..D-064
--
-- Source-agnostic by design (D-006): no GitHub vocabulary appears in a table or
-- column name. GitHub-specific identifiers live in the *_source_key columns and
-- in source_payload, which the adapter fills and nothing downstream reads.
--
-- All timestamps are ISO-8601 UTC strings ('YYYY-MM-DDTHH:MM:SSZ'), which sort
-- and compare correctly as text in SQLite and stay human-readable in the file.
--
-- Extended Phase 6.1 · 2026-08-21 · Decision D-110 — sections 11-12 add
-- Jira/Linear ticket and Slack-triage entities for Part II. Sections 1-10
-- above are Phase 2's frozen GitHub model and are UNCHANGED by this
-- extension: no existing table, column, or constraint was edited. New
-- entities reuse `source`, `project`, `actor`, and `fetch` rather than
-- duplicating them, which is what D-006's source-agnostic design was
-- built to allow.
--
-- Amended Phase 6.3 · 2026-08-21 · Decision D-113 — `ticket.status_category`
-- and `ticket_status_event.to_status_category` gained a 'canceled' value,
-- discovered while building the Linear adapter (Linear's WorkflowState.type
-- genuinely distinguishes canceled/duplicate work from completed work;
-- Jira's three-category model never surfaced this gap at 6.2). Sections
-- 1-10 remain untouched; this is section 11's own CHECK constraint being
-- widened, not a new table.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- ---------------------------------------------------------------------------
-- 1. Provenance: where data came from and when we looked
-- ---------------------------------------------------------------------------

CREATE TABLE source (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,          -- 'github'
    base_url        TEXT NOT NULL
);

-- A snapshot is one immutable read of one project at one moment (D-064).
-- Every clock in the model is measured against observed_at, never wall-clock
-- now(), so re-running Phase 3 against an old snapshot reproduces its numbers.
CREATE TABLE snapshot (
    id              INTEGER PRIMARY KEY,
    source_id       INTEGER NOT NULL REFERENCES source(id),
    project_id      INTEGER NOT NULL,              -- FK added logically; project is created below
    observed_at     TEXT NOT NULL,                 -- the reference "now" for this snapshot
    started_at      TEXT NOT NULL,
    completed_at    TEXT,                          -- NULL until the run finishes cleanly
    is_complete     INTEGER NOT NULL DEFAULT 0,    -- 0 = partial/aborted; Phase 3 must refuse these
    tool_version    TEXT,
    notes           TEXT
);

-- Every fetch attempt, including the ones that failed (D-063).
-- This table is what makes step 2.4's reliability measurement a query.
CREATE TABLE fetch (
    id              INTEGER PRIMARY KEY,
    snapshot_id     INTEGER NOT NULL REFERENCES snapshot(id),
    url             TEXT NOT NULL,
    purpose         TEXT NOT NULL,                 -- 'item_page' | 'search' | 'label_list' | 'closed_sample'
    attempt         INTEGER NOT NULL,              -- 1 = first try; >1 = a retry
    tool            TEXT NOT NULL,                 -- 'tavily_extract' etc.
    requested_at    TEXT NOT NULL,
    duration_ms     INTEGER,
    outcome         TEXT NOT NULL
                    CHECK (outcome IN ('ok','failed','corrupt','empty')),
    http_status     INTEGER,
    error_detail    TEXT
);
CREATE INDEX ix_fetch_snapshot   ON fetch(snapshot_id);
CREATE INDEX ix_fetch_url        ON fetch(snapshot_id, url);
CREATE INDEX ix_fetch_outcome    ON fetch(snapshot_id, outcome);

-- ---------------------------------------------------------------------------
-- 2. Core entities
-- ---------------------------------------------------------------------------

CREATE TABLE project (
    id              INTEGER PRIMARY KEY,
    source_id       INTEGER NOT NULL REFERENCES source(id),
    source_key      TEXT NOT NULL,                 -- 'apache/airflow'
    display_name    TEXT NOT NULL,
    uses_work_items INTEGER NOT NULL DEFAULT 1,    -- D-015: repos that route to Discussions are blind
    UNIQUE (source_id, source_key)
);

-- An actor is anyone or anything that acts. kind is the *account-level* read;
-- the per-event human decision lives on event.counts_as_human (D-062).
CREATE TABLE actor (
    id              INTEGER PRIMARY KEY,
    source_id       INTEGER NOT NULL REFERENCES source(id),
    source_key      TEXT NOT NULL,                 -- login
    display_name    TEXT,
    kind            TEXT NOT NULL
                    CHECK (kind IN ('human','bot','unknown')),
    kind_reason     TEXT NOT NULL
                    CHECK (kind_reason IN ('suffix_bot','known_bot_list','profile_flag',
                                           'assumed_human','unresolved')),
    person_id       INTEGER,                       -- cross-source identity; unused in the MVP
    UNIQUE (source_id, source_key)
);

CREATE TABLE work_item (
    id                  INTEGER PRIMARY KEY,
    snapshot_id         INTEGER NOT NULL REFERENCES snapshot(id),
    project_id          INTEGER NOT NULL REFERENCES project(id),
    source_number       INTEGER NOT NULL,          -- issue/PR number
    kind                TEXT NOT NULL
                        CHECK (kind IN ('issue','change_request')),
    title               TEXT NOT NULL,
    body                TEXT,
    state               TEXT NOT NULL
                        CHECK (state IN ('open','closed','merged')),
    is_draft            INTEGER NOT NULL DEFAULT 0,      -- H8
    author_id           INTEGER REFERENCES actor(id),
    created_at          TEXT NOT NULL,
    closed_at           TEXT,
    milestone_id        INTEGER,                          -- FK below
    url                 TEXT NOT NULL,
    -- Stored for one purpose only: reporting how far GitHub's clock drifts from
    -- the human clock. NEVER used to compute silence (D-014).
    source_updated_at   TEXT,
    fetch_id            INTEGER REFERENCES fetch(id),
    source_payload      TEXT,                             -- raw JSON, adapter-only
    UNIQUE (snapshot_id, project_id, source_number)
);
CREATE INDEX ix_item_project ON work_item(snapshot_id, project_id, state);
CREATE INDEX ix_item_created ON work_item(snapshot_id, project_id, created_at);

-- ---------------------------------------------------------------------------
-- 3. The event log — the spine of the model (D-061)
-- ---------------------------------------------------------------------------

CREATE TABLE event (
    id                  INTEGER PRIMARY KEY,
    snapshot_id         INTEGER NOT NULL REFERENCES snapshot(id),
    work_item_id        INTEGER NOT NULL REFERENCES work_item(id),
    type                TEXT NOT NULL CHECK (type IN (
                            'opened','closed','reopened','commented',
                            'review_submitted','review_requested','review_request_removed',
                            'assigned','unassigned','labeled','unlabeled',
                            'milestoned','demilestoned','committed','force_pushed',
                            'ready_for_review','converted_to_draft','renamed',
                            'referenced','cross_referenced','reacted','other')),
    actor_id            INTEGER REFERENCES actor(id),
    -- The person the event was done *to* (assigned-to, review-requested-of).
    subject_actor_id    INTEGER REFERENCES actor(id),
    occurred_at         TEXT,                             -- NULL only when date_precision='unknown'
    date_precision      TEXT NOT NULL DEFAULT 'exact'
                        CHECK (date_precision IN ('exact','at_or_before','unknown')),  -- D-039
    -- The human decision, made per event and not per actor (D-062).
    counts_as_human     INTEGER NOT NULL DEFAULT 0,
    human_reason        TEXT NOT NULL CHECK (human_reason IN (
                            'human','bot_account','ai_drafted_footnote',
                            'automation_event','unknown_actor')),
    detail              TEXT,
    fetch_id            INTEGER REFERENCES fetch(id)
);
CREATE INDEX ix_event_item        ON event(work_item_id, occurred_at);
CREATE INDEX ix_event_item_human  ON event(work_item_id, counts_as_human, occurred_at);
CREATE INDEX ix_event_actor       ON event(work_item_id, actor_id, counts_as_human, occurred_at);
CREATE INDEX ix_event_type        ON event(work_item_id, type, occurred_at);

-- ---------------------------------------------------------------------------
-- 4. Conversation
-- ---------------------------------------------------------------------------

CREATE TABLE comment (
    id                  INTEGER PRIMARY KEY,
    event_id            INTEGER NOT NULL REFERENCES event(id),
    work_item_id        INTEGER NOT NULL REFERENCES work_item(id),
    actor_id            INTEGER REFERENCES actor(id),
    created_at          TEXT,
    body                TEXT NOT NULL,
    authorship          TEXT NOT NULL CHECK (authorship IN
                            ('human','bot','ai_drafted_under_human_account')),   -- D-057
    has_question_mark   INTEGER NOT NULL DEFAULT 0                              -- S-06
);
CREATE INDEX ix_comment_item ON comment(work_item_id, created_at);

-- Extracted once at ingest so nine detectors do not each re-parse prose (§3.5).
CREATE TABLE mention (
    id                  INTEGER PRIMARY KEY,
    comment_id          INTEGER NOT NULL REFERENCES comment(id),
    work_item_id        INTEGER NOT NULL REFERENCES work_item(id),
    mentioned_actor_id  INTEGER REFERENCES actor(id),   -- S-06 route
    mentioned_team      TEXT,                           -- S-09 route
    in_code_or_quote    INTEGER NOT NULL DEFAULT 0,     -- declared S-06 false positive
    CHECK (mentioned_actor_id IS NOT NULL OR mentioned_team IS NOT NULL)
);
CREATE INDEX ix_mention_item ON mention(work_item_id);

-- ---------------------------------------------------------------------------
-- 5. Review
-- ---------------------------------------------------------------------------

CREATE TABLE review (
    id              INTEGER PRIMARY KEY,
    event_id        INTEGER NOT NULL REFERENCES event(id),
    work_item_id    INTEGER NOT NULL REFERENCES work_item(id),
    actor_id        INTEGER REFERENCES actor(id),
    state           TEXT NOT NULL CHECK (state IN
                        ('approved','changes_requested','commented','dismissed')),
    submitted_at    TEXT
);
CREATE INDEX ix_review_item ON review(work_item_id, submitted_at);

-- Requested party is EITHER an individual (S-04) or a team (S-09), never coerced.
-- origin='codeowners' does not count as a promise (D-043).
CREATE TABLE review_request (
    id              INTEGER PRIMARY KEY,
    work_item_id    INTEGER NOT NULL REFERENCES work_item(id),
    actor_id        INTEGER REFERENCES actor(id),
    team            TEXT,
    requested_by    INTEGER REFERENCES actor(id),
    requested_at    TEXT,
    removed_at      TEXT,
    origin          TEXT NOT NULL DEFAULT 'manual'
                    CHECK (origin IN ('manual','codeowners','unknown')),
    CHECK (actor_id IS NOT NULL OR team IS NOT NULL)
);
CREATE INDEX ix_revreq_item ON review_request(work_item_id, requested_at);

-- ---------------------------------------------------------------------------
-- 6. Ownership, labels, milestones — all stored as intervals, not current state
-- ---------------------------------------------------------------------------

CREATE TABLE assignment (
    id              INTEGER PRIMARY KEY,
    work_item_id    INTEGER NOT NULL REFERENCES work_item(id),
    actor_id        INTEGER NOT NULL REFERENCES actor(id),
    assigned_at     TEXT,
    unassigned_at   TEXT,                                  -- D-049's bulk sweep is visible here
    assigned_by     INTEGER REFERENCES actor(id),
    is_automatic    INTEGER NOT NULL DEFAULT 0             -- H9
);
CREATE INDEX ix_assign_item ON assignment(work_item_id, assigned_at);

CREATE TABLE label (
    id                      INTEGER PRIMARY KEY,
    project_id              INTEGER NOT NULL REFERENCES project(id),
    name                    TEXT NOT NULL,
    description             TEXT,
    -- Per-project vocabulary (§3.2). Proposed by rule, confirmed by a human.
    classification          TEXT NOT NULL DEFAULT 'unclassified'
                            CHECK (classification IN
                                ('blocker','healthy_slowness','triage_only',
                                 'neither','unclassified')),
    classification_status   TEXT NOT NULL DEFAULT 'proposed'
                            CHECK (classification_status IN ('proposed','confirmed')),
    classified_at           TEXT,
    UNIQUE (project_id, name)
);

CREATE TABLE work_item_label (
    id              INTEGER PRIMARY KEY,
    work_item_id    INTEGER NOT NULL REFERENCES work_item(id),
    label_id        INTEGER NOT NULL REFERENCES label(id),
    applied_at      TEXT,                                  -- S-02's clock starts here
    applied_by      INTEGER REFERENCES actor(id),          -- S-02's named next actor
    removed_at      TEXT
);
CREATE INDEX ix_wil_item  ON work_item_label(work_item_id);
CREATE INDEX ix_wil_label ON work_item_label(label_id);

CREATE TABLE milestone (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES project(id),
    title           TEXT NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('open','closed')),
    due_on          TEXT,
    closed_at       TEXT,                                  -- H2 expiry is a comparison, not a guess
    UNIQUE (project_id, title)
);

-- ---------------------------------------------------------------------------
-- 7. Relationships between items
-- ---------------------------------------------------------------------------

CREATE TABLE reference (
    id                  INTEGER PRIMARY KEY,
    from_work_item_id   INTEGER NOT NULL REFERENCES work_item(id),
    to_project_key      TEXT NOT NULL,                     -- resolved even when unfetched
    to_work_item_id     INTEGER REFERENCES work_item(id),  -- NULL when the target is outside the snapshot
    to_number           INTEGER,
    relation            TEXT NOT NULL CHECK (relation IN
                            ('blocks','blocked_by','closes','closed_by',
                             'linked_pr','mentions','duplicate_of','unknown')),
    is_cross_project    INTEGER NOT NULL DEFAULT 0,        -- D-050: must never be read as local activity
    detected_at         TEXT
);
CREATE INDEX ix_ref_from ON reference(from_work_item_id, relation);
CREATE INDEX ix_ref_to   ON reference(to_work_item_id);

-- ---------------------------------------------------------------------------
-- 8. Mechanical readiness — three-valued on purpose (D-031/D-037/D-042)
-- ---------------------------------------------------------------------------

CREATE TABLE readiness (
    work_item_id    INTEGER PRIMARY KEY REFERENCES work_item(id),
    merge_state     TEXT NOT NULL DEFAULT 'unknown'
                    CHECK (merge_state IN ('clean','blocked','unknown')),
    checks_state    TEXT NOT NULL DEFAULT 'unknown'
                    CHECK (checks_state IN ('clean','blocked','unknown')),
    cla_state       TEXT NOT NULL DEFAULT 'unknown'
                    CHECK (cla_state IN ('clean','blocked','unknown')),
    evidence_note   TEXT                                   -- the quote D-042 asks us to find
);

-- ---------------------------------------------------------------------------
-- 9. What we could not see
-- ---------------------------------------------------------------------------

CREATE TABLE evidence_gap (
    id              INTEGER PRIMARY KEY,
    snapshot_id     INTEGER NOT NULL REFERENCES snapshot(id),
    work_item_id    INTEGER REFERENCES work_item(id),      -- NULL for project-level gaps
    gap_type        TEXT NOT NULL CHECK (gap_type IN (
                        'timeline_not_rendered','timeline_truncated','event_without_date',
                        'fetch_failed','content_corrupt','actor_unresolved')),
    detail          TEXT,
    detected_at     TEXT NOT NULL
);
CREATE INDEX ix_gap_item ON evidence_gap(work_item_id);
CREATE INDEX ix_gap_snap ON evidence_gap(snapshot_id, gap_type);

-- ---------------------------------------------------------------------------
-- 10. The clocks — views, never stored columns
-- ---------------------------------------------------------------------------

-- Last human activity on an item, and how many days ago that was measured
-- against the snapshot's observed_at (D-064, not wall-clock now).
-- is_lower_bound is set when any human event on the item lacked an exact date
-- (D-039) — the true silence can only be longer, never shorter.
CREATE VIEW v_item_clock AS
SELECT
    w.id                                        AS work_item_id,
    s.observed_at                               AS observed_at,
    MAX(e.occurred_at)                          AS last_human_at,
    CAST(julianday(s.observed_at) - julianday(MAX(e.occurred_at)) AS INTEGER)
                                                AS days_silent,
    MAX(CASE WHEN e.date_precision <> 'exact' THEN 1 ELSE 0 END)
                                                AS is_lower_bound,
    COUNT(*)                                    AS human_event_count
FROM work_item w
JOIN snapshot s ON s.id = w.snapshot_id
LEFT JOIN event e
       ON e.work_item_id = w.id
      AND e.counts_as_human = 1
      AND e.occurred_at IS NOT NULL
GROUP BY w.id;

-- The same clock, per person per item. This is D-020, and it is the reason the
-- event log exists: S-03 watches the author, S-04 the requested reviewer,
-- S-05 the assignee, S-06 the mentioned person.
CREATE VIEW v_actor_item_clock AS
SELECT
    e.work_item_id                              AS work_item_id,
    e.actor_id                                  AS actor_id,
    s.observed_at                               AS observed_at,
    MAX(e.occurred_at)                          AS last_action_at,
    CAST(julianday(s.observed_at) - julianday(MAX(e.occurred_at)) AS INTEGER)
                                                AS days_silent,
    MAX(CASE WHEN e.date_precision <> 'exact' THEN 1 ELSE 0 END)
                                                AS is_lower_bound
FROM event e
JOIN work_item w ON w.id = e.work_item_id
JOIN snapshot s  ON s.id = w.snapshot_id
WHERE e.counts_as_human = 1
  AND e.occurred_at IS NOT NULL
  AND e.actor_id IS NOT NULL
GROUP BY e.work_item_id, e.actor_id;

-- Does this item's evidence have holes? Phase 3 reports these separately rather
-- than blending them, exactly as Phase 1 did with evidence_gap: true.
CREATE VIEW v_item_confidence AS
SELECT
    w.id                                        AS work_item_id,
    COUNT(g.id)                                 AS gap_count,
    GROUP_CONCAT(DISTINCT g.gap_type)           AS gap_types,
    CASE WHEN COUNT(g.id) = 0 THEN 'high' ELSE 'low' END AS confidence
FROM work_item w
LEFT JOIN evidence_gap g ON g.work_item_id = w.id
GROUP BY w.id;

-- ---------------------------------------------------------------------------
-- 11. Phase 6 — Jira / Linear: sprint status as a filter, not a new detector
-- ---------------------------------------------------------------------------
-- A ticket is Jira/Linear's unit of work, and it is deliberately NOT folded
-- into `work_item` even though both are "a unit of work with a lifecycle"
-- (§3 of the Phase 2.1 data model). Two reasons: `work_item.kind` is a closed
-- CHECK ('issue','change_request') that step 6.1 was told not to touch, and a
-- ticket carries a concept work_item never needed — sprint membership. A
-- `project` row stands for a Jira project or a Linear team, the same reuse
-- the source-agnostic design already intended for a non-GitHub source.

-- A sprint (Jira) or cycle (Linear), generically named. state is the
-- source's own three-valued read; ARGUS never infers it from dates alone.
CREATE TABLE sprint (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES project(id),
    source_key      TEXT NOT NULL,                 -- Jira sprint id / Linear cycle id
    name            TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'unknown'
                    CHECK (state IN ('future','active','closed','unknown')),
    starts_at       TEXT,
    ends_at         TEXT,
    UNIQUE (project_id, source_key)
);

-- status_category is the normalised read step 6.4's filter actually uses
-- ('backlog' items are auto-suppressed); source_status is kept verbatim
-- alongside it for the same reason label.name and label.classification are
-- both kept in Phase 2 — so a wrong mapping is auditable, not silently
-- trusted. sprint_id NULL means backlog / no active sprint, not "unknown".
--
-- 'canceled' added at step 6.3 (D-113): Jira's three built-in status
-- categories fold "won't do" work into 'done' (there is no separate
-- native bucket for it), so 6.2 never needed this value. Linear's
-- WorkflowState.type is a genuine seven-value enum that DOES distinguish
-- 'canceled' (and 'duplicate', folded into this same bucket by the Linear
-- adapter — see docs/PHASE6_3_LINEAR_ADAPTER.md) from 'completed'.
-- Silently mapping a canceled Linear issue to 'done' would tell step
-- 6.4's filter — and eventually a human reading the standup digest —
-- that abandoned work was successfully finished, which is a real
-- precision problem for a project whose whole job is not saying that.
-- Extending this CHECK is safe: section 11 is Claude's own Phase 6.1
-- addition (not one of Phase 2's frozen 1-10 sections), no real ticket
-- data has been loaded against the tighter constraint yet, and every
-- Phase 6.2 Jira fixture ticket's status_category is unaffected (none of
-- them used a value this change removes).
CREATE TABLE ticket (
    id                  INTEGER PRIMARY KEY,
    source_id           INTEGER NOT NULL REFERENCES source(id),   -- 'jira' | 'linear'
    project_id          INTEGER NOT NULL REFERENCES project(id),
    source_key          TEXT NOT NULL,                 -- 'ENG-123'
    title               TEXT NOT NULL,
    ticket_type         TEXT NOT NULL DEFAULT 'unknown'
                        CHECK (ticket_type IN ('story','bug','task','epic','subtask','unknown')),
    source_status       TEXT NOT NULL,                 -- verbatim column/state name, e.g. 'In Review'
    status_category     TEXT NOT NULL DEFAULT 'unknown'
                        CHECK (status_category IN
                            ('backlog','ready','in_progress','in_review','done','canceled','unknown')),
    sprint_id           INTEGER REFERENCES sprint(id),
    assignee_actor_id   INTEGER REFERENCES actor(id),
    created_at          TEXT NOT NULL,
    -- Same caution as work_item.source_updated_at (D-014): the source's own
    -- clock, kept for reporting drift only. NEVER used to compute silence.
    source_updated_at   TEXT,
    fetch_id            INTEGER REFERENCES fetch(id),
    source_payload      TEXT,                          -- raw JSON, adapter-only
    UNIQUE (source_id, project_id, source_key)
);
CREATE INDEX ix_ticket_project ON ticket(project_id, status_category);
CREATE INDEX ix_ticket_sprint  ON ticket(sprint_id);

-- A dated log of status transitions, mirroring `event`'s own reasoning
-- (D-061): the current status is a query over this log's latest row, not a
-- mutable column, so a future clock ("days in Backlog", "days since last
-- status move") is free later without a migration. changed_at is nullable
-- because not every source API exposes a changelog date for every
-- transition; a NULL here is the ticket-side equivalent of work_item's
-- date_precision='unknown' and should be named as an evidence_gap by
-- whichever step (6.2/6.3) first ingests one, not silently dropped.
CREATE TABLE ticket_status_event (
    id                  INTEGER PRIMARY KEY,
    ticket_id           INTEGER NOT NULL REFERENCES ticket(id),
    from_status         TEXT,                          -- NULL on the first-seen row
    to_status           TEXT NOT NULL,
    to_status_category  TEXT NOT NULL
                        CHECK (to_status_category IN
                            ('backlog','ready','in_progress','in_review','done','canceled','unknown')),
    changed_at          TEXT,
    fetch_id            INTEGER REFERENCES fetch(id)
);
CREATE INDEX ix_tse_ticket ON ticket_status_event(ticket_id, changed_at);

-- The join step 6.4's filter runs across: which GitHub work item does this
-- ticket correspond to. Many-to-one is allowed in both directions on
-- purpose (one PR can carry two ticket keys in a squash-merged branch; one
-- epic ticket can span several PRs) — confidence lets the filter later
-- decide whether a 'low' link is trusted alone or needs a second signal.
CREATE TABLE ticket_link (
    id                  INTEGER PRIMARY KEY,
    ticket_id           INTEGER NOT NULL REFERENCES ticket(id),
    work_item_id        INTEGER NOT NULL REFERENCES work_item(id),
    link_method         TEXT NOT NULL
                        CHECK (link_method IN
                            ('smart_commit','branch_name','pr_title_key','api_link','manual')),
    confidence          TEXT NOT NULL DEFAULT 'high'
                        CHECK (confidence IN ('high','medium','low')),
    detected_at         TEXT NOT NULL,
    UNIQUE (ticket_id, work_item_id)
);
CREATE INDEX ix_tlink_item   ON ticket_link(work_item_id);
CREATE INDEX ix_tlink_ticket ON ticket_link(ticket_id);

-- ---------------------------------------------------------------------------
-- 12. Phase 6 — Slack: the install, PTO/presence, and the 1-click triage DM
-- ---------------------------------------------------------------------------
-- `integration` is deliberately generic (source-agnostic, same reasoning as
-- §11's reuse of `project`) rather than a Slack-only "workspace" table: a
-- Jira/Linear OAuth install and a Slack app install are the same shape —
-- one external account, one set of granted scopes, one place the real
-- credential lives. credential_ref is a POINTER (a file path on Dirgh's own
-- machine, e.g. 'secrets/slack_bot_token.txt') never the secret itself,
-- the same discipline D-087 set for the Anthropic API key: no credential is
-- ever written into this database or into a tracked doc.
CREATE TABLE integration (
    id                      INTEGER PRIMARY KEY,
    source_id               INTEGER NOT NULL REFERENCES source(id),  -- 'jira' | 'linear' | 'slack'
    project_id              INTEGER REFERENCES project(id),          -- NULL: a workspace-level install not yet tied to one project
    external_account_id     TEXT NOT NULL,             -- Jira site id / Linear workspace id / Slack team id
    display_name            TEXT,
    scope                   TEXT,                      -- OAuth scopes granted, verbatim
    credential_ref          TEXT NOT NULL,
    installed_at            TEXT NOT NULL,
    revoked_at              TEXT,
    UNIQUE (source_id, external_account_id)
);

-- Which Slack account is the same person as this GitHub/Jira/Linear actor.
-- Step 6.6 needs this and cannot proceed without it: a triage DM sent to the
-- wrong person is worse than no DM at all. D-110 flagged that actor.person_id
-- exists but is unpopulated; this table is the narrow, Slack-only piece of
-- that gap, solved for the one case 6.6 actually needs rather than solving
-- cross-source identity in general (still open, still D-110's).
--
-- resolved_via records HOW the match was made, because the three ways differ
-- in how much they should be trusted, and a later step must be able to tell
-- them apart rather than treating every row as equally certain.
-- 'unresolved' rows are written deliberately: a failure to identify somebody
-- is a fact worth storing, so the digest can report "we had an alert for
-- @someone and could not find them in Slack" instead of staying silent.
CREATE TABLE slack_identity (
    id              INTEGER PRIMARY KEY,
    integration_id  INTEGER NOT NULL REFERENCES integration(id),
    actor_id        INTEGER NOT NULL REFERENCES actor(id),
    slack_user_id   TEXT,                          -- NULL only when resolved_via='unresolved'
    matched_email   TEXT,
    resolved_via    TEXT NOT NULL
                    CHECK (resolved_via IN ('manual_map','email_lookup','unresolved')),
    resolved_at     TEXT NOT NULL,
    UNIQUE (integration_id, actor_id),
    CHECK (slack_user_id IS NOT NULL OR resolved_via = 'unresolved')
);
CREATE INDEX ix_slackid_actor ON slack_identity(actor_id);

-- Out-of-office / PTO, stored as an interval like assignment and
-- work_item_label rather than a single "is_ooo" flag, so 6.7's suppression
-- check can be asked "were they OOO at send time" for any historical
-- message, not just "are they OOO right now".
CREATE TABLE presence (
    id              INTEGER PRIMARY KEY,
    actor_id        INTEGER NOT NULL REFERENCES actor(id),
    status          TEXT NOT NULL CHECK (status IN ('available','out_of_office','unknown')),
    detected_via    TEXT NOT NULL DEFAULT 'unknown'
                    CHECK (detected_via IN ('slack_status','calendar_sync','manual','unknown')),
    effective_from  TEXT NOT NULL,
    effective_to    TEXT,                              -- NULL = open-ended / still in effect
    detected_at     TEXT NOT NULL
);
CREATE INDEX ix_presence_actor ON presence(actor_id, effective_from);

-- One row per 1-click triage DM sent. external_message_ts is Slack's own
-- message id and is required (not just recorded) because updating the
-- message in place after a button click needs it. Points at EITHER a
-- work_item or a ticket (a flagged GitHub item or a flagged Jira/Linear
-- ticket), never neither.
CREATE TABLE triage_message (
    id                      INTEGER PRIMARY KEY,
    integration_id          INTEGER NOT NULL REFERENCES integration(id),
    work_item_id            INTEGER REFERENCES work_item(id),
    ticket_id               INTEGER REFERENCES ticket(id),
    sent_to_actor_id        INTEGER NOT NULL REFERENCES actor(id),
    -- Both NULL for a row that records a DM we deliberately never sent
    -- (status 'suppressed_presence'). Widened at step 6.7, D-117: 6.1
    -- reserved that status but made these columns NOT NULL, so the row it
    -- was reserved for could not physically be written. They stay required
    -- for every message that really exists, enforced by the CHECK below,
    -- because updating a message in place after a button click needs them.
    external_channel_id     TEXT,                      -- Slack DM channel id
    external_message_ts     TEXT,
    sent_at                 TEXT NOT NULL,
    snooze_until            TEXT,                      -- set once a 'snooze_7d' response lands
    status                  TEXT NOT NULL DEFAULT 'sent'
                            CHECK (status IN
                                ('sent','responded','expired','suppressed_presence','failed')),
    suppressed_reason       TEXT,                      -- e.g. points at the presence.id that caused a 'suppressed_presence' status
    CHECK (work_item_id IS NOT NULL OR ticket_id IS NOT NULL),
    CHECK (status = 'suppressed_presence'
           OR (external_channel_id IS NOT NULL AND external_message_ts IS NOT NULL))
);
CREATE INDEX ix_triagemsg_item   ON triage_message(work_item_id);
CREATE INDEX ix_triagemsg_ticket ON triage_message(ticket_id);
CREATE INDEX ix_triagemsg_actor  ON triage_message(sent_to_actor_id, status);

-- The three buttons from step 6.6, stored as a typed response rather than
-- free text alone, so the digest (6.8) can count "N handled offline" without
-- parsing prose. blocked_on_text is the only field that carries free text,
-- and only when response_type = 'blocked_on'.
CREATE TABLE triage_response (
    id                  INTEGER PRIMARY KEY,
    triage_message_id   INTEGER NOT NULL REFERENCES triage_message(id),
    response_type       TEXT NOT NULL
                        CHECK (response_type IN ('handled_offline','blocked_on','snooze_7d')),
    blocked_on_text     TEXT,
    responded_at        TEXT NOT NULL,
    raw_payload         TEXT                            -- Slack's interaction payload, adapter-only
);
CREATE INDEX ix_triageresp_msg ON triage_response(triage_message_id);
