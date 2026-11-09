# Knowledge Graph Chatbot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the chatbot with one that answers from a per-company and system knowledge graph, recommends fixes, and is proven on staging.

**Architecture:** Graph tables in Neon (`kg_nodes`, `kg_edges`, `kg_outbox`). Postgres triggers fill the outbox, a debounced queue message and a pre-answer drain apply it. A guarded tool loop in `workers/src/kg/agent.ts` uses only graph tools and releases an answer after verification.

**Tech Stack:** Cloudflare Workers, Hono, Drizzle (raw SQL for graph), Neon Postgres + pgvector, Workers AI embeddings, Analytics Engine, DeepSeek/OpenRouter, React.

**Spec:** `docs/superpowers/specs/2026-11-09-knowledge-graph-chatbot-design.md`

## Global Constraints

- Staging only: every test script refuses a target other than staging. No production deploy or migration.
- Never store: `.env*`, password hashes, TOTP secrets, API key hashes, enrolment tokens, `audit_logs`.
- Extraction is a per-table column allowlist. A secret-pattern match blocks the chunk.
- Rows with NULL tenant are excluded from the company layer.
- Access filter is built on the server from the user. The model never supplies a tenant.
- Limits: 4 rounds, 6 tool calls, 6000 chars per tool result, 12 chats per user per minute.
- No new timers. Paid AI calls capped at 200 per test run.
- Do not touch `frontend/src/pages/AgentsPage.jsx`.
- Record work in `docs/kg-chatbot/DEV_LOG.md`, test sessions in `log.txt`, the outcome in `docs/kg-chatbot/SUMMARY.md`.
- The user did not ask for commits: leave work uncommitted for review.

## Review Focus

- Very long or empty questions: validated at the route (1 to 1000 chars), no crash. (Task 5)
- Backlog larger than one drain batch: answer carries a "still catching up" note, not silent staleness. (Task 2, 5)
- Model returns malformed JSON or tool arguments: tool error is fed back, the request survives. (Task 5)
- Confirm token reused or used by another user: refused. (Task 6)
- Embedding service down: nodes still stored and found by keyword. (Task 2, 3)

---

### Task 1: Migration and bindings

**Files:** Create `workers/drizzle/0027_knowledge_graph.sql` (via `drizzle-kit generate --custom`). Modify `workers/wrangler.toml`, `workers/src/types.ts`.

**Produces:** tables `kg_nodes(key text pk, tenant_id uuid null, visibility text, role_group text, type text, title text, body text, props jsonb, source_ref text, embedding vector(768), tsv tsvector generated, updated_at)`, `kg_edges(from_key, to_key, relation, tenant_id, props, pk(from_key,to_key,relation))`, `kg_outbox(table_name, row_pk, changed_at, pk(table_name,row_pk))`. Function `kg_capture()`. Env adds `AI`, `PERF`, `CF_ACCOUNT_ID?`, `CF_ANALYTICS_TOKEN?`.

Triggers: insert-or-delete only on `asset_software`, `dependencies`, `asset_identifiers`, `posture_metrics`; changed-column conditions on `agents`, `asset_addresses`, `events`, `scan_results`; all changes on the rest. `event_cti_indicators` records its `events` row.

- [ ] Generate, fill, `npm run db:migrate:staging`. Expected: `db:status:staging` shows no pending, `to_regclass('kg_nodes')` set.

### Task 2: Extraction and sync

**Files:** Create `workers/src/kg/redact.ts`, `extract.ts`, `store.ts`, `sync.ts`, tests `extract.test.ts`, `redact.test.ts`. Modify `queues/consumer.ts`, `cron/triggers.ts`, `index.ts`.

**Produces:** `containsSecret(s): boolean`; `extractAsset|Event|...(row, ctx): GraphDelta`; `drainOutbox(db, env, limit=500): Promise<{processed, remaining, tenants}>`; `signalKgSync(env): Promise<void>` (KV key `kg:sync:signal`, TTL 120 s, queue delay 30 s).

Tests assert: a row's `api_key_hash`, `password_hash`, `totp_secret` never reach output; `tenant_id` NULL gives no node; secret text is blocked; advisory inherits its event's asset tenant; CVE nodes are keyed per tenant.

### Task 3: Retrieval

**Files:** Create `workers/src/kg/access.ts`, `retrieve.ts`, tests `access.test.ts`.

**Produces:** `accessFor(user, tenantId): Access`; `accessSql(a)`; `searchGraph(db, env, a, q, limit)`; `getNode`, `followLinks(db, a, key, depth<=2, budget)`, `countNodes(db, a, {type, where, groupBy})`.

Tests assert: tenant user never gets `platform`; business_owner only role_group `all`; superadmin without tenant gets shared only; a tenant-less non-superadmin gets nothing.

### Task 4: Problem rules

**Files:** Create `workers/src/kg/rules.ts`, `problems.ts`, test `rules.test.ts`.

**Produces:** `evaluateRules(facts, now): ProblemNode[]`, `refreshProblems(db, tenantId)`.

Tests: each rule fires on a matching fact and stays silent otherwise; ranking puts internet-facing critical first.

### Task 5: Guarded agent

**Files:** Create `workers/src/kg/guard.ts`, `agent.ts`, test `guard.test.ts`. Rewrite the POST route in `routes/chatbot.ts`.

**Produces:** `classify(ai, q): 'system'|'fix'|'general'|'neither'`, `verifyAnswer(text, evidence, kind): string[]`, `runGraphAgent(ctx, q, history, emit)`.

Tests: an invented IP, CVE or count fails; present ones pass; list markers are ignored; for `fix`, only "What we found" is checked; a failed answer regenerates once and then gives the refusal.

### Task 6: Confirm flow and removal of old chatbot

**Files:** Modify `routes/chatbot.ts`, `frontend/src/pages/ChatbotPage.jsx`, `workers/src/mcp/tools.ts` header. Delete `workers/src/mcp/agent.ts`, `workers/scripts/agent-live-demo.ts`, and agent use in `workers/scripts/mcp-tools-demo.ts`.

**Produces:** `POST /chatbot/confirm {token}`. Quick buttons and advisory sessions send natural questions. Sources render under answers.

Verify: `npm run build` in `frontend`, `npx tsc --noEmit` in `workers`.

### Task 7: Performance history

**Files:** Create `workers/src/kg/perf.ts`, test `perf.test.ts`. Modify `db/client.ts`, `index.ts`, `queues/consumer.ts`, `cron/triggers.ts`.

**Produces:** `perfMiddleware`, `recordJob(env, name, ms, ok)`, `normalisePath(p)`, `buildWindows(rows)`, `refreshPerf(db, env)`.

Tests: a path with an id or IP records no value; window flags slowness and its coinciding jobs.

### Task 8: System layer builder

**Files:** Create `workers/scripts/kg/build-system-graph.mjs`, `py_outline.py`. Modify `package.json` `deploy:staging`.

Verify: run for staging; node count per type printed; zero chunks stored from `.env*`; secret scan count reported.

### Task 9: Test and record

**Files:** Create `workers/scripts/kg/seed-test.mjs`, `qa.mjs`, `stress.mjs`, `lib.mjs`.

Deploy to staging, seed two test companies, run every QA scenario in the spec, then stress at 1, 5, 10, 25 users. Append each session to `log.txt`. Fix what fails, re-run, keep failures in the log. Remove test data afterwards.

### Task 10: Review and summary

- [ ] Fresh reviewer on the whole change. Fix findings. Write `docs/kg-chatbot/SUMMARY.md`.
