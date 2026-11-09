# Knowledge Graph Chatbot: Development Log

Newest entries at the bottom. Dates are 2026-11-09 unless stated.

## Planning

- Design approved by owner: `docs/superpowers/specs/2026-11-09-knowledge-graph-chatbot-design.md`.
- Plan written: `docs/superpowers/plans/2026-11-09-knowledge-graph-chatbot.md`.
- Staging preflight: wrangler logged in, 8 staging secrets present, Neon staging branch has no pending migrations.
- Owner did not ask for commits, so all work is left uncommitted for review.

## Task 2: extraction and sync, finished

- Fixed the 14 type errors in `workers/src/kg/` with real guards or zero defaults for empty query results (no `!`, no `any`).
- Wrote migration `0028_kg_outbox_claim.sql` (adds `kg_outbox.claimed_until`; no index, the claim query already uses the `changed_at` index). Set its journal `when` to 1794230000000 so drizzle does not skip it after staging's last applied migration. Not run.
- Added `redact.test.ts` (secret columns never reach any extractor's output, each secret pattern is blocked, a blocked node drops its edges) and `sync.test.ts` (which API requests ask for a sync; written first, seen failing, then implemented).
- Wiring: the queue consumer handles `kg_sync` on the advisory queue (failure retries, advisory jobs unaffected); the 6-hourly drift-audit cron runs a sync as its own isolated step; a small middleware in `index.ts` signals after successful POST/PUT/PATCH/DELETE, skipping heartbeats, chat and auth. Signals never throw and never come from the `kg_sync` job itself. No new cron or timer. Wiring is to be checked on staging.
