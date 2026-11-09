# Knowledge Graph Chatbot: Development Log

Newest entries at the bottom. Dates are 2026-11-09 unless stated.

## Planning

- Design approved by owner: `docs/superpowers/specs/2026-11-09-knowledge-graph-chatbot-design.md`.
- Plan written: `docs/superpowers/plans/2026-11-09-knowledge-graph-chatbot.md`.
- Staging preflight: wrangler logged in, 8 staging secrets present, Neon staging branch has no pending migrations.
- Owner did not ask for commits, so all work is left uncommitted for review.

## Task 2: extraction and sync, finished

- Fixed the 14 type errors in `workers/src/kg/` with real guards or zero defaults for empty query results (no `!`, no `any`).
- Wrote migration `0030_kg_outbox_claim.sql` (adds `kg_outbox.claimed_until`; no index, the claim query already uses the `changed_at` index). Set its journal `when` to 1794230000000 so drizzle does not skip it after staging's last applied migration. Not run.
- Added `redact.test.ts` (secret columns never reach any extractor's output, each secret pattern is blocked, a blocked node drops its edges) and `sync.test.ts` (which API requests ask for a sync; written first, seen failing, then implemented).
- Wiring: the queue consumer handles `kg_sync` on the advisory queue (failure retries, advisory jobs unaffected); the 6-hourly drift-audit cron runs a sync as its own isolated step; a small middleware in `index.ts` signals after successful POST/PUT/PATCH/DELETE, skipping heartbeats, chat and auth. Signals never throw and never come from the `kg_sync` job itself. No new cron or timer. Wiring is to be checked on staging.

## Fix round 1 (Tasks 1-4 review), extraction and sync part

- C1: the relationship source query now keeps only pairs where both devices belong to the same company, and the extractor refuses a pair whose target company differs. Other sources join labels only from their own asset, so they needed no change.
- I1: `clip` no longer cuts inside an emoji, and every string is made well-formed before it is written. The outbox counts attempts per claim and sets a row aside after 5. A failing batch is retried row by row, so one bad row cannot block the others. The job requeues itself only when it applied something, and `remaining` counts only claimable rows.
- I2: the company of a deleted row is read before the delete, and every drain refreshes the companies it touched, not only when the outbox is empty.
- I3, I7: migration 0030 adds triggers for asset merges (software, dependencies, identifiers, alerts and their advisories) and for occurrences, gateway address and MAC changes. It also adds `kg_outbox.tenant_id`, resolved when the change is captured and never able to fail a business write. `drainOutbox` takes an optional company.
- I4: the secret scan now catches unquoted values, any `scheme://user:pass@`, Bearer tokens and a key name followed by 64 hex. It runs on the whole field before the length cut. Objects under allowed alert keys are no longer copied.
- I5: refresh also removes indicators no alert points at. I-count: more than 6 filters is an error.

## Task 5: guarded agent

- Added `workers/src/kg/guard.ts`: `classify` sorts a question into system, fix, general or neither, and anything it cannot read counts as system. `verifyAnswer` lists every IP, CVE ID, hostname, advisory ID and number that the retrieved content does not support. List markers and citation markers are ignored. A digit inside a retrieved IP or CVE does not support a count. For fix answers, everything except "Suggested steps" is checked, and an answer with no "What we found" label is checked whole.
- Added `workers/src/kg/agent.ts`: the six graph tools, the limits (4 rounds, 6 tool calls, 6000 characters per result), the pre-answer sync for the company, the regenerate-once-then-"I don't know" step, and the single-use proposal token in `KV_CACHE`. The token never goes to the model, and a refused answer deletes its proposal.
- Each tool result gets a reference such as S1. The model cites it as [S1], an invented citation fails verification, and the final event lists only the cited sources.
- Tool results and the browser's history go to the model marked as untrusted data, with `<` escaped so the data cannot close its own tag.
- Rewrote the POST `/` handler in `routes/chatbot.ts`. The typed commands are gone, so `fix <id>` is an ordinary question and cannot close an advisory. `/categorize` is unchanged. `mcp/agent.ts` stays on disk and is no longer used by the route.
- Until Task 6 ships, the Confirm button on the chat page still sends `fix <id>`, which now does nothing to the advisory.
- Not run against staging: the agent is unit tested with a fake model and a fake query function only.

## Fix round 1 (Task 5 review)

- Dates and clock times are now compared whole and no longer feed the number set, so a timestamp cannot support a count. Answers that quote a retrieved date or time, including forms like "9 November 2026" or "2:05 PM", still pass.
- The verifier now reads underscore emphasis, full-width digits, "zero", "a dozen", and "hundred" or "thousand" as multipliers.
- "Suggested steps" is now checked for IP addresses, CVE IDs, advisory IDs and host-like values. Plain numbers, versions, documentation and local addresses, and the words of commands in code blocks are left alone. "What we found" must come first and hold something.
- Digit-free hostnames are checked after the words host, hostname, device, server, asset and workstation, using a stoplist of ordinary following words, and all-caps hyphenated names are checked too.
- The text on the Confirm card is now built on the server from the advisory row. The tool no longer takes a reason from the model.
- `propose_resolve_advisory` is offered only when the user's own question asks to close an advisory. Server code decides this from the question text alone.
- `count_nodes` and `list_problems` now return an error, not a citable zero, for types the caller cannot see.
- An uncited answer must be a plain refusal. An answer claiming the assistant closed an advisory is rejected. A model reply that ends without `stop` or `tool_calls` is treated as cut off.

## Task 6: Confirm flow and chat page

- Added `POST /chatbot/confirm {token}` in `routes/chatbot.ts`. The logic is in `kg/confirm.ts` with injected KV and query pieces, tested in `kg/confirm.test.ts` (10 tests). It reads the token, refuses another user's token without deleting it, re-checks the role with `ADVISORY_STATUS_ROLES` and the company, then closes the advisory with one statement that only matches an active advisory in the user's company and writes the audit record (`advisory_status_update`, new state `resolved` via `chatbot`) in the same statement. Zero rows means already handled, so nothing is audited. The token is deleted after the attempt, except when the database call itself failed, so the person can retry. The route signals a graph sync itself, because the signal middleware skips `/chatbot`.
- `ChatbotPage.jsx`: Confirm calls the endpoint and shows the result in the chat, is disabled while pending and cannot be double clicked. Cancel hides the card with no request. The card label is now "Advisory". Sources (title and type) show under answers as plain text. Errors, including the question limit message, show in a red box. The old response types and typed-command handling are gone, quick buttons and the Advisories "Debug with AI" session send ordinary questions, and the two copies of the stream reader became one. A superadmin gets a company picker in the header, because typed commands no longer prompt for one.
- Updated the header of `mcp/tools.ts`: it no longer claims the chatbot uses it. The old agent files stay until after staging.
- Not run against staging: the confirm SQL is checked by unit tests with a fake query function only.

## Task 7: Performance history

- New `kg/perf.ts`. `perfMiddleware` (first middleware after the logger in `index.ts`) writes one Analytics Engine data point per API request: route pattern from Hono's matched routes, status, total ms and database ms. A route nothing matched is recorded as `unmatched`. `normalisePath` is the fallback and turns ids, IPs, hostnames and MACs into `:id` or `:ip`. Failures are recorded too, including a thrown handler. A missing `PERF` binding or a throwing write never touches the request.
- Database wait is kept per request with `AsyncLocalStorage` (`nodejs_compat` is on). `db/client.ts` sets `neonConfig.fetchFunction` once so every Neon query adds the time to its response to the running request. Concurrent queries in one request add up, so the share is capped at 100%. This measures time until the response arrives, not the body read.
- `recordJob` and `timedJob` record queue jobs (`queues/consumer.ts`), the drift audit and each cron step (`cron/triggers.ts`).
- `buildWindows` makes one summary per hour. A route is flagged slow at an average of 1000 ms or more over at least 5 requests. `refreshPerf` posts SQL to the Analytics Engine SQL API (staging reads `umeagleeye_perf_staging`, otherwise `umeagleeye_perf`), stores `performance_window` nodes (platform visibility, no tenant) for the last 14 days and removes older ones. Without `CF_ACCOUNT_ID` and `CF_ANALYTICS_TOKEN` it logs once and returns. A failed call returns `ok: false` and changes nothing.
- `rules.ts` gained `evaluatePlatformRules`: route persistently slow (3 or more hours), error spike (20 or more requests and 20% server errors), slowness in the same hour as a job or scan request (worded as timing, not cause), threat feed failing (from the feed health record in KV), graph sync backlog (200 or more `kg_outbox` rows, or the oldest older than 60 minutes; every row counts). `refreshPlatformProblems` in `problems.ts` stores and removes them, touching only its own rules so code hotspots in Task 8 are safe.
- The 6-hourly cron runs `perf-refresh` after `kg-sync`, as its own isolated step. `agent.ts` runs the same refresh before answering a speed question from a user who may see platform content, then adds the limits and the range of recorded history as notes, and tells the model to say there is no history for a time no window covers.
- Not run on staging. The `CF_ANALYTICS_TOKEN` secret (Account Analytics Read) and `CF_ACCOUNT_ID` must be set before any history is pulled. The SQL (`toStartOfInterval`, `if`, `_sample_interval`) follows Cloudflare's docs but has not been run against a real dataset.

### Task 7 fix round 1

- The pre-answer performance refresh is bounded. The Analytics call has an abort timer of 5 seconds (a plain `setTimeout` with `AbortController`, because `AbortSignal.timeout` timers do not keep a Node test alive). The whole refresh in `agent.ts` is raced against an 8 second deadline, and is skipped when the newest window node was written under 5 minutes ago. A timed-out or failed refresh adds the existing "could not be refreshed" note.
- Times: window times stay UTC. The notes and the model prompt now say so, give the current UTC time, and treat a bare clock time as Malaysia time (UTC+8) unless the user says UTC. `resolveAskedTime` and `askedTimeNote` in `perf.ts` map the time asked to its hour and say covered, outside the range, or a gap, which reads as no history. Gaps inside the recorded range are listed.
- The SQL now orders newest first (`ORDER BY bucket DESC`). At the 10000-row limit it logs, leaves out the possibly partial oldest hour, and deletes nothing.
- Windows are only deleted when they are older than 14 days, never because a pull did not contain them, and never after an empty or truncated pull.

## Task 8: System layer builder

- New `workers/scripts/kg/build-system-graph.mjs` (with `py_outline.py`) builds the shared layer from `git ls-files`: 537 tracked files, of which 3 `.env*` example files are skipped without being named, 69 are recorded by name only (lockfiles, drizzle meta, data, binaries, fixtures) and 465 are parsed. TypeScript and JSX go through the TypeScript compiler API, Python through `ast` (`python -I`, falling back to `python3`, with a clear failure if neither runs).
- It produces file, page, route, table, queue, cron, class, function, doc, technique, tactic, cwe and problem nodes (1861 in the dry run) and 3692 edges (imports, tests, route to table and service, page to route, migration to table, queue and cron links). 155 frontend API calls matched a route; 1 did not. Routes get their full `/api/v1` path from the mounts in `index.ts`.
- All keys start with `system:`, `tenant_id` is NULL and `role_group` is `analyst`. README, PRODUCT, AGENT_SETUP_GUIDE, the agent-gui README and the install notes, plus the ATT&CK and CWE reference data, are `all_staff`; everything else is `platform`. The 1385 CWE entries are grouped 20 to a node (70 nodes) to keep the embedding count down; 1199 nodes will need an embedding.
- Hotspots use their own rules, `code_hotspot_large_file` (900 lines or more) and `code_hotspot_shared_module` (12 or more importing files), so `PLATFORM_RULES` in `problems.ts` is untouched. A package `__init__.py` is not counted. The dry run found 19.
- A rerun deletes only keys starting with `system:` that are no longer built, and refuses to prune when fewer than 200 nodes were built. The write uses `upsertNodes` and `replaceEdges` from `kg/store.ts` with no AI binding, so a node whose text did not change keeps its embedding and new ones wait for `backfillEmbeddings`, which has no tenant filter and so reaches NULL-tenant nodes (it only embeds the types in `EMBEDDED_TYPES`: `class`, `function`, `queue`, `cron` and `tactic` are found by keyword only).
- Only `staging` is accepted as the target. `deploy:staging` now runs the build after the deploy; `deploy` is unchanged. Pure rules are in `kg/systemGraph.ts` with 13 tests (`systemGraph.test.ts`). The database write path was not run; only `--dry-run` was.
