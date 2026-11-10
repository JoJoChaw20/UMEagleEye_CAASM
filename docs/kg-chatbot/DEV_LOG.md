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

## Task 9: Staging QA and stress

- New scripts in `workers/scripts/kg/`: `lib.mjs` (target guard, AI budget counter, SSE chat client, `log.txt` writer that masks credential shapes), `seed-test.mjs` (two fake KGTEST- companies, removal with verification), `qa.mjs` (every scenario in the spec's Testing section), `stress.mjs` (1, 5, 10 and 25 users). Passwords and agent keys live in an OS temp file, never in the repo or `log.txt`.
- Real defects found by running on staging, each fixed with a unit test first and then redeployed:
  - The Workers free plan allows 50 subrequests per run. A drain of 78 rows took 73, so the first chat after data changed failed outright with "The assistant failed", and queue drains would never have finished. `drainOutbox` and `refreshProblems` now read and write through one batched Neon transaction (`store.ts` `runBatch`, one subrequest). A poison row is isolated by splitting the write in half, instead of one retry per row. A drain now costs about 7 subrequests instead of 73.
  - Every question was sorted as `system`: `classify` allowed 10 tokens and the model spends its tokens reasoning before the label, so the reply was empty. `general`, `fix` and `neither` never fired. Now 1024 tokens.
  - A URL path in a question was split into separate words, but it is one token in the index, so `search_graph` never found the route node. `keywordQuery` now searches the whole path and its parts.
  - On the last round (no tools offered) the model wrote its tool call out as text, and the guards released it. The last round now says no more lookups are available, and text with tool-call markup is regenerated, then refused.
  - `count_nodes` gave no hint which filter means "open", so "open alerts" counted closed ones too. The tool description now names `open` and `active`.
  - The signal's debounce is leading-edge, so writes after the signalled job ran got no signal and their rows stranded until the next write. A finished drain now schedules one sweep after the debounce window; an idle sweep stops the chain. A row written with no signal was applied in 131 seconds.
- Results, per-scenario detail and what is unproven are in `.superpowers/sdd/2026-11-09-knowledge-graph-chatbot/task-9-report.md`, and every session is in `log.txt`.

### Task 9 fix round 1

- A row whose extractor throws, or whose read fails, now fails alone. The others are applied, and a row that could not be extracted or read is never taken for a deleted row. A failed read splits the same way a failed write does.
- Splitting has a budget. A queue drain uses at most 18 requests and a chat drain at most 12, finish included. Rows the budget does not reach, and rows caught by a "Too many subrequests" error, get their claim released and their attempt returned, so they cannot be quarantined that way. Every `kg_sync` message in a queue batch now shares one run, placed after the batch's other jobs.
- A signalled job always ends in one sweep, even if it found nothing or went on to fill embeddings. A sweep that applies nothing ends the chain, so idle and poison rows cannot keep it running. Sweeps and continuations carry `followUp`, and a continuation that still owes a sweep carries `owesSweep`.
- `embedChanged` embeds each key once. Nodes and edges are written in key order, so two drains cannot deadlock on shared keys.
- Tool-call markup found verbatim in the evidence no longer triggers a regeneration, so a banner cannot change the agent's behaviour.
- The system prompt now says that questions about problems, bottlenecks, hotspots, risks or weak points must call `list_problems`. This was not proven on the real model, because the approved AI calls are spent.
- `resolveAskedTime` reads dates such as `3 March 2026`, `March 3 2026` and `2026-03-03`, with an optional year. A date it cannot read gives null instead of today.
- `qa.mjs`: `notFailed` needs a non-empty answer, and `bottleneck` refuses "I don't know". The script was edited and not run.

## Task 10: final review fixes

- Migration `0029_knowledge_graph` had a journal timestamp older than `0027` and `0028`, so Drizzle would skip it on a database that already has those two, and `0030` would then fail. Its `when` is now `1794220000000`, between `0028` and `0030`. No SQL file and no other timestamp changed. A new test (`src/db/journal.test.ts`) checks that timestamps rise with the index.
- A chat now stays within 45 subrequests, counting every KV call, Workers AI call, queue send, Neon query or batch, model call and analytics fetch, plus 3 for the route (rate-limit read and write, and the speed-history data point). Everything the agent does goes through a counter that holds 3 back for the final answer, one regeneration and removing a refused proposal. When a lookup would eat into those, tools are no longer offered and a tool call gets an error result, so the answer is always written. The chat drain's budget went from 12 to 8, and `refreshPlatformProblems` reads in one batch and writes in one batch. The dearest chat measured 59 subrequests before and 43 after (superadmin speed question), and 47 before and 42 after (tenant admin with a proposal).
- A question that refers to the user's own organisation ("our", "we", "my", "us", "this company") is never answered as general guidance, even when the classifier says general. A general answer is checked before release and regenerated once, then refused, if it holds a private address, an advisory ID, a host-like name, or a count of the user's things such as "you have 14 servers". CVE IDs and public facts still pass.
- When the pre-answer drain leaves rows behind, the chat signals the global sync (debounced in KV), so the rows `0029` seeds with no company are applied without waiting for a write or the cron.
- A company user can no longer count platform-only records (speed history, code records, or problems of the platform and hotspot rules), so a meaningless zero cannot be cited. A close verb now proposes a closure only in a sentence that names an advisory or an advisory ID, so "how do I resolve CVE-2024-1234 on web-01" does not; a bare "close it" no longer does either. An alert on an asset with no IP no longer prints "(null)". A stuck outbox row now means one set aside after `MAX_ATTEMPTS` (5) failed claims.
- 367 unit tests pass and `tsc --noEmit` is clean. Nothing was deployed or run against a database or the model.

## Hand-off

- Final staging deploy: version `10c80f6c` (no speed-history binding), system layer rebuilt (1945 nodes, 3837 edges, 0 `.env` files stored, 0 secret blocks). Health check 200, chat without a login 401, outbox empty. No chat was run, because the AI cap is spent.
- The temporary config `workers/.wrangler-staging-noperf.toml` was deleted.
- Outcome and every decision made along the way: `docs/kg-chatbot/SUMMARY.md`.

## Manual staging test, 2026-11-10

- The staging frontend was an old build (Pages deploy from `6cc6337`), not this branch. Its Confirm button sent the chat message `fix <advisory_id>` instead of calling `POST /chatbot/confirm`, so "Confirm" produced fix steps and closed nothing. Advisory `007b4173` stayed open with 0 audit rows.
- A fix answer copied the section instructions into its headings ("## What we found: facts about this company from the tool results only, each cited."). `FIX_FORMAT` had each heading and its instruction on one line. The headings now stand alone and the instructions (`FOUND_HINT`, `STEPS_HINT` in `guard.ts`) are separate lines. `stripFormatEcho` cuts a copied instruction back to the bare heading before checking, so a copied instruction cannot count as the content of What we found.
- Typing "confirm" got the off-topic reply. `isTypedConfirmation` now catches a bare "confirm" (and "yes", "ok", "go ahead" right after an answer that asked for Confirm) and replies, with no model call, that typing closes nothing and the Confirm button on the card does.
- 378 unit tests pass and `tsc --noEmit` is clean. Staging Worker redeployed as version `fa3ef30e` (no speed-history binding, Analytics Engine is still not enabled; the temporary config was deleted). Staging frontend redeployed from this branch.
- The first frontend redeploy pointed at `http://localhost:8000/api/v1`: the developer shell exports `VITE_API_URL`, which beats `.env.staging`. Rebuilt with the shell `VITE_*` variables unset; the live bundle now calls the staging API and CORS passes.
- Not fixed: the fix answer cited [S1] for "proposed for resolution but not yet closed", which came from the chat history, not the advisory. The guard checks values, not claims like this.

## Confirm checks the latest scan, 2026-11-10

- Confirm used to close an advisory whatever the scans said: it only changed the record. Now an advisory is closed from the chat only when no alert for the same problem on that device is still open. Scans own that alert: drift, exposure, patch and indicator checks close it when the problem is gone, and an SBOM scan closes a CVE alert when the CVE is no longer present.
- `kg/detection.ts` holds the one check (`sameProblemOpen`): same device, same alert type, status `open` or `in_progress`, and the same identifying details (`port`, `cve_id`, `rule`, `changed_attribute`, `package_name`, `indicator_value`, `key`). It includes the advisory's own alert and a newer duplicate it was merged into.
- The proposal tool checks it in the same advisory lookup query (no extra subrequest). A problem still detected gets no Confirm card, and the agent is told why. The Confirm statement checks it again in the same SQL statement as the update, so a problem that reappears between proposal and click is still refused. The audit row now records `last_scanned` and `last_sbom`.
- The refusal names the device and the relevant scan time: the network scan for ports and other scan findings, the latest SBOM for a CVE, and for a new device how its alert closes (My Assets, an owner, or an EagleEye agent).
- The SQL was checked on the staging database with `EXPLAIN` (planned, never run) and a read-only run of the lookup. In Home Network, 11 of 12 open advisories are still detected (10 CVE, 1 new device), so only `281ab6b4` (port 445 on JoJochaw, alert already closed) can be closed from the chat.
- Advisories whose alert is closed are already resolved by the nightly sweep (`resolveAdvisoriesOfClosedEvents`), which does not run on staging because staging has no crons. That is why `007b4173` and `281ab6b4` stayed open there.
- Not changed: the status control on the Advisories page does not check scans.
- 388 unit tests pass and `tsc --noEmit` is clean. Staging Worker version `2079d1c3` (no speed-history binding).

### Refused closes are answered in the server's words

- On staging, a platform superadmin with no company picked asked "Please close advisory 281ab6b4." and got "I don't know". The proposal tool refused (role), the model explained, and verification refused the explanation: error results are not evidence, so any wording that names the advisory, device or scan time fails. The still-detected refusal had the same flaw.
- A role that cannot close advisories (anything but `tenant_superadmin` and `tenant_admin`) is now told "Your role cannot close advisories. Only an admin of the company (tenant admin or tenant superadmin) can close one from the chat." When the message only asks to close an advisory (`onlyAsksToClose`, politeness aside), that is the whole answer, with no model call. When it also asks something else, the rest is answered, the close tool is not offered, and the refusal is a note on top.
- A refusal from the proposal tool (not found, ambiguous ID, not an ID, still detected) is kept as `closeRefusal` and released as the server's text: the whole answer for a message that only asks to close, otherwise a note on the answer.
- 398 unit tests pass and `tsc --noEmit` is clean. Staging Worker version `b2dfa1b8` (no speed-history binding).

## Chatbot moved to a floating bubble, 2026-11-10

- The Chatbot page and its sidebar entry are gone. The assistant is a bubble in the bottom-right corner (`frontend/src/components/chat/ChatWidget.jsx`, moved from `pages/ChatbotPage.jsx` with `git mv`), rendered once by `MainLayout`, so a chat and an answer still streaming survive page changes.
- The bubble opens a 400 x 640 panel above it (a Make larger button widens it to 760 x 860); on a phone the panel fills the screen. The header shows the chat name, the number of chats (click for the chats list, which opens over the conversation), New chat, Clear, Make larger and Close. A superadmin's company picker is a row under the header. Quick questions are a scrolling row of chips above the input in the General chat. Escape closes the chats list, then the panel.
- The bubble shows an amber dot while an answer is being written with the panel closed, and a green dot when it finished unseen.
- `ChatbotContext` holds `widgetOpen` and `pendingAdvisory`. "Debug with AI" on the Advisories page calls `openAdvisoryChat`, which opens the panel on that advisory's chat. The command palette action opens the panel. An old `/chatbot` link opens the panel over the dashboard.
- Pages get bottom padding (`pb-24`) so their last row is never under the bubble.
- Checked in a temporary local preview with a mocked API (desktop dark and light, and a 390 px phone frame), then removed. Staging frontend redeployed; the live bundle calls the staging API.

## Assistant panel docked on the right, full screen when expanded, 2026-11-11

- The bubble now opens a full-height panel on the right edge, 420 px wide, sliding in from the right (`panel-slide`). The bubble is hidden while the panel is open (it sat over the input); focus goes back to it when the panel closes. The `chat-rise` animation was removed.
- From 1280 px wide, `MainLayout` adds a 420 px right margin while the panel is open, so the page sits beside the chat instead of under it. Below that the panel overlays the page; on a phone it fills the screen as before.
- The expand button (Full screen / Exit full screen) makes the panel cover the whole app (`z-[55]`, above the sidebar). The conversation, chips, input, company picker and chats list keep a readable width (about 52rem) in the middle. Escape closes the chats list, then leaves full screen, then closes the panel. Closing the panel resets full screen.
- The panel header is 64 px tall, so its bottom border lines up with the app header.
- Checked in a temporary local preview with a mocked API (1440 px docked in dark and light, 1100 px overlay, full screen), then removed. Staging frontend redeployed; the live bundle calls the staging API.
- Full screen shows the chats list as a fixed left column (288 px, `SessionList` with `sidebar`), the conversation to its right. The header title is then only a title (no chats toggle). In the docked panel the list still opens over the conversation from the title. Checked in the same kind of temporary preview (full screen dark and light, docked list), then removed; staging redeployed.
