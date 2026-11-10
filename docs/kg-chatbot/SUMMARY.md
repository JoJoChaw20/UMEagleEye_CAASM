# Knowledge Graph Chatbot: Summary

Spec: `docs/superpowers/specs/2026-11-09-knowledge-graph-chatbot-design.md`.
Plan: `docs/superpowers/plans/2026-11-09-knowledge-graph-chatbot.md`.
Work record: `docs/kg-chatbot/DEV_LOG.md`. Test sessions: `log.txt` at the repo root.

## What was built

The dashboard chatbot now answers from a knowledge graph instead of running live lookups.

- **Graph tables** (`kg_nodes`, `kg_edges`, `kg_outbox`) in migrations `0029_knowledge_graph` and `0030_kg_outbox_claim`. Postgres triggers record every relevant change in the outbox, with the company resolved at capture time.
- **Sync** (`workers/src/kg/sync.ts`, `store.ts`, `extract.ts`, `redact.ts`). A debounced queue job applies the outbox, and a per-company drain runs before every answer. Extraction uses a per-table column allowlist, and any text matching a secret pattern is blocked. Rows with no company never enter the company layer. A bad row is isolated and set aside after 5 attempts, so it cannot block healthy rows.
- **Retrieval** (`access.ts`, `retrieve.ts`). The access filter is built on the server from the signed-in user. The model never supplies a company.
- **Problem rules** (`rules.ts`, `problems.ts`) rank what to fix first.
- **Guarded agent** (`guard.ts`, `agent.ts`). The agent classifies the question, uses only graph tools, and works within 4 rounds, 6 tool calls, 6000 characters per tool result and 12 chats per user per minute. Before an answer is released, every IP, CVE, count, advisory and host name in it is checked against what the tools returned. A failed answer is regenerated once, then replaced by "I don't know".
- **Confirm flow** (`confirm.ts`, `routes/chatbot.ts`, `frontend/src/pages/ChatbotPage.jsx`). The agent can only propose closing an advisory. A person closes it with Confirm, through a single-use token tied to that user, company and advisory.
- **Speed history** (`perf.ts`) records request and job timings in Analytics Engine and explains slow periods.
- **System layer** (`workers/scripts/kg/build-system-graph.mjs`) maps pages, routes, tables, queues and docs, and runs after `npm run deploy:staging`.
- **Old chatbot removed**: `workers/src/mcp/agent.ts`, `scripts/agent-live-demo.ts`, `scripts/debug-live-demo.ts`, and the old agent checks in `scripts/mcp-tools-demo.ts`. The MCP server tools in `workers/src/mcp/tools.ts` stay.

Unit tests: 350 pass, `tsc --noEmit` is clean, and the frontend builds.

## Staging results

Everything ran against `umeagleeye-api-staging` and the Neon `staging` branch. Two fake companies were seeded and then removed, with every check count back to zero. Nothing touched production.

**No anti-goal was violated.** No company saw another company's data, no secret reached the graph or an answer, no invented fact was released as verified, and no advisory closed without Confirm. Six concurrent confirms of one advisory produced exactly one close and one audit row.

**QA:** 59 PASS, 4 FAIL and 5 NOT RUN, counting the latest run of each scenario.

| Result | Scenarios |
|---|---|
| FAIL, cause fixed but not re-run | advisories-open and exact-counts (closed items were counted as open) |
| FAIL, fixed in code but not re-run | bottleneck (false "I don't know") |
| FAIL, unexplained | regen-bait (an empty reply) |
| NOT RUN | slow-traffic (Analytics Engine is not enabled), embedding-down (cannot be forced on staging), cross-probe-reverse, owner-close-refused and propose-cancel (the AI cap ran out) |

**AI calls:** all 200 allowed calls were used, counted as an upper bound. No further real-model chats were run after that.

**Stress at 25 users** (dashboard reads, scan ingest and graph retrieval; chat was skipped because the AI cap was spent):

| Target | Result |
|---|---|
| Retrieval p95 under 1 s | Not met as measured: 2954 ms. This was measured from a laptop in Malaysia to Neon in us-east-1, so it includes internet round trips. The Worker-side figure was not measured. |
| Error rate under 1% | Met: 0 errors in 487 requests. Only 5xx responses were counted. |
| No cross-company data | Met: none in three runs. |
| Outbox drained within 3 minutes | Met: 6 s after the burst. |

A new alert was known to the chatbot 27 seconds after ingest. False "I don't know" answers occurred on 1 of 17 distinct questions with answers in the graph, after fixes.

## Defects found on staging and fixed

1. The free plan's limit of 50 subrequests per invocation broke drains and the first chat after new data. Drain writes are now batched transactions, with a subrequest budget.
2. Question classification had too few tokens, so every question was sorted as a system question.
3. URL paths in questions were split into words, so route nodes were not found.
4. On the last round, tool-call markup was released as answer text.
5. `count_nodes` counted closed alerts and advisories as open.
6. The debounce stranded rows written after a signal. A finished drain now schedules one follow-up sweep.

The review of those fixes found that one bad row could still set aside a whole healthy batch. That is now fixed, with a budget that stops splitting before the limit. Rows it cannot reach go back unharmed.

## Not proven

- Chat under concurrent load, and regeneration on the real model.
- Fixes 5 and the bottleneck fix on the real model. Both are unit tested only.
- Two chats ended with no answer, one cut off at 17 s and one empty. The cause is unknown because `wrangler tail` showed no logs. The free plan's CPU limit is a possible cause.
- Speed history, end to end.
- The final-review changes below. They are unit tested and the Worker bundles, but no chat has run on them, because the AI cap is spent.

## Final review

A fresh reviewer read the whole change. It found no critical issue: each anti-goal was traced and none had a real path. It raised five important issues. Four were fixed and one was left for a production check.

1. **Migration order.** `0029_knowledge_graph` had an older timestamp than the teammate's `0027` and `0028`. On production, Drizzle would have skipped it, and `0030` would then fail. Its journal timestamp is now between `0028` and `0030`, and a unit test checks that the journal timestamps always increase. Staging is unaffected, because it already has `0030`.
2. **Subrequest limit.** The worst-case chat used about 59 subrequests, counting KV, Workers AI, queue, database and model calls. The limit is 50 on the free plan. Every chat now counts its requests and stops at 45. When the budget runs low, tools return an error result and the agent answers with what it has. The worst cases are now 43 and 42.
3. **General answers.** Questions about "my", "our", "we" or "this company" are no longer answered as general guidance. They take the checked, graph-based path. General answers are now checked for company-looking values: private IPs, advisory IDs, host names and counts such as "you have 14 servers".
4. **Trigger cost on bulk writes.** Not changed. Each captured row of software, dependencies and identifiers looks up its company with one indexed read inside Postgres. Measure one real agent inventory upload on staging before production.
5. **First fill after a production migration.** The migration queues every existing row with no company set, and nothing started the drain until a write or the 6-hourly cron. A chat that sees the graph is still catching up now starts the drain.

Smaller fixes: counting performance and platform-rule types is refused for company users instead of returning a false zero. Alert and advisory text no longer shows "(null)" for a device with no IP. The "stuck sync" rule now uses the real attempt limit.

Behaviour changes to know about:

- The Confirm card is offered only when the question names the advisory or its ID. "Fix 3f2a91c0" and "close the advisory on web-01" work, but "close it" alone does not.
- A general question phrased with "we" or "us", such as "tell us how XSS works", now takes the graph path and may get "I don't know".
- A general answer that uses an example private range, such as `10.8.0.0/24`, is regenerated once.

Deferred minor items: a Confirm card restored from browser storage can show an expired token; `routes/chatbot.ts` keeps its own model call for `/categorize`; the Analytics Engine dataset names are written in two places.

## What the owner needs to do

1. **Enable Analytics Engine** in the Cloudflare dashboard. Until then, `npm run deploy:staging` and any production deploy fail. Staging runs version `10c80f6c` without the speed-history binding. It was deployed from a temporary config, now deleted.
2. **Add the speed-history secrets** to read history: `npx wrangler secret put CF_ACCOUNT_ID --env staging` and `npx wrangler secret put CF_ANALYTICS_TOKEN --env staging`.
3. **Decide on more AI calls.** A targeted re-run of the 7 failed or unrun chat scenarios needs about 45 counted calls, beyond the 200 approved.
4. **Before production**, run migrations `0029` and `0030`. Note that `db:status` compares only the latest timestamp, so it can hide an older migration that never ran.
5. `npm run deploy:staging` now also needs `workers/.env.staging` and Python 3, because it rebuilds the system layer.
6. The frontend was not deployed to staging.

## Known issues outside this work

- `workers/src/routes/relationships.ts:468` does not check the target asset's company for a superadmin or a caller with no company. The graph's own filter closes the leak into chat answers.
- `frontend/src/pages/AgentsPage.jsx` on `main` uses `<Modal>` without defining it. A local fix exists but is uncommitted.
- `workers/src/mcp/external.ts` is no longer used by any route now that the old agent loop is gone.
- The developer shell's `DATABASE_URL` points at the production database. The test scripts ignore it and read only `workers/.env.staging`.

## Decisions made during the build

These are the calls made without asking, in the order they were made, each with what it costs if it was wrong.

1. Work stayed uncommitted, and reviews used snapshot commits that no branch points to. If wrong: commit normally, nothing is lost.
2. Work stayed in the current folder on `feature/kg-chatbot`, with no new worktree. If wrong: moving it is a copy.
3. The empty claim migration was filled with the claim column, with a newer timestamp so it would run. If wrong: one column on staging. (It was later renumbered `0030`.)
4. Tasks 1 to 4 were reviewed once, together. If wrong: one extra review.
5. The old agent was deleted only after staging QA, not at Task 6, because the spec says so. If wrong: dead files linger briefly.
6. Task 5 creates Confirm tokens and Task 6 uses them. If wrong: cheap to move.
7. Task 7 was allowed to edit `rules.ts` and `agent.ts` for speed-history rules. If wrong: small scope growth.
8. The system-layer script stores nodes without embeddings, and the Worker fills them in later. If wrong: keyword search works meanwhile.
9. Staging migrate and deploy waited for your approval. Cost: one question.
10. Everything after the first approved commit stayed uncommitted. If wrong: you ask for another commit.
11. Asking before staging changes stayed in force after the merge. Cost: one question.
12. The outbox records each row's company when the change happens, so a chat drains its own company first. Cost: one indexed lookup per captured row.
13. The threat-feed and sync-backlog problem rules went in Task 7, and hotspots in Task 8, because no task listed them. If wrong: small scope growth.
14. All new schema went into the one migration not yet applied. If wrong: split it later.
15. The missing company check in `routes/relationships.ts` was left alone, because the graph filter already blocks the leak. Flagged above.
16. The Confirm card's text comes from the advisory record, never from the model. If wrong: a plainer card.
17. Suggested steps are checked for IPs, CVEs, advisory IDs and host names, but not for numbers or versions. If wrong: some fix answers are refused.
18. A regeneration is one extra model call outside the 4 rounds, with no tools. Cost: one paid call per failed answer.
19. Three minor review findings were fixed because each touched an anti-goal: a refusal lifting the citation rule, a false "I closed it" claim, and a cut-off answer released as complete.
20. Suggested steps may name loopback and example addresses such as `127.0.0.1`. If wrong: one pattern to narrow.
21. A clock time without a zone is read as Malaysia time, and the answer shows both that and UTC. If wrong: one constant.
22. An empty response from Analytics Engine no longer deletes the stored speed history. Cost: small.
23. The system-layer builder was checked with a dry run, and its first real write happened in the approved staging step. If wrong: one run moves earlier.
24. The builder's pure logic lives in `src/kg/systemGraph.ts`, so the unit tests cover it. Cost: one extra file.
25. Three minor builder findings were fixed: a production-host check, `.env` path variants, and a partial scan deleting nodes.
26. `README.md` is visible only to platform staff, because it holds the production URL and deploy steps. If wrong: one line to change.
27. When the production host is unknown, the builder prints a note and carries on, so a teammate without production credentials can still deploy staging. If wrong: one line to make it fail.
28. Staging was deployed from a temporary config without the speed-history binding, because Analytics Engine is not enabled. Speed history is untested as a result.
29. Stress past the AI cap measured graph retrieval from a laptop against the staging database, not through the Worker. The figure includes internet round trips.
30. The 200 AI calls were treated as spent, and no more real-model chats were run. Some fixes stay unproven on the real model.
31. The old agent was deleted although 4 QA scenarios failed: no anti-goal failed, and nothing used it any more. If wrong: restore it from git.
32. `scripts/debug-live-demo.ts` was deleted too, because it only drove the old agent. If wrong: restore it from git.
33. `workers/src/mcp/external.ts` was kept although nothing in the Worker uses it now. If wrong: one unused file.
34. Six minor findings in the Task 9 fixes were fixed because each was a regression or touched an anti-goal.
35. The bottleneck and stated-date fixes were made although neither can be proven on the real model. If wrong: no worse than before.
36. A fresh implementer did the Task 9 fixes instead of the original one. Cost: re-reading the code.
37. The `0029` migration timestamp was moved between `0028` and `0030`. If wrong: a database that has `0029` applied but whose latest applied migration is older than `0029`'s new timestamp would try to run `0029` again and fail. Only staging has `0029` today, and it is safe.
38. Every call to KV, Workers AI, queues, the database and the model counts as a subrequest, and a chat stops at 45. If wrong: some chats lose a lookup they could have afforded.
39. Questions about "my", "our" or "we" never get the unverified general path. If wrong: some general questions get a graph answer or "I don't know".
40. The cost of the trigger's company lookup on bulk inventory writes was not changed. Measure it on staging before production.
41. A chat that sees the graph catching up starts the drain, and the migrations stayed unchanged. If wrong: the first fill waits for a chat or a write.
42. Four more minor final-review findings were fixed: false zeros for company users, the Confirm card offered on "how do I resolve CVE...", "(null)" in alert text, and the stuck-sync limit.
