# Knowledge Graph Chatbot: Design

Date: 2026-11-09
Status: awaiting approval

## Intent

UMEagleEye is used by individual small and medium companies, internally. Their IT staff need
one place to ask anything about their environment and about UMEagleEye itself, and to be told
what to fix next. Today's chatbot (`workers/src/mcp/agent.ts`) does a few live lookups per
question (6 at most), knows only security records, and struggles with connected questions.

The new chatbot replaces it. It answers from a knowledge graph: a prepared map of the
company's data and of how the system is built, with the links between them.

## Decided by the project owner

1. The current chatbot is removed and replaced, not extended.
2. Questions about the system or the company's data are answered only from the knowledge
   graph. A fact not in the graph gets "I don't know", never a guess.
3. One exception: general security questions (for example "how do I harden SSH?") may be
   answered from the model's own training.
4. The chatbot can propose closing an advisory. Nothing closes until a person presses Confirm.
5. It recommends solutions for both kinds of problem: the company's security problems and
   problems in UMEagleEye itself.
6. Users are one company's own staff. Each company sees only its own devices, alerts and
   advisories.
7. A new alert must reach the chatbot within a few minutes.
8. The graph updates when something new arrives, not on a short timer, so the database can
   sleep when nothing is happening.
9. Testing is QA and stress testing of the whole system, simulating real use, with each
   session recorded in `log.txt`. There is no A/B test.
10. All testing runs on staging only.
11. The chatbot can explain past slowness, such as "why was the site slow at 3pm?".
    UMEagleEye does not record this today, so recording it is part of this work.
12. Company staff get how-to guides and problems in their own setup. Only the UMEagleEye team
    (`superadmin`) can ask about code details and UMEagleEye's internal problems.
13. Fix advice may use the model's training for the steps, clearly separated: facts about the
    company come only from the graph, and the steps are labelled as general guidance.
14. The typed commands (`status`, `assets`, `alerts`, `advisories`, `posture`, `debug`, `fix`,
    `mcp`) are removed. Everything goes through the graph. The quick buttons and the Advisories
    page fix-session button stay, and send normal questions.

Settled by the designer and shown to the owner:

- Only the Confirm button can close an advisory. Today, typing `fix <id>` closes one
  immediately, and the Confirm button works by sending that text. This is replaced.
- Counts and lists are exact and complete, never computed from a partial retrieval.
- A `superadmin` must pick one company before asking about company data.
- `business_owner` users stay limited to overall status and security score.

## Goals

- A knowledge graph holding the system's data and information.
- A retrieval (RAG) pipeline over the graph.
- One agent acting as general chatbot and solution recommender, with guardrails.
- QA and stress results recorded in `log.txt`.

## Non-goals

- Production rollout. Work stops at staging. Promoting to production follows the steps in
  `STAGING.md` and is the owner's separate decision.
- New actions beyond proposing to resolve an advisory.
- Changes to the MCP server (`workers/src/routes/mcp.ts`). It is a separate way in for
  external tools and stays, along with `workers/src/mcp/tools.ts`, which it uses.

## Anti-goals: failure even if it technically works

- One company sees another company's data, in any answer or citation.
- A secret reaches the graph or an answer.
- An invented IP address, CVE, count or advisory presented as fact.
- Text inside collected data (a hostname, a banner) makes the agent change its behaviour.
- Any test touches production data.
- An advisory closes without a person's confirmation.

## Constraints

- Backend: Cloudflare Workers, Hono, Drizzle, Neon Postgres. Queues, KV and R2 already exist.
- The Postgres database is shared with a teammate. Migrations are applied by hand on purpose.
  Check the schema before applying, and apply to the staging branch only.
- Unit tests run with `npm test` in `workers/` (pure logic only). Worker routes are checked
  on staging.
- `frontend/src/pages/AgentsPage.jsx` has unrelated uncommitted work. Leave it alone.

## How it works

### 1. Storage (builder's choice, stated to the owner)

New Postgres tables, no new database:

- `kg_nodes`: id, `tenant_id` (NULL means shared system knowledge), `visibility` (`company`,
  `all_staff` for product docs and how-to knowledge, `platform` for code details and internal
  problems), `min_role_group` (`business_owner` nodes are status and score only), type, stable
  source key, title, text, JSON properties, source reference, embedding (pgvector), full-text column,
  updated time. Unique on tenant, type and source key.
- `kg_edges`: from, to, relation type, `tenant_id`, properties.
- `kg_outbox`: the list of changed records waiting to be applied to the graph.

The migration needs `CREATE EXTENSION vector`. Applying it on the staging branch is part of
the work.

### 2. What goes in the graph

**Company layer (per tenant).** Built from: `assets`, `asset_addresses`, `asset_software`,
`asset_identifiers`, `asset_relationships`, `sboms`, `dependencies`, `events`, `advisories`,
`ti_events`, `event_cti_indicators`, `posture_metrics`, `agents`, `topology_nodes`,
`network_links`, `scan_results` (status and summaries).

Rows in these tables with a NULL tenant are left out, because NULL in `kg_nodes` means shared.

**Shared layer (`tenant_id` NULL).** Built from every git-tracked file:

- `workers/`: routes, services, queues, cron jobs, tables, with import and call links.
- `frontend/`: pages, components, and which API each page calls.
- `agent-gui/`: modules, classes and functions.
- Migrations, tests, and docs (`README.md`, `PRODUCT.md`, `DESIGN.md`, `STAGING.md`,
  `AGENT_SETUP_GUIDE.md`).
- Reference knowledge already in the repo: ATT&CK and CWE data.

A script reads every tracked text file, parsing code properly (TypeScript compiler API for TS
and JSX, Python `ast` for Python). Lockfiles and generated files are recorded by name only.
Untracked folders (`agent/`, `backend/`) are not included.

The CTI table is global and large. Only indicators linked to a company's events enter the
graph.

**Never in the graph.** `.env*` files, password hashes, MFA secrets, API keys, enrolment
codes, session tokens, `users` credentials, and `audit_logs`. The extractor uses an allowlist
of columns per table, so a new column stays out until someone adds it. A secret-pattern scan
checks every chunk before it is stored, and a match blocks that chunk.

**Problem nodes.** Fixed rules, not the AI, find problems and store them with links to their
evidence and a recommended solution. The first rule set:

- Security: internet-facing critical asset with open advisory; asset with no SBOM, so not
  CVE-checked; open high-severity alert ageing; exposed risky port.
- System: agent offline; scans repeatedly failing; threat feed failing; stale posture data;
  chatbot graph sync backlog; code-level hotspots from the shared layer, such as very large
  files or heavily depended-on modules.

The recommender ranks these. Rules are plain code and unit tested. Security problems belong to
one company. System problems about UMEagleEye itself are `platform` visibility, so a company
is never told to fix code it cannot change. Scans failing or agents offline in a company's own
setup are that company's problems. Performance windows are `platform` visibility.

### 3. Staying current

1. Postgres triggers on the company-layer tables record each change in `kg_outbox`. Triggers
   are used because about 20 places in the code write these tables, and a trigger cannot be
   forgotten.
2. After a write, the code sends one `kg_sync` message on the existing `ADVISORY_QUEUE`,
   limited with a short KV debounce so a big scan sends few messages. The consumer in
   `workers/src/queues/consumer.ts` applies the outbox to the graph.
3. Before answering, the chatbot applies any outstanding outbox rows for that company. A lost
   message therefore can never produce a stale answer.
4. The existing 6-hourly cron drains anything left over. No new timers are added.

Embeddings are generated with Cloudflare Workers AI (`@cf/baai/bge-base-en-v1.5`) through a
new `AI` binding. If embedding fails, the node is stored without one and keyword search still
finds it. A later sync fills it in.

The shared layer rebuilds on deploy, through a script chained to `deploy:staging`.

### 3a. Performance history (for "why was it slow?")

UMEagleEye records nothing about speed today, so new recording is added:

- A Hono middleware records each API request: route pattern (never the real URL or its
  values), status, total time, and time spent waiting on the database. Queue jobs and cron
  jobs record name, duration and outcome. Failures are recorded the same way.
- Records go to Cloudflare Workers Analytics Engine through a new binding, not to Postgres, so
  recording adds no database load and cannot wake the database. Writing is fire-and-forget, so
  a recording failure cannot break a request.
- Summaries become `PerformanceWindow` nodes in the shared layer: for each time window, the
  slowest routes, error rate, request volume, database share of the time, and jobs running at
  that moment. These are pulled on the existing 6-hourly cron, and again just before answering
  a question about performance, so no new timer is added.
- Rules produce system problem nodes from these windows: a route persistently slow, a spike in
  errors, or slowness that coincides with a scan or a job.
- The chatbot explains slowness from these nodes, citing the window. It states what lined up
  in time and does not claim proof of cause.
- Limits it must state plainly: no history exists before recording is switched on; it measures
  the API and background jobs, not the speed of a person's browser or network; history lasts as
  long as Analytics Engine keeps it (about 3 months).

Querying Analytics Engine needs a Cloudflare API token, stored as a new Worker secret.

### 4. Retrieval

For each question: search by meaning (pgvector) and by keyword (Postgres full text), merge the
results, then walk the links outward up to 2 steps, limited by a node budget. The tenant
filter is applied inside the retrieval function from the signed-in user's context. The model
never supplies it. A query always means: `tenant_id` equals the user's company, or the node is
shared with `all_staff` visibility. `platform` nodes are added only for `superadmin`. The same
filter applies to role limits and to every link walked, so a walk cannot cross into a node the
user may not see. A `superadmin` with no company picked sees shared knowledge only.

### 5. The agent

The same route, `workers/src/routes/chatbot.ts`, and the same streaming event format, so
`frontend/src/pages/ChatbotPage.jsx` keeps its streaming logic. It gains a list of sources, its
quick buttons send normal questions, and the responses typed `stats`, `assets` and `alerts` go
away. The model stays on the existing DeepSeek/OpenRouter setup.

The agent has only graph tools: `search_graph`, `get_node`, `follow_links`, `list_problems`,
`count_nodes` (exact counts and complete lists over `kg_nodes`, with filters, under the same
access filter), and `propose_resolve_advisory`.

Proposals are held on the server with a short-lived token tied to the user, company and
advisory. A new confirm endpoint is the only way to close an advisory from chat. The Confirm
button calls it, and it re-checks tenant and role and writes the audit record.

### 6. Guardrails

1. Each question is first sorted as: about the system or company; fix advice for something in
   the company; general security; or neither. "Neither" is politely refused.
2. System answers use only retrieved graph content and cite the nodes used.
3. General security answers are labelled as general knowledge, not facts about this company.
   Fix advice has two labelled parts: "What we found" from the graph, cited, and "Suggested
   steps" from general guidance.
4. Verification: every IP, CVE ID, hostname, advisory ID and number in a system answer, and in
   the "What we found" part of fix advice, must appear in retrieved content. Suggested steps
   are not checked this way, but must use the real values from "What we found" where they name
   this company's asset, port or version. A failed answer is regenerated once, then replaced with "I
   don't know". To make this possible, answer text is released after it passes, while progress
   events stream during retrieval.
5. Graph content is marked as untrusted data, and the agent is told never to follow
   instructions in it.
6. Confirming an advisory is re-checked on the server against the user's tenant and role.
7. Existing role and tenant checks, and limits on tool calls and output, stay.

### 7. Removing the old chatbot

The old agent loop, its prompt, and the typed commands in `workers/src/routes/chatbot.ts` are
deleted once the new one passes on staging. Tools in
`workers/src/mcp/tools.ts` still used by the MCP server stay.

## Testing

All against staging (`umeagleeye-api-staging` and the Neon `staging` branch). Test scripts
refuse to start if the target is not staging. Every session is appended to `log.txt` at the
repo root: time, scenario, inputs, tools and sources used, answer, timing, pass or fail.

**QA scenarios**, each simulating real use:

- Asset, alert, advisory and connected questions, checked against the database.
- A new scan or alert arrives, and the chatbot knows it within a few minutes.
- System questions, such as "which page calls this API?".
- "What should I fix first?" and system bottleneck questions.
- A question with no answer in the graph returns "I don't know".
- Generate slow traffic at a known time, then ask why it was slow at that time.
- Ask about slowness before recording began; the chatbot says it has no history.
- General security questions get the label; unrelated questions are refused.
- Cross-company probing with two test companies.
- Company staff asking for code details, and each role asking beyond its limits.
- Exact counts checked against the database.
- Typing `fix <id>` no longer closes an advisory.
- Prompt injection planted in a hostname.
- Propose, cancel and confirm for closing an advisory.
- Attempts to extract secrets.
- Regression of the main dashboard flows: login, assets, scan ingest, alerts, advisories,
  reports.

**Stress**, in rising steps of 1, 5, 10 and 25 simultaneous users, simulating mixed chat,
scan ingest bursts and dashboard reads. Paid AI calls are capped at 200 for a whole test run.
Beyond the cap, load tests hit retrieval without the model. Starting targets, to be reported
honestly rather than tuned to pass: retrieval p95 under 1 second at 25 users, error rate under
1%, no cross-company data at any load, outbox drained within 3 minutes of a burst.

## Left to the builder

Exact schema details, node and relation names, debounce length, retrieval weights, node
budget, batch sizes, and test tooling.
