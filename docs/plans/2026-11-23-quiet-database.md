# Quiet database: agent check-ins without waking Neon (plan)

Status: **built 23 Nov 2026, not deployed** (Neon's compute allowance ran out on 23 Nov; staging and production
are branches of one project and share it). Unit tests for the hub's logic and the 503; the flush statement run
on a local PostgreSQL. The Durable Object itself is checked on staging after the reset: an idle lab agent's
check-ins answered without the database, "last seen" on the Agents page within a minute of opening it, a
scan or setting change reaching the agent at its next check-in, and Neon's usage page over a quiet day.

## Why

Neon's free plan gives a project 100 CU-hours a month and suspends a compute after 5 minutes without queries.
Every agent checks in every 30 s, and each check-in ran about ten statements (agent row, key check, tenant
policies, the update, seven job-expiry UPDATEs and the pending-jobs SELECT in `pendingJobsFor`). So the
database never slept: one always-on 0.25 CU compute is ~180 CU-hours a month, and the lab agents kept the
staging branch awake around the clock. On 23 Nov both branches were suspended (HTTP 402) until the monthly reset.

## What changes

A **Durable Object**, `AgentHub` (one for the platform, SQLite-backed so it is on the free plan), answers
routine check-ins from memory:

- **Fast path** (no database): the agent is known to the hub, its key hash matches, what it reports (version,
  build, settings, capabilities, networks, gateway, public address) is unchanged, it had no jobs waiting, and
  the cached answer is younger than ~6 hours (spread per agent). The hub notes the time and returns the cached
  answer (its managed settings and policy version, no jobs).
- **Slow path** (today's code): anything else. Afterwards the hub remembers the answer, the report and whether
  jobs are still waiting (including new-device scans that are not due yet), so an agent with work keeps taking
  the slow path until its queue is empty.
- **Last seen reaches the database** in one statement for all agents: before any signed-in request (the
  dashboard wakes the database anyway; at most once a minute per Worker instance), before every scheduled job
  and queue batch, and on the hub's own alarm at least hourly. So pages, reports and job routing always read a
  current "last seen".
- **Cached answers are dropped** when anything could change them: any successful change a signed-in user makes
  in their tenant (settings, scans, inventory and SBOM requests, updates, keys, deletions; the database is
  awake then anyway), the platform superadmin's changes (all tenants), and new-device scans the server queues
  itself (`autoInvestigate`).
- When the database is unreachable, the API answers **503 "The database is not available right now"**
  instead of a bare 500.

The hub keeps its state in memory only. If Cloudflare restarts it, the next check-in of each agent simply
takes the slow path, and at most the last hour of "last seen" times is lost.

## Expected effect

An idle tenant wakes the database about once an hour (the alarm) plus the scheduled jobs, instead of
continuously: roughly 10-20% of the hours, ~20-40 CU-hours a month per branch, inside the free allowance for
production and staging together. Measured after the reset on staging (Neon's usage page, a day with the lab
agents running and nobody signed in).

Still waking it, unchanged for now: passive-listening uploads (every 5 minutes when on), threat-sightings
event lists (every 30 minutes per agent with sightings on), and inventory and SBOM uploads.

## Limits of the free plan

Cloudflare's free plan allows 100,000 Worker requests and 100,000 Durable Object requests a day. A check-in
every 30 s is 2,880 a day per agent, so about 30 agents in total across production and staging; the same
limit as before this change, now on two counters.
