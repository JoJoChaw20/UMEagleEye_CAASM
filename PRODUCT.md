# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary: IT/security admin at a small organisation (company or university lab), often one or a few people. They triage alerts, review newly discovered devices and act on remediation advisories as part of their day-to-day work. Other roles exist in the app (platform superadmin, tenant_superadmin, tenant_admin, business_owner with read access), but the admin is the confirmed design target.

## Product Purpose

UMEagleEye 2.0 is an AI-driven Cyber Asset Attack Surface Management (CAASM) platform, a University of Malaya FYP (Faculty of Computer Science & Information Technology). It gives visibility into every cyber asset, detects drift and threats, and turns findings into guided remediation and posture reporting. Success: an admin sees what is on the network, what changed, what is exploitable, and what to fix first, with no infrastructure to run.

## Positioning

Four mechanisms, all confirmed by the user:
- Serverless: Cloudflare Workers, Pages, Queues, R2 and Neon Postgres; no always-on servers.
- Identity-resolved inventory: active scans, passive sniffing and agent reports merge into one device per real device, with duplicate detection and merge.
- CVEs grouped by fix plus threat-intel context: alerts collapse to one upgrade action, ranked by CISA KEV, EPSS and indicator matches, with a "Why this alert" explanation.
- AI advisories and chatbot: DeepSeek writes remediation advisories and answers questions with live posture and alert context.

## Operating Context

Web dashboard (React, Vite, Tailwind, Recharts) over a Cloudflare Workers API. An EagleEye agent runs on each monitored computer (Nmap, passive ARP/mDNS/DHCP/SSDP, SNMPv3, Syft/Grype for SBOM and CVE checks). Staging and production environments exist. Multi-tenant. Dense data work: inventory tables, alert queues, topology tree, force-directed relationship graph, reports (PDF), notification centre.

## Capabilities and Constraints

- Asset inventory (My Assets, Discovered, relationship graph), CSV import, duplicate merge, computed criticality.
- Discovery (networks, scan history, compare), topology, posture score and drift events.
- Alerts, advisories lifecycle (open, acknowledged, in_progress, resolved), SLA breach notices, CVE-by-fix grouping, threat intel (feeds, events, matches), SBOM coverage page.
- Chatbot with SSE streaming, reports, MFA (TOTP), Google sign-in, agent management.
- CVE checks only for computers running the agent; printers, routers, IoT and phones are discovered but not CVE-checked.
- Dark, light and system themes are required; colours run on CSS custom properties and every change must work in all three.

## Brand Commitments

Name: UMEagleEye (version "2.0"). Binding visual constraint: keep dark, light and system theme modes.

## Evidence on Hand

Live deployment at https://umeagleeye.csnet.my and a staging environment with a sanitised database copy. README.md, STAGING.md and AGENT_SETUP_GUIDE.md document features and setup. No customer testimonials, benchmarks or pricing exist; do not fabricate them.

## Product Principles

1. Show what to do, not only what is wrong: group findings by fix and explain why an alert ranked high.
2. One device, one row: identity resolution is the foundation; the UI must never make the admin reconcile duplicates by hand.
3. Honest coverage: state plainly which assets are checked and which are not (no agent, no CVE check).
4. Built for a small team's daily triage: dense, scannable and fast, without enterprise-SOC ceremony.
5. Zero-infrastructure trust: the product is serverless and tenant-isolated, and the interface should reflect that safety.

## Accessibility & Inclusion

No formal standard was requested. Theme switching (dark, light, system) is the only confirmed requirement.
