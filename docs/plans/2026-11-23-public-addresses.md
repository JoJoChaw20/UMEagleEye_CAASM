# D4: the organisation's public addresses (blocklists + seen from the internet): plan

Status: **steps 1-3 built 23 Nov 2026, not deployed**: Neon's compute allowance ran out the same day, so
migration 0047 and the staging checks wait for the monthly reset. The SQL was run against an empty copy of
the schema on a local PostgreSQL 18 (27 checks: recording, listing, sharing, R11 levels and reopening, DROP,
InternetDB alerts, dashboard counts, retention). Decisions taken as recommended. The rule is **R11** (R9 and
R10 were taken). Step 4 (evaluation) after the reset. D4 from the threat-intel plan (22 Nov), joined with the
stakeholders' "internet-facing" ask. The last planned item; integrations, uv Python and remediation are optional.

## What exists today

- **R5** (`services/iocMatch.ts`) matches an asset's **public** IP against the feeds' IP indicators. Inventory
  assets almost never have one (they are LAN addresses), so in practice R5 matches hostnames and URLs.
- **Internet-facing** (`lib/exposure.ts resolveInternetFacing`) is true only for the asset that is an agent's
  reported default gateway, or an analyst override. Nothing says what the internet actually sees.
- The server **does not record** an agent's public address. Every heartbeat arrives with it
  (`CF-Connecting-IP`), but only the audit log reads that header, for user actions.
- Feeds already loaded nightly: ThreatFox (IP:port of C2 and payload servers), Feodo Tracker (botnet C2 IPs),
  URLhaus (malware URLs, some on bare IPs).

## What we build

### 1. Record the public addresses

- On each heartbeat, the server reads the agent's public address and stores it on the agent (`agents.public_ip`,
  `public_ip_at`). It also writes a row in `public_addresses`, but only when the address changes, or once an hour.
  Most heartbeats therefore cost no extra query.
- `public_addresses` holds one row per tenant and address:
  - when it was first and last seen, and which agents saw it;
  - its **status**: *unconfirmed* (seen by agents), *ours*, or *not ours*;
  - the latest blocklist and InternetDB results.
- Admins can **add** addresses by hand, such as the office's static IP or the public IP of a web or mail server.
  Those start as *ours*.
- **Why the status matters:**
  - A laptop at home reports the home ISP's address.
  - On a campus or shared office, one address carries thousands of other people's traffic.

  So an address seen by agents is only *unconfirmed* until someone marks it *ours*. Two hints help:
  - **seen by N agents:** an address several agents share is more likely the office;
  - **shared:** agents of other organisations also report it. Which organisations is never shown.
- IPv6: an agent reaching the server over IPv6 shows its own address (no NAT). These are stored and checked
  against the lists like IPv4. InternetDB is IPv4 only.

### 2. Blocklists (rule R11; R9 and R10 are the vulnerable-service and security-baseline rules)

- **Lists:** the address is checked against the IP lists already loaded (ThreatFox, Feodo, URLhaus hosts), plus
  **Spamhaus DROP** (new).
  - DROP holds about 1,000 network ranges run by criminals or hijacked. It is free, with attribution, and may be
    fetched at most once a day.
  - DROP rarely matches a real organisation, and it costs one small download a day.
- **When:**
  - after the nightly feed refresh;
  - when a new address appears;
  - when someone changes an address's status.
- **What a match means:** the organisation's own address on a C2 or malware list means a computer inside is
  probably infected, or a port-forward is serving something it shouldn't.
- **The alert** is a threat-intel alert (`cti_match`, `match_kind: 'public_address'`, rule R11). It gets the existing
  tiers, ATT&CK mapping, fix-time target and Why panel.
- **Which asset it sits on:** the network's gateway, when an agent reported it and it is in the inventory.
  Otherwise, the computer of the agent that last reported the address. Alerts need an asset.

| Status | On a botnet C2 list (Feodo, ThreatFox `botnet_cc`) | On another list |
|---|---|---|
| ours | **critical** | **high** |
| unconfirmed | **medium**, "review: is this address yours?" | **low**, review |
| not ours | no alert, shown on the list | no alert, shown on the list |

- **Resolving and reopening:** when the address drops off the list, the alert resolves. When it comes back, the
  alert reopens. This is the same reconciliation as R5. `matchIocs` must leave R11 alerts alone, as it does for
  sightings.

### 3. Seen from the internet (Shodan InternetDB)

- **What it gives:** InternetDB answers for one IPv4 address: the open ports, the products it recognised (CPE),
  hostnames, tags (such as `vpn`, `self-signed`, `compromised`), and CVEs. It needs no key, and Shodan rebuilds it
  weekly.
- **Schedule:** we ask about each *ours* and *unconfirmed* address **once a week**. To stay inside the Workers
  subrequest limit, each nightly run checks at most 20 addresses, the oldest first.
- **Alerts:** for *ours* addresses, the existing **exposure** rules run on the ports the internet sees, with
  `internetFacing = true`. Examples: RDP 3389, SMB 445, Telnet, databases, or the router's admin page.
  - The alert sits on the gateway asset, with the evidence "Shodan saw port 3389 open on 203.0.113.7
    (scan of 17 Nov)".
  - It resolves when Shodan no longer lists the port.
  - This also gives the gateway real evidence for "internet-facing".
- **Shodan's CVEs:** shown on the list as "reported by Shodan, unverified", with **no alert**. Shodan guesses them
  from product versions, and its own docs say they include unverified ones.
- *Unconfirmed* addresses show their InternetDB results but raise no alert, so a campus address never alerts.
- **Attribution:** "Data from Shodan InternetDB".

### 4. Where it shows

- **Network page:** a **Public addresses** card on the overview. Each address shows:
  - status, with a selector to change it;
  - seen by N agents, and first/last seen;
  - the lists it is on, and the ports open from the internet;
  - when it was last checked.

  The card also has **Add address** and a switch for the Shodan check.
- **Dashboard, Exposure section:** "Public addresses: N · X on a blocklist · Y with ports open to the internet".
- **Everywhere else:** labels in `alertMeta` and `WhyAlert`, the PDF report, the weekly record, and the assistant's
  network text.

## Licences and privacy

| Source | Terms | Use here |
|---|---|---|
| ThreatFox, Feodo, URLhaus | abuse.ch, already in use | unchanged |
| [Spamhaus DROP](https://www.spamhaus.org/drop/terms/) | free for any organisation, attribution, ≤ 1 download a day; copyright kept by Spamhaus | **yes**, credited on the page |
| [Shodan InternetDB](https://blog.shodan.io/introducing-the-internetdb-api/) | free for non-commercial use: "you can use it at a company but you can't use it to build commercial products that you charge money for" | **yes while UMEagleEye is not sold**; a paid product needs Shodan's licence |
| [AbuseIPDB](https://docs.abuseipdb.com/) | free key, 1,000 checks a day; the terms need written approval for use beyond the site | **not now**. It is the best "something inside attacks others" signal; possible later, with permission |
| blocklist.de | free, run by Abusix; no terms found for reuse | not used |

**Privacy:** the InternetDB check sends the organisation's public address to Shodan. It is the only new outbound
data. Each tenant's switch for it is **on by default**, and turning it off stops the check and clears the stored
results.

## Steps

1. **Record:**
   - migration 0047: `agents.public_ip`/`public_ip_at`, the `public_addresses` table, and a tenant setting for
     the Shodan check;
   - the heartbeat stores the address;
   - the Network page card with status and Add.

   Tests, then staging. **Lab check:** the VMs and your PC appear, and which addresses they show.
2. **Blocklists:** the Spamhaus DROP feed step (network ranges kept in KV and matched in code, `lib/ipRanges.ts`), R11 matching and alerts,
   and alert labels. Tests, then staging.
3. **InternetDB:** the weekly check, exposure alerts on the gateway, the dashboard tile, the report and the
   weekly record. Tests, then staging.
4. **Evaluation**, on staging:
   - **Blocklists:** a published test event that lists the lab's own public address. Check the alert level for
     each status (ours, unconfirmed, not ours), that it resolves when the event is withdrawn, and that it
     reopens when the event comes back.
   - **InternetDB:** add a public test host the Nmap project allows scanning (scanme.nmap.org) as *ours*, then
     compare Shodan's ports with our own scan of it.
   - Results go into this plan and `C:\FYP\AP2\eval\public-addresses\`.

Effort: about 2–3 days. It is more than the 1–2 days first estimated, because the address isn't recorded yet.

## Decisions

1. **Lists:** the existing ones plus Spamhaus DROP, and AbuseIPDB not now. *Recommended.*
2. **InternetDB:** use it while UMEagleEye isn't sold, with a per-tenant switch on by default. *Recommended.*
3. **Alert levels** as in the table: *unconfirmed* is a review alert, and *not ours* never alerts. *Recommended.*
4. **Who can change an address's status or add one:** a new permission, `network.public_address.edit`. Tenant
   admins get it by default, as with `tenant.security_baseline_target`. Seeing the card needs `network.view`.
   *Recommended.*
