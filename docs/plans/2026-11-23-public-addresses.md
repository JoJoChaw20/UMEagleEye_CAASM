# D4: the organisation's public addresses (blocklists): plan

Status: **built 23-24 Nov 2026, not deployed**: Neon's compute allowance ran out on 23 Nov, so migration 0047
and the staging checks wait for the monthly reset. The SQL was run against an empty copy of the schema on a
local PostgreSQL 18 (recording, listing, sharing, R11 levels and reopening, DROP, dashboard counts, retention).
The rule is **R11** (R9 and R10 were taken). D4 from the threat-intel plan (22 Nov), joined with the
stakeholders' "internet-facing" ask.

**Decision 24 Nov: Shodan InternetDB removed.** It was built (weekly check of each address, exposure alerts for
risky open ports, an off switch) and then taken out again at the user's request, so the feature is blocklists
only. Nothing about the organisation's addresses leaves the system, and there is no third-party licence to
track. What it would have added, and what to use instead, is under "Not built". The evaluation of it
(`C:\FYP\AP2\eval\public-addresses\RESULTS.md`) stays as a record.

## What exists today

- **R5** (`services/iocMatch.ts`) matches an asset's **public** IP against the feeds' IP indicators. Inventory
  assets almost never have one (they are LAN addresses), so in practice R5 matches hostnames and URLs.
- **Internet-facing** (`lib/exposure.ts resolveInternetFacing`) is true only for the asset that is an agent's
  reported default gateway, or an analyst override.
- The server did not record an agent's public address. Every heartbeat arrives with it (`CF-Connecting-IP`),
  but only the audit log read that header, for user actions.
- Feeds already loaded nightly: ThreatFox (IP:port of C2 and payload servers), Feodo Tracker (botnet C2 IPs),
  URLhaus (malware URLs, some on bare IPs).

## What we build

### 1. Record the public addresses

- On each heartbeat, the server reads the agent's public address and stores it on the agent (`agents.public_ip`,
  `public_ip_at`). It also writes a row in `public_addresses`, but only when the address changes, or once an hour.
  Most heartbeats therefore cost no extra query. Phones are left out: on mobile data they show the carrier's.
- `public_addresses` holds one row per tenant and address:
  - when it was first and last seen, and which agents saw it;
  - its **status**: *unconfirmed* (seen by agents), *ours*, or *not ours*;
  - what the blocklists say about it, and when they were checked.
- Admins can **add** addresses by hand, such as the office's static IP or the public IP of a web or mail server.
  Those start as *ours*.
- **Why the status matters:**
  - A laptop at home reports the home ISP's address.
  - On a campus or shared office, one address carries thousands of other people's traffic.

  So an address seen by agents is only *unconfirmed* until someone marks it *ours*. Two hints help:
  - **seen by N agents:** an address several agents share is more likely the office;
  - **shared:** agents of other organisations also report it. Which organisations is never shown.
- IPv6: an agent reaching the server over IPv6 shows its own address (no NAT). These are stored and checked
  against the lists like IPv4.

### 2. Blocklists (rule R11; R9 and R10 are the vulnerable-service and security-baseline rules)

- **Lists:** the address is checked against the IP lists already loaded (ThreatFox, Feodo, URLhaus hosts), the
  organisation's published threat events, plus **Spamhaus DROP** (new).
  - DROP holds about 1,800 network ranges run by criminals or hijacked. It is free, with attribution, and may be
    fetched at most once a day.
  - DROP rarely matches a real organisation, and it costs one small download a day.
- **When:**
  - after the nightly feed refresh;
  - when a new address appears;
  - when someone changes an address's status, or a threat event changes.
- **What a match means:** the organisation's own address on a C2 or malware list means a computer inside is
  probably infected, or a port-forward is serving something it shouldn't.
- **The alert** is a threat-intel alert (`cti_match`, `match_kind: 'public_address'`, rule R11). It gets the existing
  tiers, ATT&CK mapping, fix-time target and Why panel.
- **Which asset it sits on:** the network's gateway, when an agent reported it and it is in the inventory.
  Otherwise, the computer of the agent that last reported the address, else an asset holding the address.

| Status | On a botnet C2 list (Feodo, ThreatFox) | On another list |
|---|---|---|
| ours | **critical** | **high** |
| unconfirmed | **medium**, "review: is this address yours?" | **low**, review |
| not ours | no alert, shown on the list | no alert, shown on the list |

- **Resolving and reopening:** when the address drops off the list, the alert resolves. When it comes back, the
  alert reopens. This is the same reconciliation as R5. `matchIocs` leaves R11 alerts alone, as it does for
  sightings.

### 3. Where it shows

- **Network page:** a **Public addresses** card on the overview. Each address shows its status (with a selector
  to change it), the lists it is on, the agents connecting from it now, when it was last seen, and a note; the
  card has **Add address**.
- **Dashboard, Exposure section:** "Public addresses: N · X on a blocklist · Y to confirm".
- **Everywhere else:** labels in `alertMeta` and `WhyAlert`, and the Alert rules page.

## Not built (decided against)

- **Seen from the internet (Shodan InternetDB).** Weekly, per address marked ours or unconfirmed: the open
  ports, recognised products and guessed CVEs, with an exposure alert for each risky port (RDP, SMB, databases,
  SSH, router management) on the gateway. Dropped on 24 Nov. What is lost: nothing in UMEagleEye now shows what an
  address exposes to the internet from outside. What covers part of it: an active scan from inside, and the
  exposure rules on an internet-facing device (an analyst marks it). Free for non-commercial use only, and the
  organisation's address would have been sent to Shodan. A scan of scanme.nmap.org agreed with it on both ports
  both checked (see RESULTS.md).
- **AbuseIPDB:** the best "something inside attacks others" signal; its terms need written approval for use
  beyond its own site. Possible later.
- **blocklist.de:** free, run by Abusix; no terms found for reuse.

## Licences and privacy

| Source | Terms | Use here |
|---|---|---|
| ThreatFox, Feodo, URLhaus | abuse.ch, already in use | unchanged |
| [Spamhaus DROP](https://www.spamhaus.org/drop/terms/) | free for any organisation, attribution, ≤ 1 download a day; copyright kept by Spamhaus | **yes**, credited on the page |

**Privacy:** the organisation's public addresses stay in the system; no new outbound data.

## Steps

1. **Record:** migration 0047 (`agents.public_ip`/`public_ip_at`, the `public_addresses` table), the heartbeat
   stores the address, the Network page card with status and Add. Tests, then staging. **Lab check:** the VMs
   and your PC appear, and which addresses they show.
2. **Blocklists:** the Spamhaus DROP feed step (network ranges kept in KV and matched in code,
   `lib/ipRanges.ts`), R11 matching and alerts, and alert labels. Tests, then staging.
3. ~~InternetDB~~ removed (above).
4. **Evaluation**, on staging: a published test event that lists the lab's own public address. Check the alert
   level for each status (ours, unconfirmed, not ours), that it resolves when the event is withdrawn, and that
   it reopens when the event comes back. Results go into this plan and `C:\FYP\AP2\eval\public-addresses\`.

## Decisions

1. **Lists:** the existing ones plus Spamhaus DROP, and AbuseIPDB not now.
2. **Shodan InternetDB:** not used (24 Nov).
3. **Alert levels** as in the table: *unconfirmed* is a review alert, and *not ours* never alerts.
4. **Who can change an address's status or add one:** a new permission, `network.public_address.edit`. Tenant
   admins get it by default, as with `tenant.security_baseline_target`. Seeing the card needs `network.view`.
