# Action-Based Access Control: Design

Date: 2026-11-17
Status: draft v3, awaiting approval

## Intent

Today, access is decided by four fixed roles (superadmin, tenant_superadmin, tenant_admin,
business_owner). A company cannot give someone "view alerts and run SBOM scans" without also
giving them everything else that role carries.

The new model keeps only two roles and replaces the rest with individual actions. The Tenant
Superadmin chooses, for each person in their tenant, exactly which actions that person may
perform.

## Decided by the project owner

1. Only two roles remain: **Platform Superadmin** and **Tenant Superadmin**. Every other account
   is a **Tenant user** with no role, only the actions granted to them.
2. Only the Tenant Superadmin grants or removes actions, and only inside their own tenant.
3. A tenant has exactly one Tenant Superadmin at all times: never zero, never two.
4. There is one Platform Superadmin account. It views data across all tenants and holds no
   rights inside any tenant,
   with three exceptions: **Provision tenant**, **Restore tenant ownership**, and **End a
   tenant** (deactivate, then delete).
5. MFA reset moves from the Platform Superadmin to the Tenant Superadmin, for their own users.
6. MFA is required for every account.
7. Presets (Viewer, Analyst, Operator) are shortcuts that tick actions. They are never stored as
   roles.
8. Existing tenant_admin and business_owner accounts are converted automatically to the actions
   they can perform today.
9. "Refresh threat feeds" is removed. Feeds are shared by all tenants and refresh on schedule only.
10. The role keeps the name **Tenant Superadmin**.
11. A deactivated tenant is kept for 90 days before it can be deleted.

---

## 1. Who can do what

| | Platform Superadmin | Tenant Superadmin | Tenant user |
|---|---|---|---|
| How many | Platform staff | Exactly one per tenant | Any number per tenant |
| Sees | Every tenant's data (view only) | Everything in own tenant | Only what their granted view actions allow |
| Changes data | Never | Everything in own tenant | Only what their granted actions allow |
| Grants access | Never | Yes, own tenant only | Never |
| Reserved actions | Provision tenant, Restore tenant ownership, End a tenant | All reserved tenant actions (section 4) | None |

### General rules

1. **New Tenant users start with no access.** They can sign in and manage their own password and
   MFA, and nothing else until actions are granted.
2. **Granting an action also grants what it needs.** For example, "Run active scans" also grants
   "View scans". The picker shows which actions were added.
3. **Removing a view action also removes the actions that depend on it.** Before saving, the
   picker lists exactly what will be removed.
4. **Every grant and removal is written to the tenant audit log:** who changed it, for whom,
   what changed, and when.
5. **Changes take effect on the user's next request.** No sign-out is needed.

### Impact levels shown beside each action

- **Low:** read only. Nothing changes.
- **Medium:** creates or changes records, or starts work on an agent.
- **High:** deletes data, cannot be undone, or reads private activity on users' computers.

---

## 2. Grantable actions (58)

### 2.1 Dashboard

| Action | What it allows | Also grants | Impact |
|---|---|---|---|
| **View dashboard** | Allows the user to see the security overview: posture score and its history, key figures, and notifications. | None | Low |

### 2.2 Asset inventory

| Action | What it allows | Also grants | Impact |
|---|---|---|---|
| **View assets** | Allows the user to see all assets in the tenant: details, installed software, address history, risk score, baseline and possible duplicates. | None | Low |
| **Add assets** | Allows the user to add an asset by hand. | View assets | Medium |
| **Import assets** | Allows the user to upload a CSV file of assets. Matching existing assets are updated, not duplicated. | View assets | Medium |
| **Edit assets** | Allows the user to change an asset's details and record its current state as the approved baseline. | View assets | Medium |
| **Delete assets** | Allows the user to permanently delete an asset, with its software list and history. This cannot be undone. | View assets | High |
| **Merge duplicate assets** | Allows the user to combine assets that are the same device into one record. This cannot be undone. | View assets | High |
| **Dismiss duplicate warnings** | Allows the user to mark two assets as "not a duplicate", and to undo that decision. | View assets | Medium |
| **Recalculate risk scores** | Allows the user to recalculate the risk score of one asset or of all assets. | View assets | Medium |
| **Collect software inventory** | Allows the user to ask an asset's agent to report its installed software now. | View assets | Medium |
| **Clear software inventory** | Allows the user to delete the recorded software list of an asset. It is rebuilt at the agent's next report. | View assets | High |

### 2.3 Discovery and scanning

| Action | What it allows | Also grants | Impact |
|---|---|---|---|
| **View scans** | Allows the user to see scan history, discovered networks and hosts, scan progress, and comparisons between scans. | None | Low |
| **Run active scans** | Allows the user to start a scan that probes a network range to find devices and open ports. Active scans create network traffic and may be noticed by other security tools. | View scans | Medium |
| **Run passive discovery** | Allows the user to start passive listening, where an agent finds devices from network traffic without sending probes. | View scans | Medium |
| **Cancel scans** | Allows the user to stop a scan that is waiting or running. | View scans | Medium |
| **Run drift check** | Allows the user to check now for changes from approved baselines and close outdated alerts. This normally runs every night. | View scans, View alerts | Medium |
| **Preview scan routing** | Allows the user to see which agent would scan a given network, before starting a scan. | View scans | Low |

### 2.4 SBOM (software bill of materials)

| Action | What it allows | Also grants | Impact |
|---|---|---|---|
| **View SBOMs** | Allows the user to see the software components of each computer, search packages across the tenant, and view dependency trees. | None | Low |
| **Download SBOMs** | Allows the user to download SBOM files in standard formats. | View SBOMs | Low |
| **Run SBOM scans** | Allows the user to ask an agent to build a fresh SBOM for a computer. | View SBOMs, View assets | Medium |
| **Delete SBOMs** | Allows the user to delete all SBOMs recorded for an asset. This cannot be undone. | View SBOMs | High |

### 2.5 Alerts

| Action | What it allows | Also grants | Impact |
|---|---|---|---|
| **View alerts** | Allows the user to see alerts, their evidence, and related CVEs. | None | Low |
| **Manage alerts** | Allows the user to acknowledge alerts, change their status, and assign them to people. | View alerts | Medium |
| **Bulk-update alerts** | Allows the user to change the status or assignee of many alerts at once. | Manage alerts | Medium |

### 2.6 Advisories

| Action | What it allows | Also grants | Impact |
|---|---|---|---|
| **View advisories** | Allows the user to see remediation advisories and their progress. | None | Low |
| **Generate advisories** | Allows the user to create a remediation advisory from an alert. | View advisories, View alerts | Medium |
| **Update advisories** | Allows the user to change an advisory's status (open, acknowledged, in progress, resolved) and its assignee. | View advisories | Medium |
| **Close advisories from the assistant** | Allows the user to confirm closing an advisory when the AI assistant proposes it. | Update advisories, Use AI assistant | Medium |

### 2.7 Threat intelligence

| Action | What it allows | Also grants | Impact |
|---|---|---|---|
| **View threat intelligence** | Allows the user to see threat indicators, statistics, the MITRE ATT&CK matrix, indicator lookup, and "Seen in traffic" matches. | None | Low |
| **View threat events** | Allows the user to see the threat events recorded by the tenant and their indicators. | View threat intelligence | Low |
| **Create threat events** | Allows the user to record a new threat event. | View threat events | Medium |
| **Edit threat events** | Allows the user to change a threat event, and to add, edit or remove its indicators. | View threat events | Medium |
| **Publish threat events** | Allows the user to publish or unpublish a threat event. When published, its indicators are sent to agents for threat sightings. | View threat events | Medium |
| **Delete threat events** | Allows the user to permanently delete a threat event and its indicators. This cannot be undone. | View threat events | High |

### 2.8 Network map and relationships

| Action | What it allows | Also grants | Impact |
|---|---|---|---|
| **View network map** | Allows the user to see the network map, device links, and topology tree. | None | Low |
| **Map network devices** | Allows the user to ask a network agent to read routers and switches (SNMP) and update the map. | View network map | Medium |
| **Edit topology** | Allows the user to add or remove topology nodes by hand, and to rebuild the topology from current assets. | View network map | Medium |
| **View relationships** | Allows the user to see how assets depend on each other, and the blast radius of an asset. | View assets | Low |
| **Manage relationships** | Allows the user to add relationships by hand and to detect them from current data. | View relationships | Medium |
| **Delete relationships** | Allows the user to remove a relationship between assets. | View relationships | Medium |

### 2.9 Reports

| Action | What it allows | Also grants | Impact |
|---|---|---|---|
| **View reports** | Allows the user to see the list of reports and the data behind them. | None | Low |
| **Download reports** | Allows the user to download report files. | View reports | Low |
| **Generate reports** | Allows the user to create new reports and upload report files. | View reports | Medium |
| **Delete reports** | Allows the user to permanently delete report files. | View reports | High |
| **Take posture snapshots** | Allows the user to record the current security posture as a fixed point for later comparison. | View reports | Medium |

### 2.10 Agents

| Action | What it allows | Also grants | Impact |
|---|---|---|---|
| **View agents** | Allows the user to see agents, their status, roles and settings. | None | Low |
| **Download agent installer** | Allows the user to download the agent installer. | View agents | Low |
| **Enrol agents** | Allows the user to register agents and to create, view and revoke enrolment tokens. Anyone holding a token can connect a computer to this tenant until it expires or is revoked. | View agents | High |
| **Rename agents** | Allows the user to change an agent's display name. | View agents | Low |
| **Configure agents** | Allows the user to change an agent's settings, such as how often it reports and how deeply it scans. | View agents | Medium |
| **Assign agent roles** | Allows the user to switch roles on or off per agent: Scanner (runs scans), Sensor (passive listening), Inventory (reports its own software and SBOM), Collector (reads network devices). | Configure agents | Medium |
| **Enable threat sightings on agents** | Allows the user to let agents check the computer's DNS lookups and outbound connections against the tenant's threat list. Only matches are sent. The privacy notice covers users of those computers. | Configure agents | High |
| **Replace agent keys** | Allows the user to issue a new key to an agent. The old key stops working immediately, and the agent must be updated with the new key. | View agents | High |
| **Remove agents** | Allows the user to remove an agent from the tenant. The computer stops reporting until it is enrolled again. | View agents | High |

**What a user can make agents do.** These five actions control which jobs a user can send to
agents, wherever the button appears:

- Run active scans
- Run passive discovery
- Collect software inventory
- Run SBOM scans
- Map network devices

An agent also refuses any job its own role does not allow, whoever sends it.

### 2.11 Tenant settings

| Action | What it allows | Also grants | Impact |
|---|---|---|---|
| **View tenant settings** | Allows the user to see the tenant's scan policy and default agent settings. | None | Low |
| **Change scan policy** | Allows the user to decide whether new devices are investigated automatically, and whether agents may run scans started on their own computer. | View tenant settings | Medium |
| **Change default agent settings** | Allows the user to set the default settings for each kind of agent (computer, network, phone). Agents without their own override follow these defaults. | View tenant settings | Medium |

### 2.12 AI assistant

| Action | What it allows | Also grants | Impact |
|---|---|---|---|
| **Use AI assistant** | Allows the user to ask the assistant about the tenant's assets, alerts and advisories. The assistant only shows data the user can already view. | None | Low |

---

## 3. Presets

### Rules

- Choosing a preset ticks its actions. The grantor can add or remove any action before saving.
- Only the actions are saved, never the preset. A user's summary shows "Matches: Analyst" or
  "Custom".
- Changing a preset's definition later does not change existing users.
- The presets build on each other: Analyst includes Viewer, and Operator includes Analyst.

### Viewer: 15 actions. Sees everything and changes nothing.

View dashboard, View assets, View scans, View SBOMs, Download SBOMs, View alerts,
View advisories, View threat intelligence, View threat events, View network map,
View relationships, View reports, Download reports, View agents, Use AI assistant.

### Analyst: Viewer plus 12 actions (27 in total). Investigates and responds.

Dismiss duplicate warnings, Preview scan routing, Manage alerts, Bulk-update alerts,
Generate advisories, Update advisories, Close advisories from the assistant,
Create threat events, Edit threat events, Publish threat events, Manage relationships,
Generate reports.

### Operator: Analyst plus 17 actions (44 in total). Runs scans and manages assets and agents.

Add assets, Import assets, Edit assets, Recalculate risk scores, Collect software inventory,
Run active scans, Run passive discovery, Cancel scans, Run drift check, Run SBOM scans,
Map network devices, Edit topology, Download agent installer, Rename agents,
Configure agents, Assign agent roles, View tenant settings.

### Not in any preset: 14 actions, always granted one at a time

These delete data, cannot be undone, affect privacy, or change the whole tenant:

Delete assets, Merge duplicate assets, Clear software inventory, Delete SBOMs,
Delete threat events, Delete relationships, Delete reports, Take posture snapshots,
Enrol agents, Enable threat sightings on agents, Replace agent keys, Remove agents,
Change scan policy, Change default agent settings.

Total: 15 + 12 + 17 + 14 = 58.

---

## 4. Reserved actions (cannot be granted)

### Tenant Superadmin only, in their own tenant

- Invite users to the tenant, or add existing accounts
- Grant or remove actions for any user
- Deactivate or reactivate users
- Delete a user (section 4.1)
- Reset a user's MFA (section 7)
- View the tenant audit log
- Rename the tenant
- Set the successor and recovery approvers (section 6)
- Transfer tenant ownership (section 6)

### Platform Superadmin

- View every tenant's data and audit log, with a tenant filter
- **Provision tenant** (section 5)
- **Restore tenant ownership** (section 6, Path C)
- **End a tenant**: deactivate, reactivate, and delete (section 5.1)

The Platform Superadmin cannot add users to a tenant, grant actions, reset MFA, or create,
change or delete any record inside a tenant.

---

### 4.1 Deactivating and deleting users (Tenant Superadmin only)

| | Deactivate | Delete |
|---|---|---|
| **What it does** | Signs the user out and blocks sign-in. Everything is kept. | Removes the account permanently. |
| **Undo** | Reactivate at any time. | Not possible. |
| **Who can be targeted** | Any Tenant user of the same tenant | Any Tenant user of the same tenant |
| **Confirmation** | A confirm dialog | The Tenant Superadmin's password and MFA code, plus typing the user's username |

- Neither action can target yourself, the Tenant Superadmin, or the Platform Superadmin. The Tenant Superadmin changes only through section 6.
- **When a user is deleted:**
  - Their past actions stay in the audit log, shown as a deleted user with the username they had.
  - Alerts and advisories assigned to them become unassigned.
  - Their MFA and recovery codes are removed with the account.
- An account that appears in the ownership history (a transfer or a recovery, section 6) cannot be deleted. It can only be deactivated, so the history of who held ownership stays intact. The refusal says: "This account is part of the tenant's ownership history and cannot be deleted. Deactivate it instead."
- Dialog text for delete: "Delete [username]? This removes the account permanently and cannot be undone. Their past actions stay in the audit log. To keep the account, deactivate it instead."

## 5. Setting up a new tenant

1. The Platform Superadmin creates the tenant and enters the email of the nominated Tenant
   Superadmin.
2. The system sends that person a one-time invitation, valid for 72 hours.
3. The nominee accepts, sets a password, and sets up MFA before entering the tenant.
4. From then on, the Platform Superadmin cannot add users, grant actions, or change anything in
   the tenant.

The Platform Superadmin can resend or cancel the invitation only until it is accepted.

### 5.1 Ending a tenant

Ending a tenant has two stages, so a mistake can be reversed before any data is lost.

**Stage 1: Deactivate (reversible)**

1. The Platform Superadmin opens the tenant and chooses **Deactivate tenant**, giving a reason
   (for example "Contract ended").
2. They confirm with their password and MFA code.
3. From that moment:
   - No user of the tenant can sign in.
   - Agents of the tenant are refused, and no new jobs start.
   - All data is kept unchanged.
4. The Tenant Superadmin is emailed: "[Tenant] was deactivated on [date]. Its data will be
   permanently deleted on [date + 90 days] unless it is reactivated."
5. During the 90 days, the Platform Superadmin can choose **Reactivate tenant**. Everything
   returns as it was.

**Stage 2: Delete (permanent)**

1. **Delete tenant** becomes available only after the 90-day retention period.
2. The Platform Superadmin types the tenant's name and confirms with their password and MFA code.
3. All of the tenant's data, users and agents are permanently deleted. This cannot be undone.
4. The platform audit log keeps one record: who deleted which tenant, and when. No tenant data
   is kept in that record.

The Tenant Superadmin is reminded by email 30 days and 7 days before deletion.

---

## 6. Ownership handover

### Path A: Planned transfer (resignation, change of role)

The current Tenant Superadmin starts it.

1. Open **Settings → Tenant ownership → Transfer ownership**.
2. Choose the new Tenant Superadmin from the active users in the tenant.
3. Choose what happens to your own account afterwards:
   - **Stay as a Tenant user**, with the actions you select now (or a preset).
   - **Deactivate on a date**, keeping the actions you select until then.
   - **Deactivate immediately** after the transfer.
4. Confirm with your password and MFA code.
5. The recipient receives an email and an in-app request, and has 72 hours to **Accept** or
   **Decline**. Accepting needs their password and MFA code.
6. You can cancel the request any time before it is accepted.
7. On acceptance, ownership moves in one step. The tenant never has two owners or none.

Message shown to the recipient:

> "[Name] wants to make you the Tenant Superadmin of [Tenant]. You will be able to grant and
> remove access for every user, reset MFA, and transfer ownership. [Name] will become a Tenant
> user [or: will be deactivated on date]."

### Path B: Emergency recovery inside the tenant

For when the owner left without a handover, was terminated, cannot be reached, or their
account was compromised. No Platform Superadmin is involved.

The Tenant Superadmin sets these up in advance:

- **Successor:** one active user who would take over.
- **Recovery approvers:** two other active users who confirm an emergency.

Until all three are set, the Tenant Superadmin sees a persistent banner: "No recovery plan. If
you lose access, your tenant cannot recover without platform verification."

Steps:

1. The successor opens **Tenant ownership → Start emergency recovery** and chooses a reason:
   Terminated, Account compromised, Resigned without handover, or Unreachable.
2. Both recovery approvers confirm with their password and MFA code within 72 hours. If they do
   not, the request expires.
3. What happens next depends on the reason:
   - **Terminated or Account compromised:** the change takes effect immediately. The current
     owner is suspended (signed out everywhere and blocked from signing in), and the successor
     becomes Tenant Superadmin.
   - **Resigned without handover or Unreachable:** a 72-hour hold begins. The current owner is
     emailed and can cancel with their password and MFA code. If they do not cancel, ownership
     moves when the hold ends.
4. If the current owner cancels, or later disputes the change, the case moves to Path C.

### Path C: Platform-verified recovery (last resort)

Only when Path B cannot work: no successor or approvers remain, or the change is disputed.

1. An authorised officer of the organisation (for example the head of IT or HR) sends a written
   request through the official support channel, naming the new Tenant Superadmin.
2. The Platform Superadmin verifies the request independently, by calling back the organisation
   contact on record. Contact details given in the request itself are not used.
3. The Platform Superadmin performs one action, **Restore tenant ownership**. This sends a
   one-time owner invitation to the named person, as in section 5. The former owner is
   suspended at the same time.
4. The Platform Superadmin still gains no access to the tenant.
5. Every user in the tenant sees a notice for 30 days: "Ownership of this tenant was restored by
   platform verification on [date]."

### Safeguards on every path

- The Tenant Superadmin cannot deactivate themselves, leave the tenant, or be deactivated except
  through Path A, B or C.
- Every step needs a password and MFA code, and is written to the tenant audit log. The Platform
  Superadmin sees these events in cross-tenant monitoring.
- The former owner, the new owner, and the approvers are emailed at each step. All tenant users
  get an in-app notice: "Tenant ownership changed from [A] to [B] on [date]."
- **Done automatically in an emergency (Path B or C):**
  - Sign the former owner out of every session.
  - Cancel pending invitations the former owner sent.
  - Revoke all unused agent enrolment tokens.
- **The new owner's first sign-in shows a security checklist:**
  - Review every user's actions.
  - Choose a new successor and recovery approvers. The former owner and the new owner are
    removed from these positions automatically.
  - Reassign alerts and advisories assigned to the former owner.
  - After an emergency only: consider replacing agent keys.
- The former owner's account is never deleted. It stays, deactivated or as a Tenant user, so the
  history of who did what remains intact.

---

## 7. MFA

### Required for every account

- Every account, the Platform Superadmin included, must have MFA.
- A new account sets up MFA at its first sign-in, before it can see anything.
- Existing accounts without MFA must set it up at their next sign-in. There is no grace period.
- Signing in with Google also asks for the MFA code.
- When MFA is set up, the user receives 10 one-time recovery codes, shown once. A recovery code
  can be used instead of the MFA code if the device is lost.

### Reset a user's MFA (Tenant Superadmin only)

| | |
|---|---|
| **What it does** | Removes the user's MFA device and signs them out. They must set up MFA again at their next sign-in. |
| **Confirmation** | The Tenant Superadmin's password and MFA code |
| **Guidance shown on screen** | "Confirm this request in person or by phone. Do not reset MFA based only on an email or chat message, because these are common ways attackers take over accounts." |
| **Record** | An audit log entry, and an email to the user: "Your MFA was reset by [Name] on [date]. If you did not ask for this, contact them immediately." |

### If the Tenant Superadmin loses their own MFA

They sign in with a recovery code. If the recovery codes are also lost, Path B applies, with
the reason Account compromised or Unreachable.

### If a Platform Superadmin loses their MFA (proposed)

There is one Platform Superadmin and no tenant above the platform, so recovery must be prepared
in advance. Three layers make losing access very unlikely, and none of them needs a database
change.

**Layer 1: A backup authenticator device**

- When the Platform Superadmin sets up MFA, they scan the same QR code on two devices: their
  phone, and a backup device (for example a spare phone or tablet) kept in a locked place.
- Both devices show the same codes, so losing the phone does not lock the account. The person
  signs in with the backup device and sets up MFA again on a new phone.
- This needs no new feature. A hardware security key (passkey) can replace the backup device
  later, as a stronger option.

**Layer 2: Recovery codes kept offline**

- The 10 recovery codes are printed and sealed in an envelope, stored apart from the backup
  device, or stored in the organisation's password manager.
- When a code is used, an email is sent to the Platform Superadmin's address.

**Layer 3: Break-glass reset, authorised through the hosting account**

For when the device, the backup device and the recovery codes are all lost.

1. The owner of the platform's Cloudflare account signs in to Cloudflare, which has its own MFA,
   and sets a one-time reset secret for the application (`wrangler secret put
   PLATFORM_MFA_RESET`).
2. The Platform Superadmin opens the sign-in page and chooses **Lost all MFA methods**. They
   enter their email, their password, and the reset secret.
3. The system emails a confirmation link to the Platform Superadmin's address. The reset waits
   24 hours after the link is opened. During that time a cancel link in the same email stops it.
4. After the hold, the Platform Superadmin signs in and sets up MFA again, on two devices as in
   Layer 1. A new set of recovery codes is issued.
5. The reset secret works once only. The application records its use and refuses it afterwards,
   so a new secret is needed for any later reset.
6. Every step is written to the platform audit log.

Why this is safe: anyone who controls the Cloudflare account can already deploy any code, so
this adds no new way in. It needs three things at once: the hosting account (with its own MFA),
the Platform Superadmin's password, and their email inbox. The 24-hour hold gives the real owner
time to cancel.

**Database access**

Direct database access stays restricted to the platform's infrastructure credentials. It is
never part of any recovery procedure.

**If a second Platform Superadmin is added later**

A peer reset can then be added: one Platform Superadmin resets the other's MFA, with the same
24-hour hold and email cancel link. Layer 3 remains as the fallback.

---

## 8. Converting existing accounts

| Current role | After migration |
|---|---|
| **superadmin** | Platform Superadmin: view only across tenants, plus Provision tenant and Restore tenant ownership. |
| **tenant_superadmin** | Tenant Superadmin. If a tenant has more than one, the oldest active account stays Tenant Superadmin. The others become Tenant users with all 58 actions, so they lose only the reserved actions, and they are notified. A read-only check before migration lists these tenants, so the choice can be made by hand. |
| **tenant_admin** | Tenant user with 53 actions: Operator plus Clear software inventory, Delete SBOMs, Delete threat events, Delete relationships, Delete reports, Enrol agents, Enable threat sightings on agents, Replace agent keys, Remove agents. Not granted, because they cannot do these today: Delete assets, Merge duplicate assets, Take posture snapshots, Change scan policy, Change default agent settings. |
| **business_owner** | Tenant user with 13 actions: Viewer except View scans and View relationships. They cannot see the Discovery page or relationships today. |

### 8.1 Rollout in two steps (shared database)

The staging and production databases are shared with code that still uses the old roles. The
conversion therefore happens in two steps, so that old and new code both work in between.

**Step 1, expand (migration 0035).** Additive only:

- Add the role value `tenant_user`.
- Add a nullable `actions` column.

Old roles stay in the database, and no row changes. New code reads a `tenant_admin` or
`business_owner` row as a Tenant user. When `actions` is empty (NULL), that user gets the action
set from the table above. When a Tenant Superadmin edits such a user's actions, new code writes
`actions` and leaves the old role as it is, so old code still works for that user. Old code
never fails for `tenant_user`: role-gated routes return 403, open read routes return its own tenant's data.

**Step 2, contract (migration 0036).** This runs only after every copy of the code that uses
these databases is on the new code, so the project owner and teammate agree first. It:

- converts the remaining old-role rows, keeping any actions already edited;
- applies the one-Tenant-Superadmin rule;
- removes the old role values;
- adds the unique index.

A restore point is taken first.

**Rollback.**
- After step 1: redeploy the previous worker and frontend. The database needs no change.
- After step 2: restore from the restore point.

### What the Platform Superadmin loses

Registering users, inviting and assigning users, changing roles, deactivating users, MFA reset,
creating, editing and deleting threat events, refreshing threat feeds, and renaming tenants.
Deactivating, reactivating and deleting tenants stay with the Platform Superadmin (section 5.1).

### Notice to converted users

Every converted Tenant user receives one email: "Your access is now shown as individual actions.
You can still do everything you could do before."

---

## Open points

1. **Platform Superadmin MFA recovery (section 7).** Approve the three layers for a single
   Platform Superadmin: a backup authenticator device, offline recovery codes, and a break-glass
   reset authorised through the Cloudflare account.
