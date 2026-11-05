---
version: 1
slug: "frontend-src-components-layout-mainlayout-jsx"
primary_target: "frontend/src/components/layout/MainLayout.jsx"
related_targets: ["frontend/src/pages/DashboardPage.jsx","frontend/src/pages/LoginPage.jsx"]
---

## Scope

App shell (sidebar rail, header, command palette), login, dashboard, and the shared component system every authenticated page inherits. Mode: Operate. Primary user: small-org IT/security admin doing daily triage. Constraints: keep dark, light and system themes; keep every feature, route, data call and page function; other pages adopt the system without layout changes.

## Direction contract

THESIS: The interface is the eagle's field of view. A navy rail and ink-tinted neutrals carry the logo's world, and electric-blue circuit traces link what the admin sees to what they act on. Refuses the category default: glass cards on near-black, neon glow edges, gradient text, matrix-green "hacker" chrome.

OWN-WORLD: Logo palette as tokens. Navy ink rail (#08101F) in both themes; neutrals tinted toward blue (dark ground #060B17, light ground #ECF1F8); electric blue scale (primary #1A8CFF / button #0B6FF0); cyan #2BC8FF reserved for live state and the eye. Chakra Petch (chamfered, like the wordmark) for headings and figures; Geist for UI; Geist Mono only for identifiers. Corners tight (6/8/10 px), 1px borders, no blur.

STORY: The admin lands, reads posture and what changed, jumps anywhere with Ctrl+K, and acts on the top priority without hunting.

FIRST VIEWPORT: Navy rail left (lockup, nav on a circuit bus with ring nodes, live agent pulse at foot). Header: Ctrl+K command trigger, theme switch, notifications, profile. Dashboard: title row with tenant and refresh; posture dial with 30-day sparkline at left third; four KPI tiles 2x2 at right; Priority Action Centre below.

FORM: Pinned by the brief (logo-derived world, user-chosen interactions: command palette, posture gauge + sparklines, circuit-trace accents, scan pulse). seed:9a0e5db1870ccc0d (roll run after the build at review; the brief-pinned, logo-derived direction beats the roll, so the assignment was not adopted). Signature move: the circuit trace with ring nodes (nav bus, section rules, focus, loaders). Motion: 160-320 ms expo ease-out; pulses and dial sweep off under reduced motion.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
