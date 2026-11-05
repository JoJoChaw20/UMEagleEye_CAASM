---
name: UMEagleEye
description: A CAASM console in the EagleEye logo's colours, with a navy rail, ink-tinted neutrals and electric-blue circuit traces.
colors:
  eagle-blue: "#1A8CFF"
  eagle-deep: "#0B6FF0"
  eagle-bright: "#38A8FF"
  eagle-light-text: "#70C2FF"
  eagle-ink: "#0B2452"
  eye-cyan: "#2BC8FF"
  rail: "#08101F"
  rail-raised: "#111E36"
  rail-line: "#1B2A46"
  rail-text: "#E2EAF6"
  rail-muted: "#8698B8"
  ink-ground: "#060B17"
  ink-sunken: "#0B1221"
  ink-surface: "#131D32"
  ink-line: "#26334D"
  ink-line-strong: "#485775"
  ink-text-strong: "#F3F6FC"
  ink-text: "#E1E8F4"
  ink-text-secondary: "#C4D0E4"
  ink-text-muted: "#8A9BB8"
  ink-text-faint: "#7485A3"
  paper-ground: "#ECF1F8"
  paper-sunken: "#F4F7FB"
  paper-surface: "#FFFFFF"
  paper-line: "#DBE2ED"
  paper-line-strong: "#BEC9DA"
  paper-text-strong: "#050B19"
  paper-text: "#0D1629"
  paper-text-muted: "#4B5A75"
  paper-eagle-text: "#0A63D6"
  sev-critical: "#FF4D5E"
  sev-high: "#FF8A3D"
  sev-medium: "#FFC23D"
  sev-low: "#2FD58F"
  sev-critical-light: "#DC2638"
  sev-high-light: "#E66E14"
  sev-medium-light: "#CA8A04"
  sev-low-light: "#10A064"
  status-green: "#22D391"
  status-amber: "#FFB82E"
  status-red: "#FF5C66"
  status-purple: "#9D8CFF"
  series-indigo: "#7882FF"
  series-steel: "#9EB0CC"
  series-magenta: "#EC6EBE"
  on-brand: "#FFFFFF"
typography:
  display:
    fontFamily: "Chakra Petch, Geist Variable, system-ui, sans-serif"
    fontSize: "26px"
    fontWeight: 600
    lineHeight: "32px"
    letterSpacing: "-0.005em"
  headline:
    fontFamily: "Chakra Petch, Geist Variable, system-ui, sans-serif"
    fontSize: "18px"
    fontWeight: 600
    lineHeight: "24px"
    letterSpacing: "-0.005em"
  title:
    fontFamily: "Chakra Petch, Geist Variable, system-ui, sans-serif"
    fontSize: "16px"
    fontWeight: 600
    lineHeight: "24px"
    letterSpacing: "-0.005em"
  figure:
    fontFamily: "Chakra Petch, Geist Variable, system-ui, sans-serif"
    fontSize: "32px"
    fontWeight: 600
    lineHeight: 1
    fontFeature: "tnum"
  figure-hero:
    fontFamily: "Chakra Petch, Geist Variable, system-ui, sans-serif"
    fontSize: "44px"
    fontWeight: 600
    lineHeight: 1
    fontFeature: "tnum"
  body:
    fontFamily: "Geist Variable, Geist, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: "20px"
    fontFeature: "ss01, cv11"
  body-small:
    fontFamily: "Geist Variable, Geist, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: "16px"
  label:
    fontFamily: "Geist Variable, Geist, system-ui, sans-serif"
    fontSize: "11px"
    fontWeight: 500
    lineHeight: "16px"
    letterSpacing: "0.06em"
  nav-group:
    fontFamily: "Chakra Petch, Geist Variable, system-ui, sans-serif"
    fontSize: "11px"
    fontWeight: 600
    lineHeight: "16px"
    letterSpacing: "0.12em"
  mono:
    fontFamily: "Geist Mono Variable, Geist Mono, ui-monospace, Cascadia Code, Consolas, monospace"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: "16px"
rounded:
  sm: "3px"
  DEFAULT: "4px"
  md: "6px"
  lg: "8px"
  xl: "10px"
  2xl: "12px"
  3xl: "16px"
spacing:
  "1": "4px"
  "1.5": "6px"
  "2": "8px"
  "3": "12px"
  "4": "16px"
  "5": "20px"
  "6": "24px"
components:
  button-primary:
    backgroundColor: "{colors.eagle-deep}"
    textColor: "{colors.on-brand}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: "8px 14px"
  button-primary-hover:
    backgroundColor: "{colors.eagle-blue}"
    textColor: "{colors.on-brand}"
  button-secondary:
    backgroundColor: "{colors.ink-surface}"
    textColor: "{colors.ink-text-secondary}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: "8px 14px"
  button-secondary-hover:
    textColor: "{colors.ink-text-strong}"
  button-ghost:
    textColor: "{colors.ink-text-muted}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: "8px 14px"
  button-danger:
    textColor: "{colors.status-red}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: "8px 14px"
  input-field:
    backgroundColor: "{colors.ink-sunken}"
    textColor: "{colors.ink-text}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: "8px 14px"
  panel:
    backgroundColor: "{colors.ink-surface}"
    rounded: "{rounded.xl}"
    padding: "20px"
  badge:
    typography: "{typography.label}"
    rounded: "{rounded.md}"
    padding: "2px 8px"
  tab-toggle:
    textColor: "{colors.ink-text-muted}"
    rounded: "{rounded.md}"
    padding: "7px 14px"
  tab-toggle-active:
    backgroundColor: "{colors.ink-surface}"
    textColor: "{colors.eagle-bright}"
  nav-item:
    textColor: "{colors.rail-muted}"
    rounded: "{rounded.md}"
    height: "36px"
    padding: "0 10px"
  nav-item-active:
    backgroundColor: "{colors.rail-raised}"
    textColor: "{colors.on-brand}"
  kbd:
    backgroundColor: "{colors.ink-surface}"
    textColor: "{colors.ink-text-muted}"
    typography: "{typography.mono}"
    rounded: "{rounded.DEFAULT}"
    padding: "0 6px"
---

# Design System: UMEagleEye

## Overview

**Creative North Star: "The Eagle's Field of View"**

The interface is what the eagle sees. A navy rail and ink-tinted neutrals carry the logo's world, and electric-blue circuit traces link what the admin sees to what they act on. The palette, the type and the one ornament all come from the EagleEye logo: navy-black ink, the electric-blue wing (#1A8CFF to #0B6FF0), the cyan eye and the chamfered wordmark. Nothing is imported from the generic "cyber" category.

The density is tuned for one or two admins doing daily triage: solid panels on a tinted ground, 14px interface text, 11px uppercase table headings, tabular figures throughout and tight corners. Depth comes from tonal steps and 1px lines. The only decoration is the circuit trace: a 1px line that ends in a ring node. It closes page titles, runs beside section headings, marks panel headings, carries the navigation as a bus, ends every sparkline and tips the posture dial. Light, dark and system themes are required. Every colour is an "R G B" custom property that `html.light` swaps, except the rail and the brand blues, which stay the same in every theme.

The system rejects the category default: glass cards on near-black, neon glow edges, gradient text, and matrix-green "hacker" chrome.

**Key Characteristics:**
- A navy rail (#08101F) holds the logo and navigation in every theme.
- Neutrals are tinted toward blue in both themes, never pure grey.
- Chakra Petch is used for headings and figures, Geist for the interface, and Geist Mono for identifiers only.
- Panels are solid with a 1px line, a 10px corner and a faint two-layer shadow. There is no blur.
- The circuit trace with ring nodes is the one signature motif.
- Motion uses an expo ease-out (cubic-bezier(0.16, 1, 0.3, 1)) over 150 to 320ms, and pulses and sweeps turn off under reduced motion.

## Colors

The palette is navy ink and electric blue taken from the logo. Severity hues are kept for risk, and cyan is kept for things that are live.

### Primary
- **Electric Wing Blue** (eagle-blue): the brand blue. It is used for button hover, the trace end, the focus ring base, selection tint (32% alpha) and chart series 1.
- **Deep Wing Blue** (eagle-deep): primary button fill and the avatar tiles. White text sits on it through the on-brand rule.
- **Bright Wing Blue** (eagle-bright): focus outlines (2px, 2px offset), ring-node strokes, active tab text, links and caret colour. In light mode it is remapped to Paper Eagle Text so it stays readable on white.
- **Pale Wing Blue** (eagle-light-text): active nav icons and link hover on dark grounds.

### Secondary
- **Eye Cyan** (eye-cyan): kept for live state. It is used for the agents-online radar dot, the live "Updated" dot and the passive-scan series. It is never used as a decorative accent.

### Tertiary
- **Severity set** (sev-critical, sev-high, sev-medium, sev-low, with `-light` counterparts): used for risk only, in charts, the posture dial bands and severity sparklines.
- **Status accents** (status-green, status-amber, status-red, status-purple): health, warning, destructive and in-progress states. Purple is used only for the in-progress lifecycle badge.
- **Series** (eagle-blue, eye-cyan, series-indigo, series-steel, status-amber, series-magenta): categorical chart colours, with the logo-derived colours first.

### Neutral
- **Navy Rail** (rail), **Rail Raised** (rail-raised), **Rail Line** (rail-line), **Rail Text** (rail-text), **Rail Muted** (rail-muted): the sidebar's own neutral set. They are identical in every theme.
- **Ink Ground / Sunken / Surface** (ink-ground, ink-sunken, ink-surface): the dark theme's page ground, header and input wells, and panels, in rising tonal steps.
- **Ink Line / Ink Line Strong** (ink-line, ink-line-strong): 1px borders at 80% alpha, and borders on hover.
- **Ink Text Strong / Text / Secondary / Muted / Faint**: titles and figures, body text, button labels, descriptions and table heads, then placeholders and hints.
- **Paper Ground / Sunken / Surface / Line / Text**: the light theme's values for the same roles. The token scale is inverted: `dark-50` is always the strongest text and `dark-950` is always the page ground.

### Named Rules
**The Navy Rail Rule.** The rail is navy (#08101F) in light, dark and system themes. Rail colours never come from the themed neutral scale, and the silver-wordmark lockup is the only lockup used on it.

**The Live Cyan Rule.** Cyan means something is happening now, such as an agent online or a live update. Do not use it for emphasis, for decoration or for a second brand colour.

**The Zero Stays Quiet Rule.** Severity and warning colour appears only when its count is above 0. A zero renders in neutral text, and the tile tone falls back to neutral.

**The On-Brand White Rule.** White text on brand-blue or navy surfaces uses `.text-on-brand`, never `text-white`. In light mode, `text-white` is remapped to dark ink.

**The Token-Only Rule.** Every colour resolves to a theme custom property through Tailwind's `rgb(var(--token) / alpha)` scale. Literal hex values do not belong in components.

## Typography

**Display Font:** Chakra Petch 500/600/700 (fallback Geist Variable, system-ui)
**Body Font:** Geist Variable (fallback Geist, system-ui, Segoe UI)
**Label/Mono Font:** Geist Mono Variable (fallback ui-monospace, Cascadia Code, Consolas)

**Character:** Chakra Petch is chamfered like the EagleEye wordmark, so headings and numbers speak in the logo's voice. Geist keeps dense tables and forms quiet and legible. All fonts are self-hosted through @fontsource.

### Hierarchy
- **Display** (page title): used once per page, followed by a short circuit trace and ring node.
- **Headline** (section headings): followed by a trace line that runs to the section's actions.
- **Title** (panel headings): led by a 7px ring node.
- **Figure / Figure Hero** (KPI values at 32px, the posture dial at 44px): use tabular numerals.
- **Body** (14px/20px): interface text, with `ss01` and `cv11` on. Descriptions under titles use the muted tone and a maximum width of about 48rem.
- **Label** (11px, uppercase, 0.06em): table headers on a sunken band.
- **Nav group** (Chakra Petch 11px, uppercase, 0.12em): rail section labels and command-palette group titles only.
- **Mono** (12px): IPs, MACs, CVE IDs, hashes and versions.

### Named Rules
**The Wordmark Voice Rule.** `h1`, `h2` and `h3` and the big figures use Chakra Petch 600 with -0.005em tracking and balanced wrapping. Body copy, buttons and table cells never use it.

**The Mono Means Identifier Rule.** Geist Mono is only for machine identifiers and keyboard hints. Never use it for labels, headings or general numbers.

## Layout

The app shell is a fixed rail and a fluid workspace. The rail is 256px wide, or 64px when collapsed, and the choice is saved per browser. Below 1024px it becomes an off-canvas drawer over a 70% ground-colour scrim. The header is a 64px sticky bar on the sunken tone. It holds the sidebar toggle, the Ctrl+K command trigger (36px), a three-way theme switch (dark, light, system), notifications and profile. Page content has 16px padding, or 24px from 1024px up.

The spacing rhythm is on a 4px base. 8px and 12px gaps are used inside controls and rows, 16px between panels, 20px is the panel padding and 24px is used for page sections. Dashboards use 2-column and 3-column panel grids. Tables run full width inside a panel with 16px cell padding.

## Elevation & Depth

The system is mostly flat and uses tonal layering. The ground, sunken and surface steps carry the hierarchy, and a 1px line at 80% alpha defines each panel. Shadows use a themed `--shadow` colour: pure black in dark mode and navy (15 30 60) in light mode. They stay faint at rest and are reserved for things that float. There is no blur or translucency anywhere.

### Shadow Vocabulary
- **Panel** (`box-shadow: 0 1px 2px rgb(var(--shadow) / 0.06), 0 2px 8px -2px rgb(var(--shadow) / 0.10)`): every panel and stat card.
- **Float** (`box-shadow: 0 12px 32px -8px rgb(var(--shadow) / 0.35), 0 2px 6px rgb(var(--shadow) / 0.12)`): the command palette, menus, the notification tray and the open drawer.
- **Button lift** (`box-shadow: 0 1px 2px rgb(var(--shadow) / 0.25)`): primary buttons only.

### Named Rules
**The Solid Panel Rule.** Panels are opaque surfaces with a 1px line. Never use backdrop blur, translucent cards or glow edges. Overlays get the float shadow and a solid scrim.

## Shapes

Corners are tight because the logo is angular. The scale replaces Tailwind's defaults: 3px, 4px, 6px for controls, 8px, 10px for panels and overlays, then 12px and 16px. Borders are always 1px. Circles are used only for circuit nodes, status dots and the notification count, never for chips, tags or buttons.

**The Tight Corner Rule.** Controls, chips and badges use 6px corners and panels use 10px. Pills are not part of the language.

## Components

### Buttons
Every variant has one shape and one height, and each press settles 1px down.
- **Shape:** 6px corners, 8px 14px padding, 14px medium text, an 8px gap for a 16px lucide icon.
- **Primary:** Deep Wing Blue fill and border, white label and the button-lift shadow. On hover it shifts to Electric Wing Blue.
- **Secondary:** surface fill, 1px ink line, secondary-tone label. On hover the line and text strengthen.
- **Ghost:** borderless, muted label, with a 40% line-tone wash on hover.
- **Danger:** status red at 10% fill, 30% border and red label. The fill rises to 20% on hover.
- **Disabled:** 50% opacity, a not-allowed cursor and no press motion.

### Chips and Badges
- **Style:** 11px semibold, 6px corners, 2px 8px padding, a 10% tinted fill and a 30% tinted 1px border.
- **Variants:** critical, high, medium and low for severity. Open, in progress and resolved for lifecycle.
- **Counts in tabs:** a 6px-corner chip at 15% eagle tint.

### Cards / Containers
- **Corner Style:** 10px.
- **Background:** the surface step (ink-surface in dark mode, white in light mode).
- **Shadow Strategy:** the Panel shadow (see Elevation & Depth).
- **Border:** a 1px ink line at 80% alpha. Clickable stat cards raise the border to 50% Electric Wing Blue and lift 1px on hover.
- **Internal Padding:** 20px.

### Inputs / Fields
- **Style:** a sunken well with a 1px ink line, 6px corners and 8px 14px padding. Placeholders use the faint tone.
- **Focus:** the border turns Electric Wing Blue with a 3px ring at 20% alpha. Elsewhere, focus is a 2px Bright Wing Blue outline at 2px offset.
- **Selects:** native behaviour with a themed two-stroke chevron that turns blue on hover.
- **Disabled:** 60% opacity.

### Navigation
- **Rail:** each group has a Chakra Petch uppercase label. Items are 36px high with 16px lucide icons and sit on a vertical 1px bus with 5px dots. The active item gets a raised navy fill, white label and pale-blue icon, and its dot becomes a 9px ring node joined to the item by an 8px trace.
- **Collapsed rail:** 40px icon tiles, with a 1px inset blue ring on the active tile.
- **Rail foot:** the live agent pulse, which is cyan when all agents are online, amber when some are down and red when none are, then the user tile and log out.
- **Tabs:** 13px medium labels. The active tab sits on the surface step with a 1px inset blue ring and Bright Wing Blue text.
- **Mobile:** below 1024px the rail becomes a drawer, and the header shows the emblem mark in its place.

### Circuit Trace (signature)
This motif comes from the logo's wing traces. It is a 1px line that fades from the ink line to 55% Electric Wing Blue and ends in a 7px ring node with a 1.5px Bright Wing Blue stroke.
- Page titles are closed by a 44px trace and ring.
- Section headings place a trace between the title and the actions. It is hidden below 768px.
- Panel headings lead with a ring node.
- The trace loader moves a node along a 72px line.

### Posture Gauge and Sparklines
- **Gauge:** a 168px dial with a 270-degree arc, an 8px stroke on an ink-line track and ticks at each quarter. The value sweeps in over 1100ms with expo ease-out and ends in a ring node. Bands are below 50 for At risk, below 80 for Needs attention, and Good, which uses blue rather than green.
- **Sparkline:** a 1.5px line over an area fill fading from 20% to 0% that ends in a ring node. It can take an optional dashed comparison guide. With fewer than two real points it renders "Not enough history yet" instead of a line.

### Command Palette
A 640px solid panel opened with Ctrl/Cmd+K, or "/" when the user is not typing. The scrim fades in over 160ms and the panel rises over 220ms. Group titles use the nav-group type. The selected row gets a 10% eagle wash, a 1px blue trace mark at its left edge and a return-key icon. Keyboard hints use 4px-corner mono keycaps.

### Live Dot
An 8px status dot with a radar ping in its own colour, running for 2.2s with expo ease-out. The ping is removed under reduced motion.

## Do's and Don'ts

### Do:
- **Do** take every colour from the theme tokens, and check every change in dark, light and system modes.
- **Do** keep the rail navy and use the silver-wordmark lockup on it. Use the dark-ink lockup on light grounds, and use the emblem alone where space is tight.
- **Do** put white text on brand or navy surfaces through `.text-on-brand`.
- **Do** colour a severity or warning only when its count is above 0.
- **Do** close page and section titles with the circuit trace and ring node, and lead panel headings with a ring node.
- **Do** draw sparklines only from real history, and show "Not enough history yet" when there is none.
- **Do** use lucide icons at 14 to 18px for every icon.
- **Do** use the expo ease-out curve at 150 to 320ms, and keep page transitions to opacity only so fixed-position dialogs still work.

### Don't:
- **Don't** use glass, backdrop blur, gradient text, neon glow edges or matrix-green chrome.
- **Don't** use `text-white`. It is remapped to dark ink in light mode.
- **Don't** make chips, badges or tags into pills. They use 6px corners.
- **Don't** put thick coloured side stripes on cards, rows or callouts. The only edge marks are the 1px trace on a selected palette row and the nav bus.
- **Don't** use emoji or text glyphs as icons.
- **Don't** use cyan as decoration, or Geist Mono for anything other than identifiers and keycaps.
- **Don't** invent trend data or pad a sparkline with synthetic points.
