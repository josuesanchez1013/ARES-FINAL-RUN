# ARES UI visual standard

Draft for docs/ARCHITECTURE.md section 9. The source of truth for values is
`frontend/src/styles.css`; `scripts/check_contrast.py` fails if a pairing below
drops under its minimum.

## Principles

- Professional and quiet. No emoji anywhere in the frontend. Text from the
  pipeline is shown with pictographs stripped.
- A state is never shown by colour alone: every status has a label, and badges
  add an icon.
- Red means something failed: an Open finding, a failed step, an agent error.
  Command output is evidence and is always plain, whatever its exit code.
- A click never reloads the page. Every button says what it does.

## Type

IBM Plex Sans for interface text, IBM Plex Mono for rule numbers, run IDs,
commands and output. Both are bundled; nothing loads from the network.

| Role | Size / weight |
|---|---|
| Page title | 22 / 600 |
| Section title | 16 / 600 |
| Body, controls | 14 / 400, 500 for controls |
| Secondary text | 13 / 400 |
| Badge | 12 / 600 |
| Headline number | 28 / 600, tabular figures |

Sentence case throughout. No all-caps labels.

## Colour

| Token | Light | Dark | Use |
|---|---|---|---|
| canvas | #F4F5F7 | #12161B | Page |
| panel | #FFFFFF | #1B2128 | Cards, tables, navigation |
| sunken | #EEF0F3 | #151A20 | Console, table header, hover |
| ink | #17202A | #E6EAEF | Text |
| muted | #56616D | #A3ADB8 | Secondary text |
| line | #D3D9E0 | #343D48 | Borders |
| accent | #1D5A8C | #7AB2E3 | Primary button, selection, focus |

Status map, used by badges, charts, legends and the console alike:

| Status | Mark | Text light / dark | Icon |
|---|---|---|---|
| Open, failure | #D03B3B | #A32626 / #F4A3A3 | circle-alert |
| Not a finding, success | #0CA30C | #0A6B0A / #7FD67F | check |
| Not reviewed, needs attention | #FAB219 | #7A4F00 / #F6C453 | circle-dashed, triangle-alert |
| Not applicable, ended | #8A94A0 | #4A5560 / #BCC4CD | circle-minus |
| In progress, information | #2A78D6 | #1D5A8C / #9CC6F1 | loader-circle, info |

Text pairs meet 4.5:1 and marks meet 3:1 in both themes.

## Themes

Light and dark follow the system setting. The Theme control (System, Light,
Dark) overrides it and is remembered per browser.

## Icons

One set: Lucide, 16 px, 1.75 stroke, inheriting text colour. Icons accompany a
label; an icon-only button carries an accessible name.

## Components

Button (primary, default, quiet, danger text), segmented control, select,
choice chip (radio / checkbox), file drop, badge, notice (info, good, warning,
critical), panel, headline tile, step timeline, activity console, segmented
bar and bar rows for charts, data table with pager, detail drawer, review card.

Charts: one whole split by verdict is a segmented bar with a legend that
carries the counts; segments are separated by a 2 px gap. Values are printed
beside every bar, so no chart depends on hover.
