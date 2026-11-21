# UI design

ASI is a working tool for security analysts who read hundreds of hosts a day. The interface is dense, calm and
literal: a lot of data per screen, colour only where it carries meaning, plain words. It should look like an
instrument, not a marketing dashboard.

The system is `internal/web/static/app.css`. Every component is rendered in `/static/styleguide.html`
(`internal/web/static/styleguide.html`): open it before building a page and copy the markup from there.

## Rules

1. Pages compose existing classes. No new colours, font sizes, spacing values, shadows or border radii in templates
   or in new CSS. No `style=` attributes and no `<style>` blocks (the Content-Security-Policy blocks them anyway).
2. A missing component is added to `app.css` and to the styleguide in the same change, built from the existing tokens,
   and named in the PR body.
3. Colour is a signal with one meaning everywhere:

   | Token | Meaning |
   |---|---|
   | `--green` | navigation and the primary action of a page; nothing else |
   | `--ok` | active, seen, saved |
   | `--warn` | unstable, staging, expiring |
   | `--off` | inactive |
   | `--new` | new or returned host or service |
   | `--changed` | changed |
   | `--alert` | missing, error, admin panel, notable header or cookie, high interest |

   Colour never stands alone: a status is a mark plus a word (`.status`, `.change`), a finding is a labelled `.kind`.
4. Numbers that are compared sit in `.num` cells (right-aligned, tabular figures). Addresses, ports, hashes, header
   names and other literal values use `.addr` / `<code>`.
5. One primary button per page (`.primary`). Destructive actions use `.danger` and sit last.

## Layout

- Every page starts with `.page-head`: an `<h1>` naming what the page lists or edits, an optional `.lede` with the one
  fact the reader needs (counts, last run), actions on the right.
- Summary numbers go in one `.figures` strip, at most six. Do not build grids of cards.
- Lists are `table.data` inside `.table-wrap`, with `.filters` above and `.result-line` + `.pager` for paging. Sorting
  is a link in the header with `aria-sort`. A table shows 50 rows by default.
- Detail pages use `.panel` sections; several panels side by side go in `.cols`. Label/value pairs are `dl.kv`.
- History per run is a `.presence` strip (oldest left); small distributions are `.bars` with `<progress class="bar">`.
- Old and new values are `.diff` with `<del>` and `<ins>`.
- Every list has an `.empty` state that says what is missing and offers the action that fills it.

## Words

- Sentence case everywhere. No all-caps labels, no decorative labels above headings, no emoji, no exclamation marks.
- Name things as an analyst would: host, service, finding, run, change. Not asset, entity, item, record.
- Buttons say what happens: "Save changes", "Start scan now", "Export CSV". The confirmation uses the same verb:
  "Scan started".
- Errors say what went wrong and what to do, with the offending value: `Row 14: "10.0.0.300" is not an address.`
- Times are relative when recent ("14 minutes ago") with the exact time in `title`; dates are ISO (`2026-11-21 14:05`).
- Counts over 999 use a thin space: `1 284`.

## Do not

Gradients, shadows, glass effects, rounded pills, icons from an icon font, hero sections, cards with a big number and a
coloured accent, animated entrances, spinners that block the page, placeholder text as the only label, tooltips as
the only way to learn something.

## Checking

Run the app, sign in and take a screenshot of every page you changed at 1440x900 and at 800x900. Compare with the styleguide: same spacing, same components, nothing
clipped, tables scroll sideways instead of breaking the layout. Attach the screenshots as evidence.
