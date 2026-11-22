# Evaluation plan

Run by the maintainers on `main` once the planned changes are merged. Feature changes do not write or edit the
harness (`eval/**`, `lab/**`). Every claim in the report carries its evidence: a command with its output, a
screenshot, or a test name. What fails is fixed in a further change; the report is re-run after fixes and keeps both
numbers.

Output: `docs/evaluation-report.md` plus raw data in `eval/results/`.

## 1. Requirements matrix

One row per requirement R1-R20 of `docs/requirements.md` and per validation point 1-12 of the challenge.
Columns: status (met / partly / missing), evidence, gap. A second table groups the rows under the six judging criteria
with their weights (30 / 20 / 15 / 15 / 10 / 10) and gives a self-score per criterion with the reason.

## 2. Detection accuracy

| Measure | How | Target |
|---|---|---|
| Live hosts: precision, recall | `lab/run.sh` exports vs `lab/expected.json`; the organisers' lab vs their reference results | 100% / 100% on our lab |
| Services: precision, recall, service name accuracy | same | 100% on our lab |
| HTTP fields (title, status, headers, cookies, TLS, redirects) | field-by-field comparison | no mismatch |
| Technologies and findings: precision, recall | same, per kind (CMS, IoT, admin panel, staging, header, cookie) | recall 100% on our lab, no false finding |
| False changes | 10 consecutive scans of the unchanged lab | 0 changes |
| Change detection | stages 1-3 of the lab, plus an extra stage with a header-only and a certificate-only change | every change reported once, with the field |
| Unstable hosts | a host down 1, 2 and 3 runs with `--inactive-after 3`; a host up only in "office hours" over 8 runs | unstable, then inactive on the third; time-of-day pattern labelled |

The organisers' lab is added under `lab-agh/` when it arrives, with its own expected file built from their reference
results. Differences between their formats (import/export, signatures) and ours are listed and closed by changes.

## 3. Performance

Harness: `eval/bignet/` - one container that answers on a whole /18 (16 384 addresses) by redirecting the subnet to a
local responder; about 3% of addresses "live" with a mix of the lab's services. Real nmap, real probes.

| Measure | How |
|---|---|
| Full scan time, addresses/s, hosts found | `asi scan run` over the /18 with 8, 16, 32 workers |
| Rate limit honoured | packets and requests counted on the responder side per second vs `--max-rate` at 100, 300, 1000 |
| Memory and CPU of the scanner | `docker stats` sampled every second; peak RSS |
| Database | peak connections, rows written, size after 10 runs |
| Adaptive groups | group sizes and durations over the run; share of groups inside the 30-60 s target |
| UI | time to first byte of dashboard, host list (filtered, sorted, page 1 and page 200) and a host page with 20 000 hosts and 10 runs |
| Export / import | time and memory for 20 000 hosts, JSON and CSV |

Each number is the median of three runs with min and max. Machine and Docker resources are recorded.

## 4. Reliability

Each scenario is run against the lab and passes when the final export equals the export of an undisturbed run.

- kill -9 of `asi` in the middle of a run, then resume
- Postgres restarted during a run
- the time window ends mid-run; the run continues in the next window
- a host disappears between discovery and probing
- hostile responses: 10 MiB body, endless redirect chain, slow-loris headers, invalid TLS, binary garbage on an HTTP port, non-UTF-8 title
- two scans started at once for the same definition
- import of a truncated JSON file and a CSV with wrong columns
- clock change (DST) with a schedule crossing midnight
- 24 scheduled runs in a row: no growth in goroutines, connections or memory

## 5. Security and roles

- every route requested as each of the four built-in roles and one custom role: expected 200 / 403 table, generated
  from the router, with no route missing
- raw `SELECT` of every table: sensitive columns are ciphertext; key rotation works; a wrong key fails closed
- stored XSS through scanned data: titles, headers, cookie names, hostnames and notes containing markup
- CSRF: every state-changing route without a token; session fixation; logout; idle and absolute expiry; login rate limit
- signatures that break the safety rules are rejected in files, in the UI and through import
- scanner safety: only configured ports contacted, excluded addresses never contacted, only GET/HEAD, no cross-host
  redirect followed (verified on the responder side)
- CSV formula injection on export; upload limits
- `/security-review` style read of `internal/auth`, `internal/web`, `internal/store`, `internal/exchange`
- dependencies: `govulncheck`, list of direct dependencies with licences

## 6. UI

Screenshots of every page at 1440x900 and 800x900 as admin and as viewer, with real lab data and with empty data.
Checked against `docs/ui-design.md`: consistency with the styleguide, density, wording, empty and error states,
keyboard use, contrast. This part is a judgement, not a measurement, and is labelled so in the report.
A scripted walk through the demo (`docs/demo.md`) must work without touching the database by hand.

## 7. Comparison with existing tools

Same lab, same three stages. Tools: nmap + ndiff, secureCodeBox (named in the challenge), ProjectDiscovery
naabu + httpx + nuclei, reNgine, IVRE. For each: what it found (same precision/recall as §2), scan time, and a
feature table - change tracking over time, unstable-host handling, custom safe signatures, scheduling with time
windows and resume, RBAC, encryption at rest, editing that survives scans, CSV/JSON import and export, DefectDojo
export, setup effort (commands and minutes to first result). Tools that could not be run in the available time are
compared from their documentation and marked as such.

## 8. Presentation

At most 10 slides, exportable to PowerPoint: the problem, what ASI does, architecture in one picture, detection
results (§2), performance and safety numbers (§3), change tracking and unstable hosts, UI screenshots, comparison table
(§7), security and roles (§5), demo and next steps. Every number on a slide comes from `eval/results/`.
