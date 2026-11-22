# Evaluation report

What was measured, on which commit, with which harness, and what the numbers do and do not show. Every figure here has
a file under `eval/results/`; a figure that is not here was not measured. Commit hashes are those of the working
repository at measurement time and are quoted in the result files.

## 1. Acceptance lab (`lab/`)

A fixed /24 with 12 known services; three scans with changes in between (a host and a service go down and come back, a
page changes, a host appears); exports and diffs are compared with `lab/expected.json` by `lab/check.py`.

- Result: passes on every merged change (it is part of the merge gate) and in CI.
- Shows: discovery, service and technology detection on known pages, statuses over three runs, every diff type, no
  change entries for volatile headers.
- Does not show: scale, unknown products, hostile targets.

## 2. Scale (`eval/bignet`)

A simulated 10.99.0.0/18: 16 384 addresses, 485 live hosts, 594 services, ground truth written by the responder. Rate
is counted on the target side (iptables counters and HTTP requests per second), not taken from the scanner.

| | Result |
|---|---|
| Hosts found / expected | 485 / 485, 0 false |
| Services found / expected | 594 / 594 |
| Full scan, 16 workers, limit 1000/s | 167 s (commit 6ff06c0, machine busy with other labs; 73-126 s on earlier commits) |
| Second scan after 92 hosts were switched off | 92 reported missing, 0 false changes among the rest |
| Third scan after they came back | 92 reported returned |
| Peak scanner memory | 727 MiB |
| Peak rate seen by the target | 470/s, never above the limit (273 SYN + 197 HTTP) |

Limits: one machine, one Docker network, no packet loss, no firewalls; the simulated hosts answer at once. The time is
an upper bound for a quiet network and says little about a campus network with filtered ranges.

## 3. Technology recognition against nmap (`eval/vulhub`)

Same targets and ports for ASI and for `nmap -sV` at light and default intensity. A product counts as recognised when
its name is reported; a version counts when it equals the image's version.

| Set | ASI | nmap light | nmap default |
|---|---|---|---|
| 16 services the built-in signatures were written for | 16/16, versions 15/16, 1 false technology | 10/16, versions 8/16 | 10/16, versions 8/16 |
| 11 products whose pages were later used as test fixtures | 9/11, versions 4/11 | 6/11 | 7/11 |
| 12 products not seen before (commit c9403c2) | 4/12, versions 2/12, 0 false | 3/12, versions 1/12 | 3/12, versions 1/12 |
| 8 web applications not seen before, before the page-metadata rule (bbe6ac5) | 1/8 | 1/8 | 1/8 |
| the same 8, after the page-metadata rule | 3/8, 1 false technology ("assets") | 1/8 | 1/8 |

What this shows: on products ASI has signatures for it names more products and far more versions than nmap, and it
flags outdated versions (16/16 on the first set) and administration panels, which nmap does not do at all. On products
nobody prepared for, the dataset and signatures add little; the general page-metadata and corroborated-title rules
raise recognition from 1/8 to 3/8 on applications never seen before (nmap: 1/8) at the cost of one false name out
of three new ones, which is why those results carry confidence 30-40 and their source. The generic findings
(administration panel, unfinished installation) carry over as well.

Limits: one run per set; wall-clock is not comparable (ASI ran with a 300/s limit, nmap unthrottled); the second set
stopped being unseen once its pages became fixtures; the 12-product set was used to design the page-metadata rule, so
only the 8-application set measures that rule honestly.

## 4. Other tools on one lab (`eval/complab`, `eval/results/comparison/comparison.md`)

nmap + ndiff, naabu + httpx + nuclei, WhatWeb on a /24 with three stages. All tools find the same hosts and services.
The differences are in what happens next: none of them keeps an inventory with statuses over time; ndiff reports raw
differences including volatile values; nuclei reported a generic WAF on every nginx (10-11 false findings per stage)
and needed 160-490 s per stage; none flags outdated versions or staging markers as findings. Commands and raw output
are in the result directory.

## 5. Organisers' sample environments (`eval/agh`, `lab-agh/`)

The four stacks the organisers published, scanned on the host ports (commit 8ceb709), with `nmap -sV` at light and
default intensity on the same ports as the baseline.

| | ASI | nmap light | nmap default |
|---|---|---|---|
| Service names right | 20/20 | 18/20 | 19/20 |
| Products recognised | 17/19 | 4/19 | 6/19 |
| Versions right | 10/13 | 3/13 | 4/13 |
| Administration panels flagged | 4/5 | 0/5 | 0/5 |
| Outdated versions flagged | 2/2 | 0/2 | 0/2 |
| False changes between two consecutive scans | 0 on all four stacks | n/a | n/a |

The quick-start scenario (a service goes away and comes back) gives exactly `service_missing` and `service_returned`.
On amd64 (a separate machine) the vsftpd 3.0.2 image runs and is recognised; no FTP commands are sent.

Regressions found by this run against the previous one, with their status: nmap's stock probes reached web ports
in the second service pass (OPTIONS and POST seen in a target's log), the five-port quick scan took 59 s instead of
11 s, and a port speaking both TLS and plain HTTP was fetched over https again (one administration panel lost, hence
4/5). All three have one cause and one fix: the stock pass is kept off web ports. See the repository history and
issues for whether that fix is in the commit you are reading.

Still open: vsftpd without a version in its banner is not identified by ASI or by nmap; the `top1000` preset misses the
organisers' unusual ports by design; a recheck is not faster than a full scan on a single host.

## 6. Reliability under faults (`eval/reliability`)

Eleven scripted scenarios; each injects a fault and compares the result with an undisturbed run.

| Scenario | Result |
|---|---|
| kill -9 during a scan, then resume | pass: run shown as stalled after 55 s, resumed result equals the baseline |
| database restart and a 20 s outage | pass: scan finishes without a resume |
| SIGTERM | pass: paused in 0.3 s, no nmap left, resumed result equals the baseline |
| host vanishes between discovery and probing | pass: no false change, service stored with the error |
| port flapping | pass: service missing, then returned, no host-level change |
| bad input including a /8 | pass: refused before anything is sent, naming the bound |
| ten scans without change | pass: nine empty diffs, linear database growth |
| wrong encryption key | pass: refused before scanning, message names the key |
| two runs at once | pass |
| recheck mode | pass: SYN only to the 24 known address/port pairs, none to the other 82, no ICMP |
| hostile HTTP servers and tarpits | pass on 6ff06c0: 17 hostile targets in 80 s, a silent host costs 78 s (before the time bound: not finished in 900 s, 259 s per silent host); second scan gives 0 changes |

Known remainder: after kill -9 two nmap processes live for up to about a minute.

## 7. Access control audit

A live audit signed in as 14 roles (the four built-in ones, ten custom ones with single permissions, and no session)
and requested every route. First pass: 9 findings (dashboard data visible without `inventory.read`, two privilege
escalations through role assignment and role editing, leaks on secondary routes). All were fixed and re-tested as
fixed. Second pass found one more escalation (a user manager resetting an administrator's password); it is fixed (the actor must hold every permission of the target user's role) and covered by a test that replays the reported path.

## 8. DefectDojo

Export was run against a local DefectDojo 3.5: the Nmap scan import and the findings import both work; six defects
found in that run (test titles, duplicate tests on re-export, finding counts, error messages) were fixed and are
covered by tests against recorded responses. Nothing was ever sent to a public DefectDojo instance.

## 9. Requirements walk-through

`eval/results/acceptance/scorecard-final.md`: every requirement and validation point of the task checked on a running
instance (commit 89dd7a7): 47 work, 12 partly, 2 missing, 3 pending at that time. The partly and missing items were
either fixed afterwards (see `docs/requirements-coverage.md` for the current row of each requirement) or are open
issues in the repository.

## What is not claimed

- ASI is not a better fingerprinter than nmap for arbitrary products.
- The packet rate shown for nmap is an estimate; HTTP requests are measured.
- A recheck is not faster than a full scan of a single host.
- nmap sends its own service probes; the GET/HEAD-only rule covers ASI's HTTP probe and signatures.
