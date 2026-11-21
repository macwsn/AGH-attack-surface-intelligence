# Product requirements: Attack Surface Intelligence (ASI)

Customer: the Information Security Centre of AGH University (monitoring, incident handling, pentests).
Product: a tool for cyclic discovery scanning of large networks (more than 10 000 IP addresses). It finds live hosts,
identifies exposed services, web technologies, CMSes, notable headers and cookies, and records how all of that changes
over time. The best solution gets deployed and developed further, so it has to be operable, safe and documented.

## Functional requirements

| Id | Requirement |
|---|---|
| R1 | Load a list of IP addresses, CIDR ranges or domains. |
| R2 | Run a safe discovery scan: multi-threaded, using nmap; measure scan duration; split the address space into subgroups sized from the measured scan speed. |
| R3 | Detect live hosts. |
| R4 | Identify basic services. |
| R5 | For HTTP/HTTPS services collect: page title, status code, headers, cookies, TLS certificate, redirects. |
| R6 | Simple technology detection: CMS, framework, application server, IoT device. |
| R7 | Recognise service traits: test/staging environment, administration panel. |
| R8 | Compare results between consecutive scan runs. |
| R9 | Mark new, disappearing and changed services. |
| R10 | Users can create their own detection signatures. |
| R11 | A form for entering data manually and by CSV and/or JSON file; entered data is processed exactly like scanned data. |
| R12 | RBAC: roles can be created and managed. |
| R13 | Built-in roles: administration; add/delete/modify; modify and read; read only. |
| R14 | Entered values can be edited regardless of scan state, and the edits survive later scans. |
| R15 | A clear UI for every role and a main dashboard with the most important findings. |
| R16 | A database with encryption at rest for every field holding sensitive data. |
| R17 | Scheduling: configurable time windows and frequency. A scan that exceeds its window is stopped and continued in the next window. |
| R18 | Request rate limiting. |
| R19 | Export results to JSON or CSV; import scan results from JSON or CSV. |
| R20 | Handle unstable hosts: decide how a change is reported, how confident a technology identification is, and after how many missed scans a host is reported inactive. |

Signatures must only detect the presence of features, never exploit: a header, a cookie name, a favicon hash, an HTML
fragment, a path such as `/login`, `/admin`, `/version` without any login attempt, a version in a footer, a CMS
fingerprint.

## Nice to have

Time-of-day dependent differences; an "interest" or analytic priority score; repeated measurements for unstable hosts;
grouping of similar services; tags; export of selected observations to DefectDojo as informational findings or
evidence; visualisation of changes over time; passive data sources.

## How it will be judged

Tested in a lab of hosts and services imitating a varied infrastructure, with at least two scan runs, plus editing of
findings, import and role separation.

| Weight | Criterion |
|---|---|
| 30% | Discovery effectiveness and correct service identification on a large infrastructure |
| 20% | Technical quality, documentation, presentation, ease of running, import/export, DefectDojo integration |
| 15% | Change detection over time, unstable hosts, usefulness of reporting |
| 15% | Safe operation, control of scan intensity, clarity of the dashboard |
| 10% | Fingerprinting quality: technologies, CMSes, headers, cookies, signatures |
| 10% | Role separation and data protection |

Deliverables: source repository, technical documentation, a presentation of at most 10 slides with a working demo.
Only free / open-source technologies. Low resource use is valued (Go was chosen).
