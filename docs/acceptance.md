# Acceptance

Stable v1.0.0 is blocked until mandatory automated tests, real macOS sandbox
checks, authenticated Claude recovery and launchd trials have passed at the
release commit. A skipped test is not evidence of success. Trial receipts bind
commit, platform, dependency versions, test identity and artifacts and require
a human SSH signature. CI publishes test output separately from native trials.

| ID | Requirement | Evidence required |
|---|---|---|
| A01 | ASCII IDs beyond 9,999; full field validation | Automated IDs |
| A02 | Legacy spelling, aliases, collisions | Automated IDs/signatures |
| A03 | Shared reservations, concurrent worktrees, crash gaps | Real Git/process tests |
| A04 | Numeric frozen CSP order and persistent sampling | Automated review |
| A05 | New S-, stable resumed UUID/usage | Automated + authenticated trial |
| A06 | Shared map resolution; unchanged claim bytes | Automated knowledge |
| A07 | Three caps, UTF-8, full segments, indivisible units | Automated pages |
| A08 | Renderer unavailable; pure preview | Automated pages |
| A09 | Human names/cap, redirects, D-/L- preservation | Automated + owner migration review |
| A10 | Coverage, terminal/current, source sections, cap | Automated lint + editorial review |
| A11 | Successors, polarity, cross-topic conflict, abstention | Automated real query |
| A12 | Failures differ from abstention; typed values | Automated real query |
| A13 | Individual SSH case signatures and mutation | Real OpenSSH tests |
| A14 | Historical questions never fabricated | Empty base audit; owner inventory pending |
| A15 | Regression before signing and integration | Automated transaction tests |
| A16 | Inbox exclusions, zero bytes, sensitive material | Automated operations |
| A17 | Seven-day triage, provenance, hash, deferral | Automated operations |
| A18 | Weekly lint; strict >8 days; partial runs | Automated + launchd trial |
| A19 | Findings delta, task deduplication, no correction | Automated operations |
| A20 | Retention, holds, tasks, backup checks | Automated lint |
| A21 | Closure/capture deadlines, unknown class | Automated retention |
| A22 | Holds preserve deadlines and dependencies | Automated retention |
| A23 | Presentation, D+3/D+5/D+7 waiting | Automated tasks |
| A24 | Verified preservation before capacity release | Automated + native custody trial |
| A25 | Durable deletion plan and rechecks | Automated filesystem tests |
| A26 | Cleanup before backup; failures stay incomplete | Automated operations |
| A27 | Manifest-only long backup; strict short expiry | Automated backups |
| A28 | External age ciphertext and verified recovery | Real age + offline recovery trial |
| A29 | Cleanup=30, profile isolation, native resume | Real sandbox + authenticated native trial |
| A30 | Purge guards, signed map, old approvals | Automated guards + exceptional purge procedure |
| A31 | Refs/objects/backups/external copies | Publication audit + exceptional purge procedure |
| A32 | Modular implementation; honest line inventory | Automated source inventory |
| A33 | Quarantine, distinct rotation/deletion receipts | Automated incident tests + owner rotation |
| A34 | Immutable backup expiry; offline copies pending | Automated backup tests |

Additional boundary tests cover exactly/before/after 12h and 24h, context limit
and one UTF-8 byte over it, page/context independence, resumed clocks, full
runtime denial including subprocesses, signing socket exclusion, clone/ZIP
setup twice, spaces in paths, and original source bytes.

Run `python -m unittest discover -s tests -v`. macOS CI installs the pinned
runtime and age and runs real integration tests. Native trials must use a
disposable external profile, never the ordinary user profile. Required trials:
`claude-auth`, `native-resume`, `native-cleanup`, `offline-recovery`, `launchd`.
Record their command logs, before/after artifact hashes, actual UUID/usage,
versions and UTC times with `maintenance attest`. Cleanup trials include two
projects and old/recent sessions; schedules include sleep, logout and timezone
changes. No authenticated credentials are placed in CI.

Release check: `python scripts/release_check.py --vault .`.
Publication does not imply stable acceptance. No stable tag may be created
while a mandatory trial is missing, failed, stale, or unsigned.
