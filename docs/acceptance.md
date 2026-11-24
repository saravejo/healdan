# Acceptance

Stable v1.0.0 requires a successful CI attempt for the release commit and
verified native trials for the active controller. CI exercises the real macOS
sandbox. Personal trial receipts bind the vault, build, profile, measured
environment and artifacts with a human SSH signature.

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

Run `python -m unittest discover -s tests -v` for local development. CI builds
one wheel and runs it on Windows, Linux and macOS with real Git, OpenSSH and
age. The macOS profile uses the pinned sandbox runtime. Each profile publishes
the outcome of every required test for the wheel, commit and attempt.

Use a disposable external profile for `claude-auth`, `native-resume` and
`native-cleanup`. The other required trials are `offline-recovery` and
`launchd`. Before running each trial, capture its environment with
`maintenance trial-environment TRIAL` and add the result to the `environment`
field of the evidence file. Save command logs, before and after artifact
hashes, actual UUID and usage where applicable, the procedure and UTC times.
Record time in `started_at` and `completed_at` and each artifact as `path` and
`sha256` in `artifacts`. Set `platform` to `Darwin` and `passed` to `true`
after a passing run. If you measured a specific `--profile`, include its path
as `profile`.
Use `maintenance attest TRIAL EVIDENCE.json` to compare the current environment
to the recorded measurements and sign the evidence. Cleanup trials cover two
projects with old and recent sessions. Schedule trials cover sleep, logout and
timezone changes. Use the [disposable launchd procedure](native-trials.md#launchd)
to collect execution evidence before signing for the target environment.
Keep authenticated credentials in the personal environment.

Activate the wheel from the successful Actions attempt for the release commit.
Run `python scripts/release_check.py --vault PATH --ci-run RUN_ID`. Use
`--ci-attempt ATTEMPT` to require the current attempt number explicitly. The
check verifies the wheel, every required test outcome, the selected vault and
its Git history. A stable tag requires `stable_release_allowed` to be `true`.
