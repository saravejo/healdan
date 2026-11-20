# Verification record

The public repository is a development build (`1.0.0.dev1`). No stable tag
or release is authorized until the exact commit passes `release_check.py`.

Controller tests use disposable Git repositories/worktrees, real cross-process
locks, actual SSH signatures, and actual age encryption/decryption. Fixtures
contain synthetic knowledge only in temporary directories. The distributed
vault's sources, claims, cases, decisions, lessons and approval ledgers are empty.

The [macOS CI run for b59428f](https://github.com/saravejo/healdan/actions/runs/44827011532)
passed 63 tests, including real sandbox process/file/socket denial checks,
on macOS 15 with Python 3.12, Node 22.12.0 and srt 0.0.83. It also built and
audited wheel/sdist on Linux. Later commits must pass their own CI; this result
is historical evidence, not acceptance of an untested change.

Local Windows verification used Python 3.15.2, Git 2.56.1, OpenSSH and age 1.3.2.
The age archive's SHA-256 was compared with the official GitHub release asset
digest. Windows skips the macOS OS probe and does not count that skip as a pass.
Test output and dependency versions are retained by the CI artifact.

Publication audits examine tracked files, every reachable historical blob,
distribution archives, and the initially empty operational registries. The
local reference document is ignored, export-excluded and package-excluded;
its contents are not in any published commit. No personal configuration,
transcript, credential or generated signing key is distributed.

The owner confirmed that no authenticated Mac is available in this session.
The five mandatory trials remain unestablished: Claude authentication/native
file tools, native reconstruction and same-UUID resume, vendor cleanup across
profiles/projects, offline recovery on the owner's media, and launchd calendar
behavior. The CI sandbox test does not substitute for them. See
[native trial procedures](native-trials.md). Historical-question and exceptional
purge inventories also require the owner's actual materials; none are invented.
