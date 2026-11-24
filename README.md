# Healdan

A personal wiki stored as Markdown and JSONL, designed for Obsidian,
Git, and your own authenticated Claude Code on macOS.

**Development build.** The stable `v1.0.0` release is gated on the
[acceptance matrix](docs/acceptance.md), including authenticated macOS trials.
An empty vault is intentional: no sample knowledge or approvals are installed.

```text
Inbox -> Sources -> Claude extraction and review
                                  |
                                  v
                         Human approval
                                  |
                                  v
                     Claims -> Topic pages -> Query

Controller -> IDs, checks, schedules and receipts
Sessions   -> External encrypted storage -> Retention -> Backup
```

## Requirements

- macOS, Python 3.12+, Git, and OpenSSH with SSH signing.
- Obsidian and Claude Code authenticated with your own account.
- `age`, Node.js 22.12+, and sandbox runtime `srt` 0.0.83.
- `launchd` for schedules; Homebrew is optional.
- `gh` is only needed to publish; `git-filter-repo` only for historical purge.

## Install

```sh
git clone https://github.com/saravejo/healdan.git
cd healdan
python3 scripts/setup.py
```

ZIP installations use the same setup command. Setup preserves existing files
and Git history, and removes only the inherited distribution remote.
Setup prints the absolute controller path. Add its directory to `PATH`, then
run `healdan --vault "$PWD" doctor`. The controller selects the build bound
to the vault. Personal configuration, keys, native profiles, and encrypted
conversations stay outside Git.

Open this same folder as an Obsidian vault. No community plugins are required.
Follow [setup](docs/setup.md) to configure signing, custody, recovery, and backup.
Incomplete configuration blocks dependent operations and schedule activation.

## First use

```sh
healdan --vault "$PWD" status
healdan --vault "$PWD" inbox inventory
healdan --vault "$PWD" query --entity 'your entity' --property 'your property'
healdan --vault "$PWD" preview
healdan --vault "$PWD" lint
```

An empty query abstains. Empty regression coverage is reported explicitly.
The first factual promotion needs an individually signed applicable case.
Agents produce proposals; only the controller applies human-signed packages.
Every launch must pass an OS sandbox probe. There is no web server,
database, or direct integration with another AI service.

## Documentation

- [Workflow and approval](docs/workflow.md)
- [Data model](docs/data-model.md) and [CLI commands](docs/cli.md)
- [Operations and retention](docs/operations.md)
- [Recovery](docs/recovery.md)
- [Compatibility and migration](docs/compatibility.md)
- [Acceptance and verification](docs/acceptance.md)

The contracts are Healdan definitions; unavailable predecessor specifications
are not treated as implemented evidence. Released capabilities must have
recorded verification. Licensed under [MIT](LICENSE).
