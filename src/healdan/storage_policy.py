"""Versioned, human-authorized backup and retention decisions for a vault."""
from datetime import timedelta
from pathlib import Path

from .core import atomic, read_json, require, safe_path, stamp, utc
from .signing import human_sign, trusted_signers, verify

FORMAT = "healdan-storage-policy-v1"
PRESERVATION = "healdan-backup-preservation-v1"
LEGACY_DAYS = {"common": 30, "personal": 7, "sensitive": 7, "mixed": 7, "unknown": 7, "secret": 7, "export": 7}


def history_path(vault):
    return safe_path(vault.control, "storage-policy.json")


def validate_modes(backup, retention):
    require(isinstance(backup, dict) and set(backup) == {"mode"} and
            backup["mode"] in ("off", "manual", "scheduled"), "Invalid backup mode", 5)
    require(isinstance(retention, dict) and retention.get("mode") in ("keep_forever", "by_class"),
            "Invalid retention mode", 5)
    if retention["mode"] == "keep_forever":
        require(set(retention) == {"mode"}, "Permanent retention does not take class durations", 5)
    else:
        days = retention.get("days")
        require(set(retention) == {"mode", "days"} and isinstance(days, dict) and set(days) == set(LEGACY_DAYS) and
                all(n is None or type(n) is int and 0 < n <= 365000 for n in days.values()),
                "Specify positive days or null for every retention class", 5)


def authorization(vault, approval, purpose):
    decision = verify(approval, "decision", trusted_signers(vault))
    require(isinstance(decision, dict) and decision.get("format") == purpose and decision.get("vault") == vault.identity and
            decision.get("responsible") == approval["identity"] and isinstance(decision.get("reason"), str) and
            decision["reason"].strip() and decision.get("decided_at") == stamp(decision.get("decided_at")),
            "Decision must match its purpose, vault, responsible signer and UTC timestamp", 5)
    return decision


def history(vault):
    approvals = read_json(history_path(vault), [])
    require(isinstance(approvals, list), "Invalid storage policy history", 5)
    previous = None
    for version, approval in enumerate(approvals, start=1):
        decision = authorization(vault, approval, FORMAT)
        require(decision.get("version") == version and decision.get("previous") == previous,
                "Storage policy history is discontinuous", 5)
        scope = decision.get("scope")
        require(isinstance(scope, dict) and set(scope) == {"existing", "future"} and scope["future"] is True and
                isinstance(scope["existing"], list) and all(isinstance(i, str) for i in scope["existing"]) and
                scope["existing"] == sorted(set(scope["existing"])), "Invalid storage policy scope", 5)
        validate_modes(decision.get("backup"), decision.get("retention"))
        previous = approval["digest"]
    return approvals


def effective(vault):
    approvals = history(vault)
    if approvals:
        return approvals[-1]["payload"]
    return {"format": FORMAT, "vault": vault.identity, "version": 0, "origin": "legacy",
            "backup": {"mode": "scheduled"}, "retention": {"mode": "by_class", "days": dict(LEGACY_DAYS)}}


def policy_request(vault, settings):
    from .custody import materials

    require(isinstance(settings, dict) and set(settings) == {"backup", "retention", "reason"} and
            isinstance(settings["reason"], str) and settings["reason"].strip(),
            "Supply backup and retention settings and a reason", 2)
    validate_modes(settings["backup"], settings["retention"])
    with vault.locked():
        approvals = history(vault)
        return human_sign(vault, {**settings, "format": FORMAT, "vault": vault.identity,
                          "version": len(approvals) + 1, "previous": approvals[-1]["digest"] if approvals else None,
                          "scope": {"existing": sorted(materials(vault)), "future": True},
                          "responsible": vault.config.get("signing_identity"), "decided_at": stamp()}, "decision")


def apply_policy(vault, approval):
    from .custody import materials

    with vault.locked():
        approvals = history(vault)
        decision = authorization(vault, approval, FORMAT)
        if approvals and approval == approvals[-1]:
            return decision
        validate_modes(decision.get("backup"), decision.get("retention"))
        require(decision.get("version") == len(approvals) + 1 and
                decision.get("previous") == (approvals[-1]["digest"] if approvals else None) and
                decision.get("scope") == {"existing": sorted(materials(vault)), "future": True},
                "Storage policy decision has a stale version or material scope", 5)
        atomic(history_path(vault), [*approvals, approval])
        return decision


def deadline(material, policy=None):
    """Return an explicit permanent, unknown or finite result with its UTC origin."""
    retention = policy["retention"] if policy else {"mode": "by_class", "days": LEGACY_DAYS}
    if material.get("kind") == "backup":
        if material.get("expires_at"):
            return "finite", utc(material["expires_at"])
        return ("permanent" if material.get("expiry") == "permanent" else "unknown"), None
    if retention["mode"] == "keep_forever":
        return "permanent", None
    export = material.get("kind") == "export"
    classification = "export" if export else material.get("classification")
    days = retention["days"].get(classification, retention["days"]["unknown"])
    if days is None:
        return "permanent", None
    origin = material.get("captured_at") if export else material.get("closed_at")
    return ("finite", utc(origin) + timedelta(days=days)) if origin else ("unknown", None)


def backup_status(vault, policy, *, scheduled=False):
    mode = policy["backup"]["mode"]
    if mode == "off":
        return "disabled", "Backup creation disabled by policy"
    config = vault.config
    keys = ("backup_destinations", "backup_signing_identity", "backup_signing_key", "backup_allowed_signers")
    roots = config.get("backup_destinations")
    identity = config.get("backup_signing_identity")
    if (roots is not None and (not isinstance(roots, list) or any(not isinstance(p, str) or not Path(p).is_absolute() or
            (Path(p).exists() and Path(p).resolve() != Path(p)) for p in roots)) or
            identity is not None and not isinstance(identity, str) or
            any(config.get(key) and (not isinstance(config[key], str) or not Path(config[key]).is_absolute() or
                    not Path(config[key]).is_file()) for key in keys[2:])):
        return "invalid", "Invalid backup destinations or signing configuration"
    if not all(config.get(key) for key in keys):
        return "missing", "Backup destinations and signing configuration are required"
    if mode == "scheduled" and scheduled:
        interval, days = backup_interval(vault, policy), config.get("backup_generation_days")
        if interval is None or days is None:
            return "missing", "Backup schedule interval and generation lifetime are required"
        if type(interval) is not int or interval <= 0 or (days != "permanent" and (type(days) is not int or days <= 0)):
            return "invalid", "Invalid backup schedule interval or generation lifetime"
    return "configured", "Backup mode " + mode


def backup_interval(vault, policy):
    hours = vault.config.get("backup_interval_hours")
    if hours is None and policy["version"] == 0:
        # The original launchd maintenance calendar runs once a day.
        return 24
    return hours


def preservation_for(vault, record):
    path = safe_path(vault.control, "backup-preservation/" + record["id"] + ".json")
    approval = read_json(path)
    if approval is None:
        return None
    return validate_preservation(vault, record, approval)


def preservation_authorization_pending(vault, record, policy, now):
    if (policy["retention"]["mode"] != "keep_forever" or record.get("kind") != "backup" or
            record.get("status") != "complete" or not record.get("expires_at") or utc(now) < utc(record["expires_at"])):
        return False
    return preservation_for(vault, record) is None


def validate_preservation(vault, record, approval):
    from .backups import signed_manifest

    signed = signed_manifest(vault, record)
    decision = authorization(vault, approval, PRESERVATION)
    require(signed.get("expires_at") and decision.get("generation") == record["id"] and
            decision.get("envelope_digest") == record["approval"]["digest"] and
            decision.get("signed_expires_at") == signed["expires_at"],
            "Preservation decision does not match the original signed generation", 5)
    return decision


def preservation_request(vault, identifier, reason):
    from .backups import signed_manifest
    from .custody import materials

    with vault.locked():
        record = materials(vault)[identifier]
        signed = signed_manifest(vault, record)
        require(signed.get("expires_at") and isinstance(reason, str) and reason.strip(),
                "A finite signed generation and preservation reason are required", 2)
        return human_sign(vault, {"format": PRESERVATION, "vault": vault.identity, "generation": identifier,
                          "envelope_digest": record["approval"]["digest"], "signed_expires_at": signed["expires_at"],
                          "responsible": vault.config.get("signing_identity"), "reason": reason,
                          "decided_at": stamp()}, "decision")


def apply_preservation(vault, identifier, approval):
    from .custody import materials

    with vault.locked():
        record = materials(vault)[identifier]
        decision = validate_preservation(vault, record, approval)
        path = safe_path(vault.control, "backup-preservation/" + identifier + ".json")
        old = read_json(path)
        require(old is None or old == approval, "Generation already has a preservation decision", 5)
        if old is None:
            atomic(path, approval)
        return decision
