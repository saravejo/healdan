"""Quarantine first; rotation and elimination are separate human decisions."""
from pathlib import Path
from uuid import uuid4

from .core import atomic, digest, require, safe_path, stamp
from .custody import encrypt, materials, save_material
from .signing import human_sign


def quarantine(vault, relative, owner):
    with vault.locked():
        source = safe_path(vault.root, relative, exists=True)
        require(relative.startswith("inbox/"), "Only inventoried Inbox material can be quarantined here", 2)
        require(owner, "Incident owner required", 2)
        data = source.read_bytes()
        cipher = encrypt(vault, data)
        identifier = str(uuid4())
        target = vault.state / "custody" / (identifier + ".age")
        atomic(target, cipher)
        target.chmod(0o600)
        receipt = vault.receipt("quarantine", {"id": identifier, "sha256": digest(data), "owner": owner})
        record = {"id": identifier, "kind": "export", "classification": "secret", "captured_at": stamp(),
                  "quarantine_receipt": receipt, "holds": [{"id": str(uuid4()), "reason": "Incident unresolved",
                  "owner": owner, "started_at": stamp(), "dependencies": []}], "dependencies": [],
                  "copies": [{"root": str(target.parent), "path": target.name, "sha256": digest(cipher),
                              "kind": "ciphertext", "status": "present"}]}
        save_material(vault, record)
        require(digest(source.read_bytes()) == digest(data), "Secret changed during quarantine")
        # Encryption has already been decrypted and checked; restrictive encrypted copy replaces exposure.
        source.unlink()
        return {"material": identifier, "quarantine_receipt": receipt}


def incident_decision(vault, identifier, step, decision):
    require(step in {"rotation", "deletion"}, "Unknown incident step", 2)
    require(decision.get("owner") and decision.get("reason") and decision.get("reference"),
            "Incident decision requires owner, reason and external reference", 2)
    with vault.locked():
        record = materials(vault)[identifier]
        require(record.get("quarantine_receipt"), "Quarantine has not been recorded", 5)
        if step == "deletion":
            require(record.get("rotation_receipt"), "Rotation/revocation confirmation required", 5)
        signed = human_sign(vault, {"material": identifier, "step": step, "at": stamp(), "decision": decision}, "decision")
        key = "rotation_receipt" if step == "rotation" else "deletion_decision"
        record[key] = signed
        save_material(vault, record)
        return signed
