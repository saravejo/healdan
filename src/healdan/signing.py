"""Human SSH signatures with domain-separated payloads and immutable receipts."""
import base64
from pathlib import Path
import tempfile

from .core import canonical, digest, executable, require, run


def envelope(payload, namespace, identity, key):
    require(namespace in {"package", "case", "alias", "trial", "decision", "recovery", "backup", "integration-origin"},
            "Unknown signing namespace", 2)
    signed = run([executable("ssh-keygen"), "-Y", "sign", "-f", key,
                  "-n", "healdan-" + namespace], data=canonical(payload)).stdout
    require(b"BEGIN SSH SIGNATURE" in signed, "SSH signer did not return a signature")
    return {"payload": payload, "digest": digest(payload), "namespace": namespace,
            "identity": identity, "signature": signed.decode("ascii")}


def verify(value, namespace, allowed_signers):
    require(value and value.get("namespace") == namespace, "Missing or wrong signature namespace")
    require(value.get("digest") == digest(value.get("payload")), "Signed payload was changed")
    require(Path(allowed_signers).is_file(), "Allowed signers policy is missing")
    with tempfile.TemporaryDirectory(prefix="healdan-signature-") as directory:
        signature = Path(directory) / "payload.sig"
        signature.write_text(value["signature"], encoding="ascii")
        result = run([executable("ssh-keygen"), "-Y", "verify", "-f", allowed_signers,
                      "-I", value["identity"], "-n", "healdan-" + namespace,
                      "-s", signature], data=canonical(value["payload"]), check=False)
    require(result.returncode == 0, "Invalid human SSH signature")
    return value["payload"]


def verify_origin(original, approval, namespace, allowed_signers):
    require(isinstance(approval, dict) and set(approval) == {"payload", "digest", "namespace", "identity", "signature"},
            "Missing, incomplete or unknown signature envelope")
    signed = verify(approval, namespace, allowed_signers)
    origin = {"row_base64": base64.b64encode(original).decode("ascii"), "row_sha256": digest(original),
              "payload_sha256": approval["digest"], "approval": approval}
    return signed, origin


def trusted_signers(vault):
    path = Path(vault.config.get("allowed_signers") or "")
    require(path.is_absolute() and path.is_file() and not path.resolve().is_relative_to(vault.root),
            "External allowed-signers policy is required", 5)
    return path


def human_sign(vault, payload, namespace):
    key = Path(vault.config.get("signing_key") or "")
    require(key.is_absolute() and key.is_file() and not key.resolve().is_relative_to(vault.root),
            "External human signing key is required", 5)
    identity = vault.config.get("signing_identity")
    require(identity, "Human signing identity is required", 5)
    result = envelope(payload, namespace, identity, key)
    verify(result, namespace, trusted_signers(vault))
    vault.receipt(namespace + "-signature", result)
    return result
