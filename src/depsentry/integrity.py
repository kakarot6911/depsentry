"""Tamper-evidence for SBOMs and scan audit logs.

An SBOM is a security control only if you can tell whether it was altered
between generation and consumption. Two mechanisms here:

  * SBOM signing -- Ed25519 detached signatures when `cryptography` is
    available, falling back to HMAC-SHA256 so the tool still works offline with
    no key infrastructure.
  * Audit log -- an append-only hash chain. Each entry commits to the digest of
    the previous one, so removing or editing any historical scan breaks
    verification of everything after it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import SBOM

try:  # Preferred: real public-key signatures.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    HAVE_ED25519 = True
except ImportError:  # pragma: no cover - depends on the host environment
    HAVE_ED25519 = False


GENESIS = "0" * 64


# --------------------------------------------------------------------------
# SBOM signing
# --------------------------------------------------------------------------

def hmac_sign(payload: bytes, key: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def hmac_verify(payload: bytes, key: bytes, signature: str) -> bool:
    # compare_digest, not ==, to avoid leaking the comparison position.
    return hmac.compare_digest(hmac_sign(payload, key), signature)


def generate_keypair(out_dir: str | Path) -> tuple[Path, Path]:
    """Write an Ed25519 keypair to disk. Private key is mode 0600."""
    if not HAVE_ED25519:
        raise RuntimeError("cryptography is not installed; use HMAC signing instead.")

    directory = Path(out_dir).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    private_path = directory / "depsentry_ed25519.key"
    public_path = directory / "depsentry_ed25519.pub"

    private_key = Ed25519PrivateKey.generate()
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(private_path, 0o600)

    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def sign_sbom(sbom: SBOM, key: bytes | str | Path) -> str:
    """Sign an SBOM's canonical form and record the signature on it."""
    payload = sbom.canonical_bytes()

    if HAVE_ED25519 and isinstance(key, (str, Path)) and Path(key).exists():
        private_key = serialization.load_pem_private_key(
            Path(key).read_bytes(), password=None
        )
        signature = f"ed25519:{private_key.sign(payload).hex()}"
    else:
        secret = key if isinstance(key, bytes) else str(key).encode()
        signature = f"hmac-sha256:{hmac_sign(payload, secret)}"

    sbom.signature = signature
    return signature


def verify_sbom(sbom: SBOM, key: bytes | str | Path) -> bool:
    """Verify an SBOM against its recorded signature."""
    if not sbom.signature:
        return False

    algorithm, _, value = sbom.signature.partition(":")
    payload = sbom.canonical_bytes()

    if algorithm == "ed25519":
        if not HAVE_ED25519:
            return False
        public_key = serialization.load_pem_public_key(Path(key).read_bytes())
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        try:
            public_key.verify(bytes.fromhex(value), payload)
            return True
        except Exception:
            return False

    if algorithm == "hmac-sha256":
        secret = key if isinstance(key, bytes) else str(key).encode()
        return hmac_verify(payload, secret, value)

    return False


# --------------------------------------------------------------------------
# Append-only audit log
# --------------------------------------------------------------------------

class AuditLog:
    """Hash-chained JSONL log of scans.

    Entry digest = SHA256(prev_hash || canonical_json(entry_body)). Any edit to
    an earlier record changes its digest and breaks every later link.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _digest(prev_hash: str, body: dict[str, Any]) -> str:
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(f"{prev_hash}{canonical}".encode()).hexdigest()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = json.loads(line)["hash"]
        return last

    def append(self, event: str, payload: dict[str, Any]) -> str:
        body = {
            "event": event,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }
        prev_hash = self._last_hash()
        entry_hash = self._digest(prev_hash, body)

        record = {**body, "prev": prev_hash, "hash": entry_hash}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        return entry_hash

    def verify(self) -> tuple[bool, str]:
        """Walk the chain. Returns (ok, message naming the first broken link)."""
        if not self.path.exists():
            return True, "No audit log yet; nothing to verify."

        prev_hash = GENESIS
        for lineno, line in enumerate(
            self.path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            record = json.loads(line)

            if record["prev"] != prev_hash:
                return False, f"Chain broken at entry {lineno}: prev hash mismatch."

            body = {k: record[k] for k in ("event", "timestamp", "payload")}
            if self._digest(prev_hash, body) != record["hash"]:
                return False, f"Entry {lineno} has been modified: digest mismatch."

            prev_hash = record["hash"]

        return True, f"Audit chain intact; head = {prev_hash[:16]}."

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
