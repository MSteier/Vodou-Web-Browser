"""On-device Content Credentials (C2PA) verification for images.

Vodou cannot tell a deepfake from a real photo — no one reliably can, and
shipping a guess as if it were protection would be dishonest. What Vodou *can*
do is read and cryptographically verify a C2PA "Content Credential" when a piece
of media carries one: who signed it, when, whether it declares itself
AI/algorithmically generated, whether it has been altered since signing, and
whether the signer is on the official C2PA trusted list. That is provenance you
can prove, not a verdict we invented.

The honest limits are baked into the results and must be surfaced in the UI:

  * Only media that CARRIES a credential can be checked. "No credential" means
    UNKNOWN — never "authentic". A faker simply strips the credential.
  * A *valid signature* only proves the media is unchanged since whoever signed
    it signed it. Whether that signer is *trusted* is a separate check against
    the bundled C2PA trust anchors; without a trusted signer, anyone can sign
    their own claim.

Everything runs locally through the c2pa-rs core (the official Content
Authenticity Initiative library). No image bytes leave the machine. The library
is an optional dependency: if it isn't installed, verification reports itself
unavailable and the rest of the browser is unaffected.
"""

from __future__ import annotations

import io
import json
from dataclasses import dataclass, field
from pathlib import Path

try:
    import c2pa
    _AVAILABLE = True
except Exception:      # noqa: BLE001 — any import failure means "feature off"
    c2pa = None
    _AVAILABLE = False

# The official C2PA trust list (X.509 anchors for vetted signers), bundled and
# refreshed with the normal app update. A signer that chains to one of these is
# reported "trusted"; anything else is "untrusted" (valid signature, unvetted
# identity).
_TRUST_PEM = Path(__file__).resolve().parent / "c2pa_trust_anchors.pem"

# digitalSourceType IRIs (IPTC) that mean the media was machine-generated.
_AI_SOURCE_MARKERS = (
    "trainedalgorithmicmedia",   # e.g. a diffusion/GAN model output
    "algorithmicmedia",
    "compositesynthetic",
    "digitalcapture/algorithmicmedia",
)


@dataclass
class CredentialResult:
    """The outcome of checking one image, in plain terms.

    status is the single source of truth for how to present it:
      'trusted'   — valid, untampered, signer on the C2PA trusted list
      'untrusted' — valid & untampered, but signer NOT vetted (caution)
      'invalid'   — a credential is present but its signature failed (tampered)
      'none'      — no credential at all (origin unknown — NOT proof of anything)
      'unavailable' — the c2pa library isn't installed
      'error'     — the credential couldn't be read
    """
    status: str
    signer: str = ""
    signed_time: str = ""
    generator: str = ""
    ai_generated: bool = False
    headline: str = ""
    detail: str = ""
    ingredients: list = field(default_factory=list)


def available() -> bool:
    """Whether on-device C2PA verification is usable (library present + trust
    list readable)."""
    return _AVAILABLE and _TRUST_PEM.is_file()


def _trust_context():
    """A c2pa verification context configured to check signer trust against the
    bundled C2PA trust anchors."""
    anchors = _TRUST_PEM.read_text(encoding="utf-8")
    settings = c2pa.Settings.from_json(json.dumps({
        "trust": {"trust_anchors": anchors},
        "verify": {"verify_trust": True},
    }))
    return c2pa.ContextBuilder().with_settings(settings).build()


def _is_ai(manifest: dict) -> bool:
    """True if the manifest declares the media as AI / algorithmically made,
    via a c2pa.actions assertion's digitalSourceType."""
    for a in manifest.get("assertions", []):
        if not str(a.get("label", "")).startswith("c2pa.actions"):
            continue
        for act in (a.get("data", {}) or {}).get("actions", []):
            dst = str(act.get("digitalSourceType", "")).lower()
            if any(m in dst for m in _AI_SOURCE_MARKERS):
                return True
    return False


def verify_image(data: bytes, mime: str) -> CredentialResult:
    """Read and verify the Content Credential embedded in `data` (an image of
    type `mime`). Never raises — every failure maps to a status."""
    if not available():
        return CredentialResult(
            "unavailable",
            headline="Content Credentials check unavailable",
            detail="The C2PA verification library isn't installed, so provenance "
                   "can't be checked on this machine.")
    try:
        ctx = _trust_context()
        try:
            reader = c2pa.Reader(mime, io.BytesIO(data), context=ctx)
        except Exception as exc:  # noqa: BLE001
            name = type(exc).__name__
            if "ManifestNotFound" in name or "ManifestNotFound" in str(exc):
                return CredentialResult(
                    "none",
                    headline="No Content Credential",
                    detail="This image carries no signed provenance, so its origin "
                           "can't be verified. That does not mean it is fake — or "
                           "real. It is simply unknown.")
            raise

        info = json.loads(reader.json())
        active = info.get("active_manifest")
        man = (info.get("manifests") or {}).get(active, {}) or {}
        sig = man.get("signature_info") or {}
        signer = sig.get("issuer") or ""
        signed_time = sig.get("time") or ""
        generator = (man.get("claim_generator") or "").strip()
        ai = _is_ai(man)
        ingredients = [i.get("title", "") for i in man.get("ingredients", []) if i.get("title")]

        state = str(reader.get_validation_state() or "").lower()
        if state != "valid":
            return CredentialResult(
                "invalid", signer=signer, signed_time=signed_time,
                generator=generator, ai_generated=ai, ingredients=ingredients,
                headline="Credential present, but INVALID",
                detail="A Content Credential is attached, but its signature did not "
                       "verify — the image has been altered since it was signed, or "
                       "the credential is broken. Do not rely on the claimed origin.")

        results = reader.get_validation_results() or {}
        block = results.get("activeManifest") or {}
        codes = [e.get("code", "")
                 for k in ("success", "informational", "failure")
                 for e in (block.get(k) or [])]
        trusted = "signingCredential.trusted" in codes

        if trusted:
            return CredentialResult(
                "trusted", signer=signer, signed_time=signed_time,
                generator=generator, ai_generated=ai, ingredients=ingredients,
                headline="Verified — trusted signer",
                detail="The signature is valid, the image is unaltered since "
                       "signing, and the signer is on the official C2PA trusted "
                       "list.")
        return CredentialResult(
            "untrusted", signer=signer, signed_time=signed_time,
            generator=generator, ai_generated=ai, ingredients=ingredients,
            headline="Signed, but signer not on the trusted list",
            detail="The signature is valid and the image is unaltered since "
                   "signing — but the signer is not on the C2PA trusted list, so "
                   "their identity isn't vetted. Treat the claimed origin with "
                   "caution.")
    except Exception as exc:  # noqa: BLE001
        return CredentialResult(
            "error",
            headline="Couldn't read the Content Credential",
            detail=f"Verification failed: {type(exc).__name__}.")
