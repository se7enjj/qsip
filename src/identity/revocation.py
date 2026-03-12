"""
QSIP — Credential Revocation via Merkle Accumulator.

Implements a hash-based Merkle accumulator for credential revocation status.
The issuer maintains a set of revoked credential IDs, builds a Merkle tree
over their leaf hashes, and signs the root with Dilithium. Verifiers obtain
the signed accumulator, verify the root signature, and check membership.

Merkle tree construction rules
-------------------------------
- Leaf:       SHA3-256(b"QSIP-merkle-leaf-v1:"  + credential_id.encode())
- Inner node: SHA3-256(b"QSIP-merkle-node-v1:"  + left_child + right_child)
- Leaves are sorted before tree construction (canonical, deterministic output).
- Odd-length layers are padded by duplicating the last leaf before hashing.
- Empty accumulator root: SHA3-256(b"QSIP-merkle-empty-v1")

Security properties
--------------------
- SHA3-256 throughout (NIST-recommended; post-quantum: Grover 128-bit security).
- Domain-separated leaf and inner-node hashes prevent second-preimage attacks.
- Sorted leaves ensure the root is uniquely determined by the set, not insertion order.
- Root is Dilithium-signed by the issuer; always call
  ``SignedRevocationRoot.verify_signature()`` before trusting any status check.
- All byte comparisons use ``hmac.compare_digest()`` (constant-time).

Usage
-----
    from src.identity.revocation import RevocationAccumulator

    acc = RevocationAccumulator()
    acc.revoke(credential.credential_id)
    signed_root = acc.commit(issuer_sign_key, signer, issuer_id="did:qsip:issuer")

    # On the verifier side:
    if signed_root.verify_signature(issuer_verify_key, signer):
        if acc.is_revoked(credential.credential_id):
            raise IdentityError("Credential has been revoked")
"""

from __future__ import annotations

import hashlib
import hmac
from base64 import b64decode, b64encode
from dataclasses import dataclass
from typing import TYPE_CHECKING

from src.common.exceptions import IdentityError, QSIPCryptoError

if TYPE_CHECKING:
    from src.crypto.signatures import DilithiumSigner

# ── Domain separation tags ────────────────────────────────────────────────────
_LEAF_TAG  = b"QSIP-merkle-leaf-v1:"
_NODE_TAG  = b"QSIP-merkle-node-v1:"
_EMPTY_TAG = b"QSIP-merkle-empty-v1"
_ROOT_TAG  = b"QSIP-revocation-root-v1:"


# ── Low-level Merkle primitives ───────────────────────────────────────────────

def _leaf_hash(credential_id: str) -> bytes:
    """Compute the leaf hash for a single credential ID."""
    return hashlib.sha3_256(_LEAF_TAG + credential_id.encode()).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    """Compute an inner-node hash from two child hashes (order-sensitive)."""
    return hashlib.sha3_256(_NODE_TAG + left + right).digest()


def _build_merkle_tree(leaves: list[bytes]) -> tuple[bytes, list[list[bytes]]]:
    """
    Build a complete Merkle tree from leaf hashes.

    Leaves are sorted for canonical ordering.  Odd-length layers are padded
    by duplicating their last element (standard Bitcoin-style padding).

    Parameters
    ----------
    leaves : list[bytes]
        Unsorted leaf hashes.

    Returns
    -------
    tuple[bytes, list[list[bytes]]]
        (root_hash, layers)
        ``layers[0]`` is the sorted, unpadded leaf layer.
        Subsequent layers may include the padding duplicate.
    """
    if not leaves:
        return hashlib.sha3_256(_EMPTY_TAG).digest(), []

    current: list[bytes] = sorted(leaves)
    layers: list[list[bytes]] = [current[:]]  # layers[0] = sorted, unpadded leaves

    while len(current) > 1:
        if len(current) % 2 == 1:
            current = current + [current[-1]]  # pad odd layer
        current = [_node_hash(current[i], current[i + 1]) for i in range(0, len(current), 2)]
        layers.append(current[:])

    return layers[-1][0], layers


# ── Public data classes ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class SignedRevocationRoot:
    """
    An issuer-signed Merkle root authenticating a revocation accumulator.

    Security: ALWAYS call ``verify_signature()`` before trusting membership
    results obtained from an accumulator snapshot.

    Attributes
    ----------
    accumulator_root : bytes
        SHA3-256 Merkle root over all revoked credential ID leaf hashes.
    signature : bytes
        Dilithium signature over SHA3-256(_ROOT_TAG + accumulator_root).
    sig_algorithm : str
        Signature algorithm (e.g. ``"ML-DSA-87"``).
    issuer_id : str
        Identity ID of the signing issuer.
    revocation_count : int
        Number of entries in the accumulator at sign time.
    """

    accumulator_root: bytes
    signature: bytes
    sig_algorithm: str
    issuer_id: str
    revocation_count: int

    def verify_signature(
        self,
        issuer_verify_key: bytes,
        signer: "DilithiumSigner",
    ) -> bool:
        """
        Verify the issuer's Dilithium signature on this revocation root.

        Returns True only when the signature is valid.  Always call this
        before using the accumulator to make access-control decisions.

        Parameters
        ----------
        issuer_verify_key : bytes
            The issuer's Dilithium verification (public) key.
        signer : DilithiumSigner
            Configured Dilithium signer instance.

        Returns
        -------
        bool
            True if the signature is valid.
        """
        signable = hashlib.sha3_256(_ROOT_TAG + self.accumulator_root).digest()
        return signer.verify(signable, self.signature, issuer_verify_key)

    def to_dict(self) -> dict[str, object]:
        """Serialize to a JSON-safe dict (no secrets)."""
        return {
            "accumulator_root": b64encode(self.accumulator_root).decode(),
            "signature": b64encode(self.signature).decode(),
            "sig_algorithm": self.sig_algorithm,
            "issuer_id": self.issuer_id,
            "revocation_count": self.revocation_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "SignedRevocationRoot":
        """
        Deserialize from a dict produced by ``to_dict()``.

        Raises
        ------
        IdentityError
            If required fields are missing or malformed.
        """
        try:
            return cls(
                accumulator_root=b64decode(str(data["accumulator_root"])),
                signature=b64decode(str(data["signature"])),
                sig_algorithm=str(data["sig_algorithm"]),
                issuer_id=str(data["issuer_id"]),
                revocation_count=int(str(data["revocation_count"])),
            )
        except (KeyError, ValueError) as exc:
            raise IdentityError(f"Invalid SignedRevocationRoot data: {exc}") from exc


@dataclass(frozen=True)
class RevocationProof:
    """
    A Merkle inclusion proof demonstrating that a credential IS revoked.

    Constructed by ``RevocationAccumulator.prove_revocation()`` and verified
    independently by ``RevocationProof.verify()``.  The proof is self-contained:
    only the ``accumulator_root`` needs to be trusted (via ``SignedRevocationRoot``).

    Attributes
    ----------
    credential_id : str
        The credential ID this proof claims is revoked.
    siblings : list[bytes]
        Sibling hashes along the path from the leaf to the root.
    path_bits : list[bool]
        Direction at each level: ``True`` = the current node is the LEFT child
        (sibling is on the right); ``False`` = current node is the RIGHT child.
    accumulator_root : bytes
        The expected Merkle root after path reconstruction.
    """

    credential_id: str
    siblings: list[bytes]
    path_bits: list[bool]
    accumulator_root: bytes

    def verify(self) -> bool:
        """
        Verify this Merkle inclusion proof against ``accumulator_root``.

        Returns
        -------
        bool
            True if the proof is valid and ``credential_id`` is provably
            in the Merkle tree with the stored root.
        """
        if len(self.siblings) != len(self.path_bits):
            return False

        try:
            current = _leaf_hash(self.credential_id)

            if not self.siblings:
                # Single-leaf tree: the leaf itself IS the root.
                return hmac.compare_digest(current, self.accumulator_root)

            for sibling, is_left in zip(self.siblings, self.path_bits):
                if is_left:
                    current = _node_hash(current, sibling)
                else:
                    current = _node_hash(sibling, current)

            return hmac.compare_digest(current, self.accumulator_root)

        except Exception:  # noqa: BLE001
            return False


# ── Main accumulator class ────────────────────────────────────────────────────

class RevocationAccumulator:
    """
    A Merkle-tree-based credential revocation accumulator.

    The issuer maintains this object and calls ``revoke()`` when a credential
    must be invalidated.  After each update the issuer calls ``commit()`` to
    produce a new ``SignedRevocationRoot`` that it publishes to verifiers.

    Verifiers load the signed root, call ``verify_signature()`` on it, and
    may then call ``is_revoked()`` (against a local copy of the accumulator)
    or verify a ``RevocationProof`` received from a third party.

    Security
    --------
    - SHA3-256 for all hashing (Grover-resistant at 128-bit security level).
    - Domain separation between leaf hashes and inner-node hashes.
    - Root is Dilithium-signed; verification is required before trust.
    - ``is_revoked()`` is O(1); safe to call in hot verification paths.
    """

    def __init__(self) -> None:
        self._revoked: set[str] = set()

    # ── Mutation ──────────────────────────────────────────────────────────────

    def revoke(self, credential_id: str) -> None:
        """
        Add a credential ID to the revocation set.

        Idempotent: revoking an already-revoked credential is a no-op.

        Parameters
        ----------
        credential_id : str
            The UUID string credential ID to revoke.

        Raises
        ------
        IdentityError
            If ``credential_id`` is empty or whitespace-only.
        """
        if not credential_id or not credential_id.strip():
            raise IdentityError("credential_id must not be empty.")
        self._revoked.add(credential_id.strip())

    # ── Queries ───────────────────────────────────────────────────────────────

    def is_revoked(self, credential_id: str) -> bool:
        """
        Return True if ``credential_id`` is in the revocation set.

        O(1) set lookup.  For untrusted accumulators, call
        ``signed_root.verify_signature()`` first.
        """
        return credential_id in self._revoked

    @property
    def revocation_count(self) -> int:
        """Number of revoked credentials currently in this accumulator."""
        return len(self._revoked)

    # ── Merkle operations ─────────────────────────────────────────────────────

    def build_root(self) -> bytes:
        """
        Compute the Merkle root of the current revocation set.

        Deterministic: the same set always produces the same root regardless
        of insertion order (leaves are sorted before hashing).

        Returns
        -------
        bytes
            32-byte SHA3-256 Merkle root.
        """
        leaves = [_leaf_hash(cid) for cid in self._revoked]
        root, _ = _build_merkle_tree(leaves)
        return root

    def commit(
        self,
        issuer_sign_key: bytes,
        signer: "DilithiumSigner",
        issuer_id: str,
    ) -> SignedRevocationRoot:
        """
        Build the Merkle root and sign it with the issuer's Dilithium key.

        Call this after every ``revoke()`` update and publish the returned
        ``SignedRevocationRoot`` to verifiers.

        Parameters
        ----------
        issuer_sign_key : bytes
            The issuer's Dilithium signing (secret) key.
        signer : DilithiumSigner
            Configured Dilithium signer.
        issuer_id : str
            The issuer's identity ID (included in the signed root for attribution).

        Returns
        -------
        SignedRevocationRoot
            Signed root that verifiers can authenticate.

        Raises
        ------
        IdentityError
            If ``issuer_sign_key`` is empty or signing fails.
        """
        if not issuer_sign_key:
            raise IdentityError("issuer_sign_key must not be empty.")
        try:
            root = self.build_root()
            signable = hashlib.sha3_256(_ROOT_TAG + root).digest()
            signature = signer.sign(signable, issuer_sign_key)
        except QSIPCryptoError as exc:
            raise IdentityError(f"Revocation root signing failed: {exc}") from exc
        except IdentityError:
            raise
        except Exception as exc:
            raise IdentityError(f"Revocation commit failed: {exc}") from exc

        return SignedRevocationRoot(
            accumulator_root=root,
            signature=signature,
            sig_algorithm=signer.algorithm,
            issuer_id=issuer_id,
            revocation_count=len(self._revoked),
        )

    def prove_revocation(self, credential_id: str) -> "RevocationProof | None":
        """
        Generate a Merkle inclusion proof that ``credential_id`` is revoked.

        Parameters
        ----------
        credential_id : str
            The credential ID to prove revoked.

        Returns
        -------
        RevocationProof | None
            An inclusion proof if the credential is in the revocation set,
            ``None`` otherwise.
        """
        if not self.is_revoked(credential_id):
            return None

        target = _leaf_hash(credential_id)
        all_leaves = [_leaf_hash(cid) for cid in self._revoked]
        root, layers = _build_merkle_tree(all_leaves)

        # layers[0] is the sorted, unpadded leaf layer.
        sorted_leaves = layers[0]
        pos = sorted_leaves.index(target)

        siblings: list[bytes] = []
        path_bits: list[bool] = []

        for layer in layers[:-1]:
            # Pad layer to even length before determining sibling.
            padded = layer + ([layer[-1]] if len(layer) % 2 == 1 else [])
            if pos % 2 == 0:  # current node is the LEFT child
                siblings.append(padded[pos + 1])
                path_bits.append(True)
            else:              # current node is the RIGHT child
                siblings.append(padded[pos - 1])
                path_bits.append(False)
            pos //= 2

        return RevocationProof(
            credential_id=credential_id,
            siblings=siblings,
            path_bits=path_bits,
            accumulator_root=root,
        )

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, object]:
        """Serialize the accumulator's revoked-ID set to a JSON-safe dict."""
        return {
            "version": 1,
            "revoked": sorted(self._revoked),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "RevocationAccumulator":
        """
        Deserialize from a dict produced by ``to_dict()``.

        Raises
        ------
        IdentityError
            If the data is malformed.
        """
        try:
            acc = cls()
            for cid in data.get("revoked", []):  # type: ignore[union-attr]
                acc.revoke(str(cid))
            return acc
        except (KeyError, ValueError, IdentityError) as exc:
            raise IdentityError(f"Invalid RevocationAccumulator data: {exc}") from exc
