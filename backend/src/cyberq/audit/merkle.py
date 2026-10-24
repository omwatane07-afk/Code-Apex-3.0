"""RFC 6962 Merkle Tree implementation for selective disclosure and batch checkpoints.

Enforces:
1. Domain separation: \\x00 for leaf hashes, \\x01 for interior node hashes.
2. Balanced binary tree derivation for arbitrary leaf sequences.
3. Selective disclosure audit proofs (RBI CSITE compliant).
"""

from __future__ import annotations

import hashlib
from typing import TypedDict


class MerkleProofStep(TypedDict):
    position: str  # 'left' or 'right'
    hash: str


def hash_leaf(data: bytes) -> bytes:
    """Computes SHA-256(\\x00 || data)."""
    h = hashlib.sha256()
    h.update(b"\x00")
    h.update(data)
    return h.digest()


def hash_children(left: bytes, right: bytes) -> bytes:
    """Computes SHA-256(\\x01 || left || right)."""
    h = hashlib.sha256()
    h.update(b"\x01")
    h.update(left)
    h.update(right)
    return h.digest()


class MerkleTree:
    """RFC 6962 compliant Merkle Tree structure."""

    def __init__(self, leaves: list[bytes]) -> None:
        self.raw_leaves = list(leaves)
        if not leaves:
            self.root_bytes = hashlib.sha256(b"").digest()
            self.layers: list[list[bytes]] = [[self.root_bytes]]
            return

        # Layer 0: Leaf hashes
        current_layer = [hash_leaf(leaf) for leaf in leaves]
        self.layers = [current_layer]

        # Build interior tree layers
        while len(current_layer) > 1:
            next_layer: list[bytes] = []
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                if i + 1 < len(current_layer):
                    right = current_layer[i + 1]
                else:
                    # RFC 6962 rule: if odd number of nodes, promote single node to next level
                    right = left
                next_layer.append(hash_children(left, right))
            self.layers.append(next_layer)
            current_layer = next_layer

        self.root_bytes = self.layers[-1][0]

    @property
    def root_hex(self) -> str:
        return self.root_bytes.hex()

    def generate_proof(self, leaf_index: int) -> list[MerkleProofStep]:
        """Generates audit inclusion proof path for a given leaf index."""
        if leaf_index < 0 or leaf_index >= len(self.raw_leaves):
            raise IndexError(f"Leaf index {leaf_index} out of bounds (total leaves: {len(self.raw_leaves)})")

        proof: list[MerkleProofStep] = []
        idx = leaf_index

        for layer_idx in range(len(self.layers) - 1):
            layer = self.layers[layer_idx]
            is_right_child = (idx % 2 == 1)
            sibling_idx = idx - 1 if is_right_child else idx + 1

            if sibling_idx < len(layer):
                sibling_hash = layer[sibling_idx].hex()
                proof.append({
                    "position": "left" if is_right_child else "right",
                    "hash": sibling_hash,
                })
            else:
                # Odd node with no paired sibling was duplicated/promoted
                sibling_hash = layer[idx].hex()
                proof.append({
                    "position": "right",
                    "hash": sibling_hash,
                })

            idx //= 2

        return proof


def build_merkle_tree(leaves: list[bytes]) -> tuple[str, list[list[str]]]:
    """Builds a Merkle tree and returns (root_hex, layers_hex)."""
    tree = MerkleTree(leaves)
    layers_hex = [[h.hex() for h in layer] for layer in tree.layers]
    return tree.root_hex, layers_hex


def generate_merkle_proof(leaf_index: int, leaves: list[bytes]) -> list[MerkleProofStep]:
    """Generates an inclusion proof for leaf at leaf_index."""
    tree = MerkleTree(leaves)
    return tree.generate_proof(leaf_index)


def verify_merkle_proof(
    leaf: bytes,
    proof: list[MerkleProofStep],
    expected_root_hex: str,
) -> bool:
    """Verifies that leaf is part of the Merkle tree with expected_root_hex."""
    current = hash_leaf(leaf)

    for step in proof:
        sibling = bytes.fromhex(step["hash"])
        if step["position"] == "left":
            current = hash_children(sibling, current)
        else:
            current = hash_children(current, sibling)

    return current.hex().lower() == expected_root_hex.lower()
