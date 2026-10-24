"""Cryptographic key custody abstractions and dual-curve providers for audit signing (Ed25519 and ECDSA P-256)."""

from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519


class KeyProvider(Protocol):
    """Protocol for audit checkpoint signing and public key distribution."""

    @property
    def algorithm(self) -> str:
        """Returns the algorithm name ('Ed25519' or 'ECDSA_P256')."""
        ...

    def get_public_key_hex(self) -> str:
        """Returns the hex-encoded public key bytes."""
        ...

    def sign(self, message: bytes) -> bytes:
        """Signs the message canonical bytes and returns the raw signature bytes."""
        ...


class LocalKeyProvider:
    """Local software-backed key provider supporting Ed25519 and ECDSA P-256 (secp256r1).

    Suitable for local development, test environments, and air-gapped pilots.
    For production bank deployment, replace with HSM/PKCS#11 key provider (ADR-0002).
    """

    def __init__(self, private_seed_hex: str, algorithm: str = "Ed25519") -> None:
        from cyberq.core.config import get_settings

        if get_settings().is_production():
            raise ValueError(
                "LocalKeyProvider is strictly forbidden in production mode: HSM/PKCS#11 key provider required per ADR-0002"
            )
        seed_bytes = bytes.fromhex(private_seed_hex)[:32]
        if len(seed_bytes) != 32:
            raise ValueError("Audit signing seed must provide at least 32 bytes of entropy")

        self._algorithm = algorithm
        self._ed25519_priv: ed25519.Ed25519PrivateKey | None = None
        self._ed25519_pub: ed25519.Ed25519PublicKey | None = None
        self._ec_priv: ec.EllipticCurvePrivateKey | None = None
        self._ec_pub: ec.EllipticCurvePublicKey | None = None

        if algorithm == "Ed25519":
            self._ed25519_priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed_bytes)
            self._ed25519_pub = self._ed25519_priv.public_key()
            self._public_key_hex = self._ed25519_pub.public_bytes_raw().hex()
        elif algorithm == "ECDSA_P256":
            # Deterministically derive a valid P-256 private key scalar from seed
            curve_order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
            scalar = (int.from_bytes(seed_bytes, "big") % (curve_order - 1)) + 1
            self._ec_priv = ec.derive_private_key(scalar, ec.SECP256R1())
            self._ec_pub = self._ec_priv.public_key()
            self._public_key_hex = self._ec_pub.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            ).hex()
        else:
            raise ValueError(f"Unsupported signing algorithm: {algorithm}. Must be 'Ed25519' or 'ECDSA_P256'.")

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def get_public_key_hex(self) -> str:
        return self._public_key_hex

    def sign(self, message: bytes) -> bytes:
        if self._algorithm == "Ed25519":
            assert self._ed25519_priv is not None
            return self._ed25519_priv.sign(message)
        elif self._algorithm == "ECDSA_P256":
            assert self._ec_priv is not None
            return self._ec_priv.sign(message, ec.ECDSA(hashes.SHA256()))
        raise RuntimeError("Unreachable")


def verify_signature(
    message: bytes,
    signature_bytes: bytes,
    public_key_hex: str,
    algorithm: str = "Ed25519",
) -> bool:
    """Verifies a signature using the designated algorithm and hex-encoded public key."""
    try:
        if algorithm == "Ed25519":
            pub_bytes = bytes.fromhex(public_key_hex)
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            pub_key.verify(signature_bytes, message)
            return True
        elif algorithm == "ECDSA_P256":
            pub_bytes = bytes.fromhex(public_key_hex)
            pub_key_ec = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)
            pub_key_ec.verify(signature_bytes, message, ec.ECDSA(hashes.SHA256()))
            return True
        else:
            return False
    except (InvalidSignature, ValueError):
        return False
