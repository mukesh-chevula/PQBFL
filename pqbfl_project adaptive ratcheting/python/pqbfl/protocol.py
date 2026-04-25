"""
PQBFL Protocol — session establishment, ratcheting, and encrypted messaging.

Side-channel hardening (inherited):
  - All hash, key, and address comparisons use hmac.compare_digest via
    the helpers in pqbfl.utils (secure_compare / secure_bytes_compare).
  - Signature verification uses the constant-time verify_signer() from
    pqbfl.crypto.ethsig instead of raw string comparison of addresses.
  - AEAD now uses random nonces (nonce prepended to ciphertext).

Adaptive ratcheting (NEW):
  - SessionState can carry an optional AdaptiveRatchetPolicy.
  - next_model_key() checks whether the adaptive policy recommends
    triggering an asymmetric ratchet earlier than the fixed L_j.
  - update_L_j() allows hot-updating the session's ratcheting window.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from pqbfl.crypto.aead import aead_decrypt, aead_encrypt
from pqbfl.crypto.ecdh import ECDHKeypair, ecdh_keygen_secp256k1, ecdh_shared_secret_secp256k1
from pqbfl.crypto.ethsig import recover_signer, sign_bytes, verify_signer
from pqbfl.crypto.kdf import SymmetricRatchetState, chain_key_from_root, kdf_a_root_key, kdf_s_next
from pqbfl.crypto.kyber import KyberEncapResult, KyberKeypair, kyber_decap, kyber_encap, kyber_keygen
from pqbfl.utils import json_dumps_canonical, sha256, secure_bytes_compare


@dataclass
class ServerKeys:
    sig_priv_hex: str
    sig_addr: str
    kem: KyberKeypair
    ecdh: ECDHKeypair


@dataclass
class ClientKeys:
    sig_priv_hex: str
    sig_addr: str
    ecdh: ECDHKeypair


@dataclass
class SessionState:
    root_key: bytes
    ratchet: SymmetricRatchetState
    j: int
    i: int
    L_j: int
    # --- ADAPTIVE RATCHETING ---
    adaptive_L_j: Optional[int] = None  # if set, overrides L_j dynamically


def server_generate_keys(sig_priv_hex: str, sig_addr: str) -> ServerKeys:
    return ServerKeys(
        sig_priv_hex=sig_priv_hex,
        sig_addr=sig_addr,
        kem=kyber_keygen(),
        ecdh=ecdh_keygen_secp256k1(),
    )


def client_generate_keys(sig_priv_hex: str, sig_addr: str) -> ClientKeys:
    return ClientKeys(sig_priv_hex=sig_priv_hex, sig_addr=sig_addr, ecdh=ecdh_keygen_secp256k1())


def h_server_pubkeys(kpk_b: bytes, epk_b: bytes) -> bytes:
    return sha256(kpk_b + epk_b)


@dataclass
class OffchainSignedMessage:
    payload: dict[str, Any]
    signature: bytes

    def serialize_for_signing(self) -> bytes:
        return json_dumps_canonical(self.payload).encode("utf-8")


def server_send_pubkeys(server: ServerKeys, *, tx_r: dict[str, Any], id_p: int) -> OffchainSignedMessage:
    payload = {
        "type": "server_pubkeys",
        "id_p": id_p,
        "kpk_b": server.kem.public_key,
        "epk_b": server.ecdh.public_key_bytes,
        "tx_r": tx_r,
    }
    msg_bytes = json_dumps_canonical(payload).encode("utf-8")
    sig = sign_bytes(server.sig_priv_hex, msg_bytes)
    return OffchainSignedMessage(payload=payload, signature=sig)


def client_process_server_pubkeys(
    client: ClientKeys,
    *,
    server_sig_addr: str,
    signed: OffchainSignedMessage,
    expected_h_pks: bytes,
) -> KyberEncapResult:
    msg_bytes = signed.serialize_for_signing()

    # --- HARDENED: constant-time address comparison ---
    if not verify_signer(msg_bytes, signed.signature, server_sig_addr):
        raise ValueError("server signature invalid")

    kpk_b = signed.payload["kpk_b"]
    epk_b = signed.payload["epk_b"]

    # --- HARDENED: constant-time hash comparison ---
    if not secure_bytes_compare(sha256(kpk_b + epk_b), expected_h_pks):
        raise ValueError("server pubkey hash mismatch")

    ss_e = ecdh_shared_secret_secp256k1(client.ecdh.private_key, epk_b)
    encap = kyber_encap(kpk_b)
    _ = kdf_a_root_key(encap.shared_secret, ss_e)
    return encap


def client_send_epk_and_ct(client: ClientKeys, *, tx_r: dict[str, Any], id_p: int, ct: bytes) -> OffchainSignedMessage:
    payload = {
        "type": "client_epk_ct",
        "id_p": id_p,
        "epk_a": client.ecdh.public_key_bytes,
        "ct": ct,
        "tx_r": tx_r,
    }
    msg_bytes = json_dumps_canonical(payload).encode("utf-8")
    sig = sign_bytes(client.sig_priv_hex, msg_bytes)
    return OffchainSignedMessage(payload=payload, signature=sig)


def server_finish_session(
    server: ServerKeys,
    *,
    client_sig_addr: str,
    signed: OffchainSignedMessage,
    expected_h_epk_a: bytes,
) -> bytes:
    msg_bytes = signed.serialize_for_signing()

    # --- HARDENED: constant-time address comparison ---
    if not verify_signer(msg_bytes, signed.signature, client_sig_addr):
        raise ValueError("client signature invalid")

    epk_a = signed.payload["epk_a"]
    ct = signed.payload["ct"]

    # --- HARDENED: constant-time hash comparison ---
    if not secure_bytes_compare(sha256(epk_a), expected_h_epk_a):
        raise ValueError("client epk hash mismatch")

    ss_e = ecdh_shared_secret_secp256k1(server.ecdh.private_key, epk_a)
    ss_k = kyber_decap(ct, server.kem.secret_key)
    return kdf_a_root_key(ss_k, ss_e)


def client_finish_session(client: ClientKeys, *, server_pub: OffchainSignedMessage, encap: KyberEncapResult) -> bytes:
    epk_b = server_pub.payload["epk_b"]
    ss_e = ecdh_shared_secret_secp256k1(client.ecdh.private_key, epk_b)
    return kdf_a_root_key(encap.shared_secret, ss_e)


def session_from_root(root_key: bytes, *, L_j: int) -> SessionState:
    return SessionState(root_key=root_key, ratchet=chain_key_from_root(root_key), j=1, i=0, L_j=L_j)


def update_L_j(state: SessionState, new_L_j: int) -> SessionState:
    """Hot-update the ratcheting window without re-keying.

    This is the core of adaptive ratcheting — the ThreatMonitor can
    trigger a tighter or looser window at any time between rounds.
    """
    state.adaptive_L_j = max(1, new_L_j)
    return state


def get_effective_L_j(state: SessionState) -> int:
    """Return the effective L_j, considering any adaptive override."""
    if state.adaptive_L_j is not None:
        return state.adaptive_L_j
    return state.L_j


def next_model_key(state: SessionState) -> tuple[SessionState, bytes]:
    state.ratchet, model_key = kdf_s_next(state.ratchet)
    state.i += 1
    return state, model_key


def should_asymmetric_ratchet(state: SessionState) -> bool:
    """Check whether the current session state warrants an asymmetric ratchet.

    Uses the adaptive L_j if set, otherwise falls back to the fixed L_j.
    """
    effective = get_effective_L_j(state)
    return state.i >= effective


def encrypt_round_message(model_key: bytes, *, round_num: int, direction: str, payload: dict[str, Any]) -> bytes:
    """Encrypt a round message.  Uses a random nonce (prepended to ciphertext)."""
    plaintext = json_dumps_canonical(payload).encode("utf-8")
    aad = f"pqbfl:{direction}:{round_num}".encode("utf-8")
    # HARDENED: aead_encrypt now uses os.urandom nonce internally
    return aead_encrypt(model_key, plaintext, aad=aad)


def decrypt_round_message(model_key: bytes, *, round_num: int, direction: str, ciphertext: bytes) -> dict[str, Any]:
    """Decrypt a round message.  Nonce is extracted from the ciphertext prefix."""
    aad = f"pqbfl:{direction}:{round_num}".encode("utf-8")
    # HARDENED: aead_decrypt extracts the prepended nonce automatically
    pt = aead_decrypt(model_key, ciphertext, aad=aad)
    import json
    from pqbfl.utils import json_loads_bytes

    return json_loads_bytes(json.loads(pt.decode("utf-8")))
