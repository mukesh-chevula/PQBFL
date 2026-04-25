"""
End-to-end demo of the PQBFL protocol with **Adaptive Ratcheting**.

Builds on the side-channel-resistant variant and adds:
  - ThreatMonitor that collects security signals each round.
  - AdaptiveRatchetPolicy that dynamically adjusts L_j.
  - Simulated threat events at specific rounds to demonstrate L_j adaptation.
  - Full audit trail of ratchet adjustments in the DemoResult.

All side-channel hardening from the previous variant is preserved:
  - Constant-time comparisons, random nonces, safe serialization, etc.
"""
from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from web3 import Web3

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from pqbfl.adaptive.adaptive_ratchet import AdaptiveRatchetPolicy
from pqbfl.adaptive.threat_monitor import ThreatEventType, ThreatMonitor
from pqbfl.chain.contract_client import PQBFLContractClient, load_hardhat_artifact
from pqbfl.chain.hardhat_accounts import derive_hardhat_account
from pqbfl.crypto.ethsig import sign_bytes, verify_signer
from pqbfl.fl.aggregator import fedavg
from pqbfl.fl.data import make_synthetic_federated_binary
from pqbfl.fl.model import LogisticModel, accuracy
from pqbfl.protocol import (
    client_finish_session,
    client_generate_keys,
    client_process_server_pubkeys,
    client_send_epk_and_ct,
    decrypt_round_message,
    encrypt_round_message,
    get_effective_L_j,
    h_server_pubkeys,
    next_model_key,
    server_finish_session,
    server_generate_keys,
    server_send_pubkeys,
    session_from_root,
    update_L_j,
)
from pqbfl.utils import json_dumps_canonical, sha256, secure_bytes_compare


@dataclass(frozen=True)
class DemoConfig:
    chain_url: str = "http://127.0.0.1:8545"
    rounds: int = 10
    n_clients: int = 2
    L_j: int = 10           # initial L_j (will be adapted)
    project_id: int = 1
    # Adaptive ratcheting parameters
    adaptive_enabled: bool = True
    L_min: int = 2
    L_max: int = 20
    L_default: int = 10
    sensitivity: float = 2.0


@dataclass(frozen=True)
class DemoResult:
    contract_address: str
    initial_accuracy: float
    final_accuracy: float
    round_accuracies: list[float]
    transaction_timings: list[dict]
    total_transactions: int
    avg_transaction_time_ms: float
    min_transaction_time_ms: float
    max_transaction_time_ms: float
    operation_timings: list[dict]
    total_operations: int
    avg_operation_time_ms: float
    min_operation_time_ms: float
    max_operation_time_ms: float
    # --- ADAPTIVE RATCHETING ---
    adaptive_enabled: bool = True
    L_j_per_round: list[int] = field(default_factory=list)
    threat_level_per_round: list[float] = field(default_factory=list)
    ratchet_adjustments: list[dict] = field(default_factory=list)
    threat_events: list[dict] = field(default_factory=list)
    asymmetric_ratchet_rounds: list[int] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "contract_address": self.contract_address,
            "initial_accuracy": self.initial_accuracy,
            "final_accuracy": self.final_accuracy,
            "round_accuracies": self.round_accuracies,
            "transaction_timings": self.transaction_timings,
            "total_transactions": self.total_transactions,
            "avg_transaction_time_ms": self.avg_transaction_time_ms,
            "min_transaction_time_ms": self.min_transaction_time_ms,
            "max_transaction_time_ms": self.max_transaction_time_ms,
            "operation_timings": self.operation_timings,
            "total_operations": self.total_operations,
            "avg_operation_time_ms": self.avg_operation_time_ms,
            "min_operation_time_ms": self.min_operation_time_ms,
            "max_operation_time_ms": self.max_operation_time_ms,
            "adaptive_enabled": self.adaptive_enabled,
            "L_j_per_round": self.L_j_per_round,
            "threat_level_per_round": self.threat_level_per_round,
            "ratchet_adjustments": self.ratchet_adjustments,
            "threat_events": self.threat_events,
            "asymmetric_ratchet_rounds": self.asymmetric_ratchet_rounds,
        }


# ── Simulated Threat Injection ──────────────────────────────────
# These simulate what would happen in a real deployment when the
# system detects anomalies.  In production, ThreatMonitor would be
# fed by actual protocol-layer events.

def _inject_simulated_threats(monitor: ThreatMonitor, round_num: int, total_rounds: int) -> None:
    """Inject simulated security events at specific rounds for demo purposes."""

    if total_rounds < 4:
        # Not enough rounds to demonstrate adaptation
        return

    # Round 3: simulated MITM attempt (signature verification failure)
    if round_num == 3:
        monitor.record_event(
            ThreatEventType.SIG_VERIFICATION_FAILED,
            severity=0.95,
            round_num=round_num,
            detail="[SIMULATED] Detected failed signature verification — possible MITM attempt",
        )
        monitor.record_event(
            ThreatEventType.HASH_MISMATCH,
            severity=0.8,
            round_num=round_num,
            detail="[SIMULATED] Public key hash mismatch from unknown source",
        )

    # Round 4: continued suspicious activity
    if round_num == 4:
        monitor.record_event(
            ThreatEventType.TIMING_ANOMALY,
            severity=0.7,
            round_num=round_num,
            detail="[SIMULATED] Unusual RTT spike (3x normal) on off-chain channel",
        )

    # Mid-point: reputation drop
    mid = total_rounds // 2
    if round_num == mid and mid > 4:
        monitor.record_event(
            ThreatEventType.REPUTATION_DROP,
            severity=0.5,
            round_num=round_num,
            detail="[SIMULATED] Client reputation score decreased by 2 on-chain",
        )

    # Later rounds: quiet (threat level decays naturally)
    # No events injected — the monitor's exponential decay brings
    # the threat level back down, and L_j gradually increases again.


def run_demo(cfg: DemoConfig) -> DemoResult:
    chain_dir = Path(__file__).resolve().parents[3] / "chain"

    w3 = Web3(Web3.HTTPProvider(cfg.chain_url))
    if not w3.is_connected():
        raise SystemExit(
            f"Hardhat node not reachable at {cfg.chain_url}. "
            "Start it with `cd pqbfl_project\\ adaptive\\ ratcheting/chain && npm run node`."
        )

    # HARDENED: keys derived from HD wallet, never passed via CLI arguments
    server_acct = derive_hardhat_account(0)
    if cfg.n_clients < 1:
        raise ValueError("n_clients must be >= 1")
    client_accts = [derive_hardhat_account(i) for i in range(1, 1 + cfg.n_clients)]

    transaction_timings = []
    operation_timings = []

    def track_operation(op_type: str, round_num: int, client_idx: int, start_time: float) -> None:
        end_time = time.time()
        duration_ms = (end_time - start_time) * 1000
        operation_timings.append(
            {
                "op_type": op_type,
                "round": round_num,
                "client": client_idx,
                "start_time": start_time,
                "end_time": end_time,
                "duration_ms": round(duration_ms, 2),
            }
        )

    def track_transaction(tx_hash: str, tx_type: str, round_num: int, client_idx: int, start_time: float) -> None:
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        end_time = time.time()
        duration_ms = (end_time - start_time) * 1000
        transaction_timings.append({
            "tx_hash": tx_hash.hex() if isinstance(tx_hash, bytes) else tx_hash,
            "tx_type": tx_type,
            "round": round_num,
            "client": client_idx,
            "start_time": start_time,
            "end_time": end_time,
            "duration_ms": round(duration_ms, 2),
            "gas_used": receipt.gasUsed,
        })
        return receipt

    # ── Adaptive Ratcheting Setup ────────────────────────────────
    monitor = ThreatMonitor()
    policy = AdaptiveRatchetPolicy(
        L_min=cfg.L_min,
        L_max=cfg.L_max,
        L_default=cfg.L_default if cfg.adaptive_enabled else cfg.L_j,
        sensitivity=cfg.sensitivity,
    )
    L_j_per_round: list[int] = []
    threat_level_per_round: list[float] = []
    asymmetric_ratchet_rounds: list[int] = []

    # Deploy contract
    artifact = load_hardhat_artifact(chain_dir)
    deploy_start = time.time()
    contract = PQBFLContractClient.deploy_from_artifact(w3, artifact, deployer=server_acct.address)
    deploy_end = time.time()
    deploy_duration_ms = (deploy_end - deploy_start) * 1000
    transaction_timings.append({
        "tx_hash": contract.address[:10] + "...",
        "tx_type": "deploy_contract",
        "round": 0,
        "client": -1,
        "start_time": deploy_start,
        "end_time": deploy_end,
        "duration_ms": round(deploy_duration_ms, 2),
        "gas_used": 0,
    })

    # FL setup
    d = 10
    dataset = make_synthetic_federated_binary(
        n_clients=len(client_accts),
        n_train_per_client=400,
        n_test=800,
        d=d,
        seed=42,
        non_iid=True,
    )
    global_model = LogisticModel.init(d=d, seed=0)

    id_p = int(cfg.project_id)
    initial_L_j = policy.current_L_j if cfg.adaptive_enabled else int(cfg.L_j)
    rounds = int(cfg.rounds)

    t0 = time.time()
    server_keys = server_generate_keys(sig_priv_hex=server_acct.private_key_hex, sig_addr=server_acct.address)
    track_operation("server_generate_keys", 0, -1, t0)
    h_pks = sha256(server_keys.kem.public_key + server_keys.ecdh.public_key_bytes)
    h_m0 = sha256(global_model.to_bytes())

    deposit_wei = Web3.to_wei(0.01, "ether")
    tx_start = time.time()
    tx_hash = contract.register_project(
        from_addr=server_acct.address,
        id_p=id_p,
        n_clients=len(client_accts),
        h_m0=h_m0,
        h_pks=h_pks,
        deposit_wei=deposit_wei,
    )
    track_transaction(tx_hash, "register_project", 0, -1, tx_start)

    server_sessions = {}
    client_sessions = {}

    for idx, client_acct in enumerate(client_accts):
        t0 = time.time()
        client_keys = client_generate_keys(sig_priv_hex=client_acct.private_key_hex, sig_addr=client_acct.address)
        track_operation("client_generate_keys", 0, idx, t0)

        h_epk_a = sha256(client_keys.ecdh.public_key_bytes)
        tx_start = time.time()
        tx_hash = contract.register_client(from_addr=client_acct.address, h_epk=h_epk_a, id_p=id_p)
        track_transaction(tx_hash, "register_client", 0, idx, tx_start)

        tx_r_server = {
            "h_pks": h_pks,
            "n": len(client_accts),
            "h_m0": h_m0,
            "id_p": id_p,
        }

        t0 = time.time()
        signed_server = server_send_pubkeys(server_keys, tx_r=tx_r_server, id_p=id_p)
        track_operation("server_send_pubkeys", 0, idx, t0)

        t0 = time.time()
        encap = client_process_server_pubkeys(
            client_keys,
            server_sig_addr=server_acct.address,
            signed=signed_server,
            expected_h_pks=h_pks,
        )
        track_operation("client_process_server_pubkeys", 0, idx, t0)

        t0 = time.time()
        signed_client = client_send_epk_and_ct(
            client_keys,
            tx_r={"h_epk": h_epk_a, "id_p": id_p},
            id_p=id_p,
            ct=encap.ciphertext,
        )
        track_operation("client_send_epk_and_ct", 0, idx, t0)

        t0 = time.time()
        rk_server = server_finish_session(
            server_keys,
            client_sig_addr=client_acct.address,
            signed=signed_client,
            expected_h_epk_a=h_epk_a,
        )
        track_operation("server_finish_session", 0, idx, t0)

        t0 = time.time()
        rk_client = client_finish_session(client_keys, server_pub=signed_server, encap=encap)
        track_operation("client_finish_session", 0, idx, t0)

        # --- HARDENED: constant-time root key comparison ---
        if not secure_bytes_compare(rk_server, rk_client):
            raise RuntimeError("root keys mismatch")

        server_sessions[client_acct.address] = {
            "keys": client_keys,
            "state": session_from_root(rk_server, L_j=initial_L_j),
        }
        client_sessions[client_acct.address] = {
            "keys": client_keys,
            "state": session_from_root(rk_client, L_j=initial_L_j),
        }

    initial_acc = accuracy(global_model, dataset.x_test, dataset.y_test)
    round_accuracies: list[float] = [initial_acc]

    # ════════════════════════════════════════════════════════════════
    # Main training loop with adaptive ratcheting
    # ════════════════════════════════════════════════════════════════
    for r in range(1, rounds + 1):
        id_t = r

        # ── ADAPTIVE: Inject simulated threats for demo ──────────
        if cfg.adaptive_enabled:
            _inject_simulated_threats(monitor, r, rounds)

        # ── ADAPTIVE: Evaluate threat level and adjust L_j ───────
        threat_level = monitor.get_threat_level()
        if cfg.adaptive_enabled:
            current_L_j = policy.evaluate(
                threat_level,
                round_num=r,
                reason=f"Round {r}: threat={threat_level:.3f}",
            )
            # Update all sessions with the new adaptive L_j
            for addr in server_sessions:
                server_sessions[addr]["state"] = update_L_j(server_sessions[addr]["state"], current_L_j)
                client_sessions[addr]["state"] = update_L_j(client_sessions[addr]["state"], current_L_j)
        else:
            current_L_j = int(cfg.L_j)

        L_j_per_round.append(current_L_j)
        threat_level_per_round.append(round(threat_level, 4))

        # ── Record stale ratchet events ──────────────────────────
        # Check if any session has gone too long without asymmetric ratchet
        for addr in server_sessions:
            state = server_sessions[addr]["state"]
            if state.i > 0 and state.i >= get_effective_L_j(state):
                if cfg.adaptive_enabled:
                    monitor.record_event(
                        ThreatEventType.STALE_RATCHET,
                        severity=0.3,
                        round_num=r,
                        detail=f"Session with {addr[:10]}... has {state.i} symmetric ratchets without re-key",
                    )

        inf_b = {
            "r": r,
            "id_p": id_p,
            "id_t": id_t,
            "deadline": int(time.time()) + 300,
            "h_M_prev": sha256(global_model.to_bytes()),
        }
        h_inf_b = sha256(json_dumps_canonical(inf_b).encode("utf-8"))
        h_pks_r = h_pks
        tx_start = time.time()
        tx_hash = contract.publish_task(
            from_addr=server_acct.address,
            r=r,
            h_inf_b=h_inf_b,
            h_pks_r=h_pks_r,
            id_t=id_t,
            id_p=id_p,
            deadline=inf_b["deadline"],
        )
        track_transaction(tx_hash, "publish_task", r, -1, tx_start)

        local_updates: list[tuple[LogisticModel, int]] = []

        for client_idx, client_acct in enumerate(client_accts):
            # Server -> client
            server_state = server_sessions[client_acct.address]["state"]
            t0 = time.time()
            server_state, model_key = next_model_key(server_state)
            track_operation("next_model_key_server", r, client_idx, t0)
            server_sessions[client_acct.address]["state"] = server_state

            offchain_payload = {
                "r": r,
                "id_p": id_p,
                "id_t": id_t,
                "M": global_model.to_bytes(),
                "Tx_p": {"r": r, "h_inf_b": h_inf_b, "id_p": id_p, "id_t": id_t},
            }
            t0 = time.time()
            ct = encrypt_round_message(model_key, round_num=r, direction="S->C", payload=offchain_payload)
            track_operation("encrypt_S_to_C", r, client_idx, t0)

            t0 = time.time()
            sig = sign_bytes(server_acct.private_key_hex, ct)
            track_operation("sign_server", r, client_idx, t0)

            # --- HARDENED: constant-time signature verification ---
            t0 = time.time()
            if not verify_signer(ct, sig, server_acct.address):
                if cfg.adaptive_enabled:
                    monitor.record_event(
                        ThreatEventType.SIG_VERIFICATION_FAILED,
                        severity=1.0,
                        round_num=r,
                        detail=f"REAL: Server signature verification failed for client {client_idx}",
                    )
                raise RuntimeError("server signature check failed")
            track_operation("verify_server_sig", r, client_idx, t0)

            # Client -> decrypt
            client_state = client_sessions[client_acct.address]["state"]
            t0 = time.time()
            client_state, client_model_key = next_model_key(client_state)
            track_operation("next_model_key_client", r, client_idx, t0)
            client_sessions[client_acct.address]["state"] = client_state

            # --- HARDENED: constant-time key comparison ---
            if not secure_bytes_compare(client_model_key, model_key):
                raise RuntimeError("round model key mismatch")

            t0 = time.time()
            msg = decrypt_round_message(client_model_key, round_num=r, direction="S->C", ciphertext=ct)
            track_operation("decrypt_S_to_C", r, client_idx, t0)
            received_model = LogisticModel.from_bytes(msg["M"])

            # Train local model
            local_model = received_model.copy()
            ds = dataset.clients[client_idx]
            local_model.train_sgd(ds.x, ds.y, lr=0.2, epochs=2, batch_size=64, seed=100 + r)
            local_updates.append((local_model, ds.x.shape[0]))

            # Client -> server update
            inf_a = {
                "r": r,
                "id_p": id_p,
                "id_t": id_t,
                "m": local_model.to_bytes(),
            }
            h_inf_a = sha256(json_dumps_canonical(inf_a).encode("utf-8"))

            tx_start = time.time()
            tx_hash = contract.update_model(
                from_addr=client_acct.address,
                r=r,
                h_inf_a=h_inf_a,
                h_ct_epk=b"\x00" * 32,
                id_t=id_t,
                id_p=id_p,
            )
            track_transaction(tx_hash, "update_model", r, client_idx, tx_start)
            t0 = time.time()
            ct_u = encrypt_round_message(
                client_model_key,
                round_num=r,
                direction="C->S",
                payload={"Inf_a": inf_a, "Tx_u": {"r": r, "h_inf_a": h_inf_a}},
            )
            track_operation("encrypt_C_to_S", r, client_idx, t0)

            t0 = time.time()
            sig_u = sign_bytes(client_acct.private_key_hex, ct_u)
            track_operation("sign_client", r, client_idx, t0)

            # --- HARDENED: constant-time signature verification ---
            t0 = time.time()
            if not verify_signer(ct_u, sig_u, client_acct.address):
                if cfg.adaptive_enabled:
                    monitor.record_event(
                        ThreatEventType.SIG_VERIFICATION_FAILED,
                        severity=1.0,
                        round_num=r,
                        detail=f"REAL: Client {client_idx} signature verification failed",
                    )
                raise RuntimeError("client signature check failed")
            track_operation("verify_client_sig", r, client_idx, t0)

            t0 = time.time()
            _ = decrypt_round_message(model_key, round_num=r, direction="C->S", ciphertext=ct_u)
            track_operation("decrypt_C_to_S", r, client_idx, t0)

            # Feedback
            terminate = (r == rounds) and (client_idx == (len(client_accts) - 1))
            tx_start = time.time()
            tx_hash = contract.feedback_model(
                from_addr=server_acct.address,
                r=r,
                id_t=id_t,
                id_p=id_p,
                client_addr=client_acct.address,
                h_inf_a=h_inf_a,
                h_pks_r=h_pks_r,
                score_delta=1,
                terminate=terminate,
            )
            track_transaction(tx_hash, "feedback_model", r, client_idx, tx_start)

        global_model = fedavg(local_updates)
        round_accuracies.append(accuracy(global_model, dataset.x_test, dataset.y_test))

    final_acc = round_accuracies[-1]

    if transaction_timings:
        durations = [t["duration_ms"] for t in transaction_timings]
        avg_time = sum(durations) / len(durations)
        min_time = min(durations)
        max_time = max(durations)
    else:
        avg_time = min_time = max_time = 0.0

    if operation_timings:
        op_durations = [t["duration_ms"] for t in operation_timings]
        op_avg = sum(op_durations) / len(op_durations)
        op_min = min(op_durations)
        op_max = max(op_durations)
    else:
        op_avg = op_min = op_max = 0.0

    return DemoResult(
        contract_address=contract.address,
        initial_accuracy=initial_acc,
        final_accuracy=final_acc,
        round_accuracies=round_accuracies,
        transaction_timings=transaction_timings,
        total_transactions=len(transaction_timings),
        avg_transaction_time_ms=round(avg_time, 2),
        min_transaction_time_ms=round(min_time, 2),
        max_transaction_time_ms=round(max_time, 2),
        operation_timings=operation_timings,
        total_operations=len(operation_timings),
        avg_operation_time_ms=round(op_avg, 2),
        min_operation_time_ms=round(op_min, 2),
        max_operation_time_ms=round(op_max, 2),
        adaptive_enabled=cfg.adaptive_enabled,
        L_j_per_round=L_j_per_round,
        threat_level_per_round=threat_level_per_round,
        ratchet_adjustments=policy.get_adjustment_log(),
        threat_events=monitor.get_event_log(),
        asymmetric_ratchet_rounds=asymmetric_ratchet_rounds,
    )


def main():
    cfg = DemoConfig(
        chain_url=os.getenv("PQBFL_CHAIN_URL", "http://127.0.0.1:8545"),
        rounds=int(os.getenv("PQBFL_ROUNDS", "10")),
        n_clients=int(os.getenv("PQBFL_CLIENTS", "2")),
        L_j=int(os.getenv("PQBFL_LJ", "10")),
        project_id=int(os.getenv("PQBFL_PROJECT_ID", "1")),
        adaptive_enabled=os.getenv("PQBFL_ADAPTIVE", "1") != "0",
        L_min=int(os.getenv("PQBFL_L_MIN", "2")),
        L_max=int(os.getenv("PQBFL_L_MAX", "20")),
        L_default=int(os.getenv("PQBFL_L_DEFAULT", "10")),
    )

    res = run_demo(cfg)
    print("Contract deployed:", res.contract_address)
    print("Adaptive ratcheting:", "ENABLED" if res.adaptive_enabled else "DISABLED")
    print("Initial test accuracy:", round(res.initial_accuracy, 4))
    for r in range(1, len(res.round_accuracies)):
        L_j = res.L_j_per_round[r - 1] if r - 1 < len(res.L_j_per_round) else "?"
        threat = res.threat_level_per_round[r - 1] if r - 1 < len(res.threat_level_per_round) else 0.0
        print(f"Round {r}: accuracy={res.round_accuracies[r]:.4f}  L_j={L_j}  threat={threat:.3f}")
    print("Done. Final test accuracy:", round(res.final_accuracy, 4))
    print(f"L_j adjustments: {len(res.ratchet_adjustments)}")
    for adj in res.ratchet_adjustments:
        print(f"  Round {adj['round']}: L_j {adj['old_L_j']} → {adj['new_L_j']} (threat={adj['threat_level']:.3f})")


if __name__ == "__main__":
    main()
