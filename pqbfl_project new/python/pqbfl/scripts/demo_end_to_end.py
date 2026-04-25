from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from web3 import Web3

# Allow running this file directly without installing the package.
# (When executed as a script, Python adds only this directory to sys.path.)
_PKG_ROOT = Path(__file__).resolve().parents[2]  # .../pqbfl_project/python
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from pqbfl.chain.contract_client import PQBFLContractClient, load_hardhat_artifact
from pqbfl.chain.hardhat_accounts import derive_hardhat_account
from pqbfl.crypto.eddsa import ed25519_verify
from pqbfl.fl.aggregator import coord_median, fedavg, trimmed_mean
from pqbfl.fl.data import make_synthetic_federated_binary
from pqbfl.fl.model import LogisticModel, accuracy
from pqbfl.protocol import (
    client_finish_session,
    client_generate_keys,
    client_process_server_pubkeys,
    client_send_epk_and_ct,
    decrypt_round_message,
    encrypt_round_message,
    h_server_pubkeys,
    next_model_key,
    server_finish_session,
    server_generate_keys,
    server_send_pubkeys,
    session_from_root,
)
from pqbfl.utils import json_dumps_canonical, hash32


@dataclass(frozen=True)
class DemoConfig:
    chain_url: str = "http://127.0.0.1:8545"
    rounds: int = 6
    n_clients: int = 2
    L_j: int = 3
    project_id: int = 1

    # FL + data settings
    non_iid: bool = True
    data_seed: int = 42
    model_seed: int = 0
    lr: float = 0.2
    epochs: int = 2
    batch_size: int = 64
    l2: float = 0.0

    # Simulation knobs (optional)
    sim_seed: int = 123
    participation_rate: float = 1.0  # 1.0 means all clients participate every round
    label_flip_prob: float = 0.0     # 0.0 means no poisoning

    # Aggregation
    aggregator: str = "fedavg"       # fedavg | median | trimmed_mean
    trim_ratio: float = 0.1


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
        }


def run_demo(cfg: DemoConfig) -> DemoResult:
    chain_dir = Path(__file__).resolve().parents[3] / "chain"

    w3 = Web3(Web3.HTTPProvider(cfg.chain_url))
    if not w3.is_connected():
        raise SystemExit(
            f"Hardhat node not reachable at {cfg.chain_url}. Start it with `cd pqbfl_project/chain && npm run node`."
        )

    server_acct = derive_hardhat_account(0)
    if cfg.n_clients < 1:
        raise ValueError("n_clients must be >= 1")
    client_accts = [derive_hardhat_account(i) for i in range(1, 1 + cfg.n_clients)]

    transaction_timings: list[dict] = []
    operation_timings: list[dict] = []

    def track_operation(op_type: str, round_num: int, client_idx: int, start_time: float) -> None:
        end_time = time.time()
        operation_timings.append(
            {
                "op_type": op_type,
                "round": round_num,
                "client": client_idx,
                "start_time": start_time,
                "end_time": end_time,
                "duration_ms": round((end_time - start_time) * 1000, 2),
            }
        )

    def track_transaction(tx_hash: str, tx_type: str, round_num: int, client_idx: int, start_time: float):
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        end_time = time.time()
        transaction_timings.append(
            {
                "tx_hash": tx_hash.hex() if isinstance(tx_hash, bytes) else tx_hash,
                "tx_type": tx_type,
                "round": round_num,
                "client": client_idx,
                "start_time": start_time,
                "end_time": end_time,
                "duration_ms": round((end_time - start_time) * 1000, 2),
                "gas_used": receipt.gasUsed,
            }
        )
        return receipt

    # Deploy contract
    artifact = load_hardhat_artifact(chain_dir)
    deploy_start = time.time()
    contract = PQBFLContractClient.deploy_from_artifact(w3, artifact, deployer=server_acct.address)
    deploy_end = time.time()
    transaction_timings.append(
        {
            "tx_hash": contract.address[:10] + "...",
            "tx_type": "deploy_contract",
            "round": 0,
            "client": -1,
            "start_time": deploy_start,
            "end_time": deploy_end,
            "duration_ms": round((deploy_end - deploy_start) * 1000, 2),
            "gas_used": 0,
        }
    )

    # FL setup
    d = 10
    dataset = make_synthetic_federated_binary(
        n_clients=len(client_accts),
        n_train_per_client=400,
        n_test=800,
        d=d,
        seed=int(cfg.data_seed),
        non_iid=bool(cfg.non_iid),
    )
    global_model = LogisticModel.init(d=d, seed=int(cfg.model_seed))

    rng_sim = np.random.default_rng(int(cfg.sim_seed))

    id_p = int(cfg.project_id)
    L_j = int(cfg.L_j)
    rounds = int(cfg.rounds)

    # Server key material for PQBFL
    t0 = time.time()
    server_keys = server_generate_keys()
    track_operation("server_generate_keys", 0, -1, t0)
    h_pks = hash32(server_keys.kem.public_key + server_keys.ecdh.public_key_bytes)
    h_m0 = hash32(global_model.to_bytes())

    # Register project on-chain
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

    # Clients register + session establishment
    server_sessions = {}
    client_sessions = {}

    for idx, client_acct in enumerate(client_accts):
        t0 = time.time()
        client_keys = client_generate_keys()
        track_operation("client_generate_keys", 0, idx, t0)

        h_epk_a = hash32(client_keys.ecdh.public_key_bytes)
        tx_start = time.time()
        tx_hash = contract.register_client(from_addr=client_acct.address, h_epk=h_epk_a, id_p=id_p)
        track_transaction(tx_hash, "register_client", 0, idx, tx_start)

        # Off-chain session establishment, following paper Section "Session establishment"
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
            server_sig_pk=server_keys.sig.public_key_bytes,
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
            client_sig_pk=client_keys.sig.public_key_bytes,
            signed=signed_client,
            expected_h_epk_a=h_epk_a,
        )
        track_operation("server_finish_session", 0, idx, t0)

        t0 = time.time()
        rk_client = client_finish_session(client_keys, server_pub=signed_server, encap=encap)
        track_operation("client_finish_session", 0, idx, t0)

        if rk_server != rk_client:
            raise RuntimeError("root keys mismatch")

        server_sessions[client_acct.address] = {
            "keys": client_keys,
            "state": session_from_root(rk_server, L_j=L_j),
        }
        client_sessions[client_acct.address] = {
            "keys": client_keys,
            "state": session_from_root(rk_client, L_j=L_j),
        }

        _ = idx

    initial_acc = accuracy(global_model, dataset.x_test, dataset.y_test)
    round_accuracies: list[float] = [initial_acc]

    # Main training loop
    for r in range(1, rounds + 1):
        id_t = r

        inf_b = {
            "r": r,
            "id_p": id_p,
            "id_t": id_t,
            "deadline": int(time.time()) + 300,
            "h_M_prev": hash32(global_model.to_bytes()),
        }
        h_inf_b = hash32(json_dumps_canonical(inf_b).encode("utf-8"))
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
            t0 = time.time()
            server_state = server_sessions[client_acct.address]["state"]
            server_state, model_key = next_model_key(server_state)
            server_sessions[client_acct.address]["state"] = server_state
            track_operation("server_next_model_key", r, client_idx, t0)

            t0 = time.time()
            offchain_payload = {
                "r": r,
                "id_p": id_p,
                "id_t": id_t,
                "M": global_model.to_bytes(),
                "Tx_p": {"r": r, "h_inf_b": h_inf_b, "id_p": id_p, "id_t": id_t},
            }
            ct = encrypt_round_message(model_key, round_num=r, direction="S->C", payload=offchain_payload)
            track_operation("encrypt_round_message", r, client_idx, t0)

            t0 = time.time()
            sig = server_keys.sig.private_key.sign(ct)
            if not ed25519_verify(server_keys.sig.public_key_bytes, ct, sig):
                raise RuntimeError("server signature check failed")
            track_operation("server_sign_round_message", r, client_idx, t0)

            # Client -> decrypt
            t0 = time.time()
            client_state = client_sessions[client_acct.address]["state"]
            client_state, client_model_key = next_model_key(client_state)
            client_sessions[client_acct.address]["state"] = client_state
            if client_model_key != model_key:
                raise RuntimeError("round model key mismatch")
            track_operation("client_next_model_key", r, client_idx, t0)

            t0 = time.time()
            msg = decrypt_round_message(client_model_key, round_num=r, direction="S->C", ciphertext=ct)
            received_model = LogisticModel.from_bytes(msg["M"])
            track_operation("decrypt_round_message", r, client_idx, t0)

            participate = True
            if cfg.participation_rate < 1.0:
                participate = bool(rng_sim.random() < float(cfg.participation_rate))

            # Train local model
            t0 = time.time()
            local_model = received_model.copy()
            ds = dataset.clients[client_idx]

            if participate:
                y_train = ds.y
                if cfg.label_flip_prob > 0.0:
                    rng_poison = np.random.default_rng(int(cfg.sim_seed) + 10_000 * r + client_idx)
                    mask = rng_poison.random(ds.y.shape[0]) < float(cfg.label_flip_prob)
                    y_train = ds.y.copy()
                    y_train[mask] = 1.0 - y_train[mask]

                local_model.train_sgd(
                    ds.x,
                    y_train,
                    lr=float(cfg.lr),
                    epochs=int(cfg.epochs),
                    batch_size=int(cfg.batch_size),
                    l2=float(cfg.l2),
                    seed=int(cfg.sim_seed) + 1000 * r + client_idx,
                )
            track_operation("local_train_sgd", r, client_idx, t0)
            local_updates.append((local_model, ds.x.shape[0]))

            # Client -> server update
            t0 = time.time()
            inf_a = {
                "r": r,
                "id_p": id_p,
                "id_t": id_t,
                "m": local_model.to_bytes(),
            }
            h_inf_a = hash32(json_dumps_canonical(inf_a).encode("utf-8"))
            track_operation("hash_local_update", r, client_idx, t0)

            if participate:
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
                track_operation("encrypt_round_message", r, client_idx, t0)

                t0 = time.time()
                sig_u = client_keys.sig.private_key.sign(ct_u)
                if not ed25519_verify(client_keys.sig.public_key_bytes, ct_u, sig_u):
                    raise RuntimeError("client signature check failed")
                track_operation("client_sign_round_message", r, client_idx, t0)

                t0 = time.time()
                _ = decrypt_round_message(model_key, round_num=r, direction="C->S", ciphertext=ct_u)
                track_operation("server_decrypt_round_message", r, client_idx, t0)

            # Feedback (terminate only once: last client, last round)
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
                score_delta=1 if participate else 0,
                terminate=terminate,
            )
            track_transaction(tx_hash, "feedback_model", r, client_idx, tx_start)

        if local_updates:
            if cfg.aggregator == "median":
                global_model = coord_median(local_updates)
            elif cfg.aggregator == "trimmed_mean":
                global_model = trimmed_mean(local_updates, trim_ratio=float(cfg.trim_ratio))
            else:
                global_model = fedavg(local_updates)
        round_accuracies.append(accuracy(global_model, dataset.x_test, dataset.y_test))

    final_acc = round_accuracies[-1]
    return DemoResult(
        contract_address=contract.address,
        initial_accuracy=initial_acc,
        final_accuracy=final_acc,
        round_accuracies=round_accuracies,
        transaction_timings=transaction_timings,
        total_transactions=len(transaction_timings),
        avg_transaction_time_ms=round(sum(t["duration_ms"] for t in transaction_timings) / len(transaction_timings), 2) if transaction_timings else 0.0,
        min_transaction_time_ms=round(min((t["duration_ms"] for t in transaction_timings), default=0.0), 2),
        max_transaction_time_ms=round(max((t["duration_ms"] for t in transaction_timings), default=0.0), 2),
        operation_timings=operation_timings,
        total_operations=len(operation_timings),
        avg_operation_time_ms=round(sum(o["duration_ms"] for o in operation_timings) / len(operation_timings), 2) if operation_timings else 0.0,
        min_operation_time_ms=round(min((o["duration_ms"] for o in operation_timings), default=0.0), 2),
        max_operation_time_ms=round(max((o["duration_ms"] for o in operation_timings), default=0.0), 2),
    )


def main():
    cfg = DemoConfig(
        chain_url=os.getenv("PQBFL_CHAIN_URL", "http://127.0.0.1:8545"),
        rounds=int(os.getenv("PQBFL_ROUNDS", "6")),
        n_clients=int(os.getenv("PQBFL_CLIENTS", "2")),
        L_j=int(os.getenv("PQBFL_LJ", "3")),
        project_id=int(os.getenv("PQBFL_PROJECT_ID", "1")),

        non_iid=os.getenv("PQBFL_NON_IID", "1") not in ("0", "false", "False"),
        data_seed=int(os.getenv("PQBFL_DATA_SEED", "42")),
        model_seed=int(os.getenv("PQBFL_MODEL_SEED", "0")),
        lr=float(os.getenv("PQBFL_LR", "0.2")),
        epochs=int(os.getenv("PQBFL_EPOCHS", "2")),
        batch_size=int(os.getenv("PQBFL_BATCH_SIZE", "64")),
        l2=float(os.getenv("PQBFL_L2", "0.0")),

        sim_seed=int(os.getenv("PQBFL_SIM_SEED", "123")),
        participation_rate=float(os.getenv("PQBFL_PARTICIPATION", "1.0")),
        label_flip_prob=float(os.getenv("PQBFL_LABEL_FLIP_PROB", "0.0")),

        aggregator=os.getenv("PQBFL_AGG", "fedavg"),
        trim_ratio=float(os.getenv("PQBFL_TRIM_RATIO", "0.1")),
    )

    res = run_demo(cfg)
    print("Contract deployed:", res.contract_address)
    print("Initial test accuracy:", round(res.initial_accuracy, 4))
    for r in range(1, len(res.round_accuracies)):
        print(f"Round {r}: test accuracy={res.round_accuracies[r]:.4f}")
    print("Done. Final test accuracy:", round(res.final_accuracy, 4))


if __name__ == "__main__":
    main()
