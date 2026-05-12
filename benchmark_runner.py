"""
Benchmark runner: executes both PQBFL projects and collects detailed timings.
Outputs JSON results for comparison.
"""
from __future__ import annotations

import json
import os
import sys
import time


def run_base_project() -> dict:
    """Run the base PQBFL project and return its DemoResult."""
    base_python = os.path.join(os.path.dirname(__file__), "pqbfl_project", "python")
    if base_python not in sys.path:
        sys.path.insert(0, base_python)

    # Force reimport in case adaptive version was imported
    mods_to_remove = [k for k in sys.modules if k.startswith("pqbfl")]
    for m in mods_to_remove:
        del sys.modules[m]

    sys.path.insert(0, base_python)

    from pqbfl.scripts.demo_end_to_end import DemoConfig, run_demo

    cfg = DemoConfig(
        chain_url="http://127.0.0.1:8545",
        rounds=10,
        n_clients=2,
        L_j=10,
        project_id=1,
    )

    start = time.time()
    result = run_demo(cfg)
    total_time = time.time() - start

    data = result.as_dict()
    data["total_demo_time_s"] = round(total_time, 4)
    data["project"] = "base"
    return data


def run_adaptive_project() -> dict:
    """Run the adaptive ratcheting PQBFL project and return its DemoResult."""
    adaptive_python = os.path.join(
        os.path.dirname(__file__), "pqbfl_project adaptive ratcheting", "python"
    )

    # Force reimport
    mods_to_remove = [k for k in sys.modules if k.startswith("pqbfl")]
    for m in mods_to_remove:
        del sys.modules[m]

    # Put adaptive path FIRST so it takes precedence
    sys.path = [adaptive_python] + [p for p in sys.path if p != adaptive_python]

    from pqbfl.scripts.demo_end_to_end import DemoConfig, run_demo

    cfg = DemoConfig(
        chain_url="http://127.0.0.1:8545",
        rounds=10,
        n_clients=2,
        L_j=10,
        project_id=2,  # different project id so contracts don't clash
        adaptive_enabled=True,
        L_min=2,
        L_max=20,
        L_default=10,
        sensitivity=2.0,
    )

    start = time.time()
    result = run_demo(cfg)
    total_time = time.time() - start

    data = result.as_dict()
    data["total_demo_time_s"] = round(total_time, 4)
    data["project"] = "adaptive_ratcheting"
    return data


def aggregate_by_op_type(timings: list[dict]) -> dict:
    """Group operation timings by op_type and compute stats."""
    from collections import defaultdict
    groups = defaultdict(list)
    for t in timings:
        groups[t["op_type"]].append(t["duration_ms"])

    result = {}
    for op, durations in sorted(groups.items()):
        result[op] = {
            "count": len(durations),
            "total_ms": round(sum(durations), 2),
            "avg_ms": round(sum(durations) / len(durations), 2),
            "min_ms": round(min(durations), 2),
            "max_ms": round(max(durations), 2),
        }
    return result


def aggregate_by_tx_type(timings: list[dict]) -> dict:
    """Group transaction timings by tx_type and compute stats."""
    from collections import defaultdict
    groups = defaultdict(list)
    gas_groups = defaultdict(list)
    for t in timings:
        groups[t["tx_type"]].append(t["duration_ms"])
        gas_groups[t["tx_type"]].append(t.get("gas_used", 0))

    result = {}
    for tx_type, durations in sorted(groups.items()):
        gas = gas_groups[tx_type]
        result[tx_type] = {
            "count": len(durations),
            "total_ms": round(sum(durations), 2),
            "avg_ms": round(sum(durations) / len(durations), 2),
            "min_ms": round(min(durations), 2),
            "max_ms": round(max(durations), 2),
            "avg_gas": round(sum(gas) / len(gas)) if gas else 0,
            "total_gas": sum(gas),
        }
    return result


def aggregate_by_round(op_timings: list[dict], tx_timings: list[dict]) -> dict:
    """Aggregate timings per round."""
    from collections import defaultdict
    round_ops = defaultdict(list)
    round_txs = defaultdict(list)

    for t in op_timings:
        round_ops[t["round"]].append(t["duration_ms"])
    for t in tx_timings:
        round_txs[t["round"]].append(t["duration_ms"])

    rounds = sorted(set(list(round_ops.keys()) + list(round_txs.keys())))
    result = {}
    for r in rounds:
        ops = round_ops.get(r, [])
        txs = round_txs.get(r, [])
        result[str(r)] = {
            "op_count": len(ops),
            "op_total_ms": round(sum(ops), 2),
            "tx_count": len(txs),
            "tx_total_ms": round(sum(txs), 2),
            "round_total_ms": round(sum(ops) + sum(txs), 2),
        }
    return result


def main():
    print("=" * 70)
    print("PQBFL BENCHMARK: Base vs Adaptive Ratcheting")
    print("=" * 70)

    # Run base project
    print("\n[1/2] Running BASE project (10 rounds, 2 clients, L_j=10)...")
    base_data = run_base_project()
    print(f"  ✓ Base project done in {base_data['total_demo_time_s']:.2f}s")
    print(f"    Accuracy: {base_data['initial_accuracy']:.4f} → {base_data['final_accuracy']:.4f}")
    print(f"    Transactions: {base_data['total_transactions']}, Operations: {base_data['total_operations']}")

    # Run adaptive project
    print("\n[2/2] Running ADAPTIVE RATCHETING project (10 rounds, 2 clients)...")
    adaptive_data = run_adaptive_project()
    print(f"  ✓ Adaptive project done in {adaptive_data['total_demo_time_s']:.2f}s")
    print(f"    Accuracy: {adaptive_data['initial_accuracy']:.4f} → {adaptive_data['final_accuracy']:.4f}")
    print(f"    Transactions: {adaptive_data['total_transactions']}, Operations: {adaptive_data['total_operations']}")

    # Compute aggregated stats
    base_op_agg = aggregate_by_op_type(base_data["operation_timings"])
    adaptive_op_agg = aggregate_by_op_type(adaptive_data["operation_timings"])

    base_tx_agg = aggregate_by_tx_type(base_data["transaction_timings"])
    adaptive_tx_agg = aggregate_by_tx_type(adaptive_data["transaction_timings"])

    base_round_agg = aggregate_by_round(
        base_data["operation_timings"], base_data["transaction_timings"]
    )
    adaptive_round_agg = aggregate_by_round(
        adaptive_data["operation_timings"], adaptive_data["transaction_timings"]
    )

    # Compile final results
    results = {
        "benchmark_info": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "rounds": 10,
            "clients": 2,
            "base_L_j": 10,
            "adaptive_L_min": 2,
            "adaptive_L_max": 20,
            "adaptive_L_default": 10,
        },
        "base": {
            "total_demo_time_s": base_data["total_demo_time_s"],
            "initial_accuracy": base_data["initial_accuracy"],
            "final_accuracy": base_data["final_accuracy"],
            "round_accuracies": base_data["round_accuracies"],
            "total_transactions": base_data["total_transactions"],
            "total_operations": base_data["total_operations"],
            "avg_transaction_time_ms": base_data["avg_transaction_time_ms"],
            "min_transaction_time_ms": base_data["min_transaction_time_ms"],
            "max_transaction_time_ms": base_data["max_transaction_time_ms"],
            "avg_operation_time_ms": base_data["avg_operation_time_ms"],
            "min_operation_time_ms": base_data["min_operation_time_ms"],
            "max_operation_time_ms": base_data["max_operation_time_ms"],
            "op_by_type": base_op_agg,
            "tx_by_type": base_tx_agg,
            "by_round": base_round_agg,
        },
        "adaptive": {
            "total_demo_time_s": adaptive_data["total_demo_time_s"],
            "initial_accuracy": adaptive_data["initial_accuracy"],
            "final_accuracy": adaptive_data["final_accuracy"],
            "round_accuracies": adaptive_data["round_accuracies"],
            "total_transactions": adaptive_data["total_transactions"],
            "total_operations": adaptive_data["total_operations"],
            "avg_transaction_time_ms": adaptive_data["avg_transaction_time_ms"],
            "min_transaction_time_ms": adaptive_data["min_transaction_time_ms"],
            "max_transaction_time_ms": adaptive_data["max_transaction_time_ms"],
            "avg_operation_time_ms": adaptive_data["avg_operation_time_ms"],
            "min_operation_time_ms": adaptive_data["min_operation_time_ms"],
            "max_operation_time_ms": adaptive_data["max_operation_time_ms"],
            "adaptive_enabled": adaptive_data.get("adaptive_enabled", True),
            "L_j_per_round": adaptive_data.get("L_j_per_round", []),
            "threat_level_per_round": adaptive_data.get("threat_level_per_round", []),
            "ratchet_adjustments": adaptive_data.get("ratchet_adjustments", []),
            "threat_events": adaptive_data.get("threat_events", []),
            "op_by_type": adaptive_op_agg,
            "tx_by_type": adaptive_tx_agg,
            "by_round": adaptive_round_agg,
        },
    }

    out_path = os.path.join(os.path.dirname(__file__), "benchmark_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n✓ Results written to {out_path}")

    # Quick comparison table
    print("\n" + "=" * 70)
    print("SUMMARY COMPARISON")
    print("=" * 70)
    print(f"{'Metric':<35} {'Base':>15} {'Adaptive':>15}")
    print("-" * 70)
    print(f"{'Total demo time (s)':<35} {base_data['total_demo_time_s']:>15.2f} {adaptive_data['total_demo_time_s']:>15.2f}")
    print(f"{'Initial accuracy':<35} {base_data['initial_accuracy']:>15.4f} {adaptive_data['initial_accuracy']:>15.4f}")
    print(f"{'Final accuracy':<35} {base_data['final_accuracy']:>15.4f} {adaptive_data['final_accuracy']:>15.4f}")
    print(f"{'Total transactions':<35} {base_data['total_transactions']:>15} {adaptive_data['total_transactions']:>15}")
    print(f"{'Total operations':<35} {base_data['total_operations']:>15} {adaptive_data['total_operations']:>15}")
    print(f"{'Avg tx time (ms)':<35} {base_data['avg_transaction_time_ms']:>15.2f} {adaptive_data['avg_transaction_time_ms']:>15.2f}")
    print(f"{'Avg op time (ms)':<35} {base_data['avg_operation_time_ms']:>15.2f} {adaptive_data['avg_operation_time_ms']:>15.2f}")
    print(f"{'Min tx time (ms)':<35} {base_data['min_transaction_time_ms']:>15.2f} {adaptive_data['min_transaction_time_ms']:>15.2f}")
    print(f"{'Max tx time (ms)':<35} {base_data['max_transaction_time_ms']:>15.2f} {adaptive_data['max_transaction_time_ms']:>15.2f}")

    if adaptive_data.get("L_j_per_round"):
        print(f"\nAdaptive L_j per round: {adaptive_data['L_j_per_round']}")
    if adaptive_data.get("threat_level_per_round"):
        print(f"Threat level per round: {adaptive_data['threat_level_per_round']}")
    if adaptive_data.get("ratchet_adjustments"):
        print(f"Ratchet adjustments: {len(adaptive_data['ratchet_adjustments'])}")
        for adj in adaptive_data["ratchet_adjustments"]:
            print(f"  Round {adj['round']}: L_j {adj['old_L_j']} → {adj['new_L_j']} (threat={adj['threat_level']:.3f})")


if __name__ == "__main__":
    main()
