#!/usr/bin/env python3
"""
run_and_compare.py  —  Runs each PQBFL project in a clean subprocess and prints a comparison.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

BASE = Path("/Users/mchevula/PQBFL")
CHAIN_URL = "http://127.0.0.1:8545"
PYTHON = sys.executable   # use whatever venv python is active

PROJECTS = [
    {
        "name": "Original",
        "python_dir": BASE / "pqbfl_project" / "python",
        "chain_dir": BASE / "pqbfl_project" / "chain",
        "project_id": 1,
    },
    {
        "name": "Adaptive Ratcheting",
        "python_dir": BASE / "pqbfl_project new adaptive ratcheting" / "python",
        "chain_dir": BASE / "pqbfl_project" / "chain",
        "project_id": 2,
    },
    {
        "name": "Side-Channel Resistant",
        "python_dir": BASE / "pqbfl_project new adaptive side channel resistant" / "python",
        "chain_dir": BASE / "pqbfl_project" / "chain",
        "project_id": 3,
    },
]

# ─── helper runner scripts (injected into each subprocess) ───────────────────

ORIGINAL_RUNNER = """
import sys, json, warnings
warnings.filterwarnings("ignore")
sys.path.insert(0, PKG_ROOT)
from pqbfl.scripts.demo_end_to_end import DemoConfig, run_demo

cfg = DemoConfig(
    chain_url=CHAIN_URL,
    rounds=ROUNDS,
    n_clients=N_CLIENTS,
    project_id=PROJECT_ID,
    dataset_type="synthetic",
)
res = run_demo(cfg)
out = {
    "initial_accuracy": res.initial_accuracy,
    "final_accuracy": res.final_accuracy,
    "round_accuracies": res.round_accuracies,
    "total_transactions": res.total_transactions,
    "avg_transaction_time_ms": res.avg_transaction_time_ms,
    "min_transaction_time_ms": res.min_transaction_time_ms,
    "max_transaction_time_ms": res.max_transaction_time_ms,
    "total_operations": res.total_operations,
    "avg_operation_time_ms": res.avg_operation_time_ms,
    "min_operation_time_ms": res.min_operation_time_ms,
    "max_operation_time_ms": res.max_operation_time_ms,
    "adaptive_enabled": False,
    "L_j_per_round": [],
    "threat_level_per_round": [],
    "ratchet_adjustments": [],
    "threat_events": [],
}
print("__RESULT__:" + json.dumps(out))
"""

ADAPTIVE_RUNNER = """
import sys, json, warnings
warnings.filterwarnings("ignore")
sys.path.insert(0, PKG_ROOT)
from pqbfl.scripts.demo_end_to_end import DemoConfig, run_demo

cfg = DemoConfig(
    chain_url=CHAIN_URL,
    rounds=ROUNDS,
    n_clients=N_CLIENTS,
    project_id=PROJECT_ID,
    dataset_type="synthetic",
    adaptive_enabled=True,
    L_min=2,
    L_max=20,
    L_default=10,
)
res = run_demo(cfg)
out = {
    "initial_accuracy": res.initial_accuracy,
    "final_accuracy": res.final_accuracy,
    "round_accuracies": res.round_accuracies,
    "total_transactions": res.total_transactions,
    "avg_transaction_time_ms": res.avg_transaction_time_ms,
    "min_transaction_time_ms": res.min_transaction_time_ms,
    "max_transaction_time_ms": res.max_transaction_time_ms,
    "total_operations": res.total_operations,
    "avg_operation_time_ms": res.avg_operation_time_ms,
    "min_operation_time_ms": res.min_operation_time_ms,
    "max_operation_time_ms": res.max_operation_time_ms,
    "adaptive_enabled": res.adaptive_enabled,
    "L_j_per_round": list(getattr(res, "L_j_per_round", [])),
    "threat_level_per_round": [round(t,4) for t in getattr(res, "threat_level_per_round", [])],
    "ratchet_adjustments": list(getattr(res, "ratchet_adjustments", [])),
    "threat_events": list(getattr(res, "threat_events", [])),
}
print("__RESULT__:" + json.dumps(out))
"""

RESET   = "\033[0m"
GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"

def _col(text, colour): return f"{colour}{text}{RESET}"


def run_project(proj: dict, runner_template: str, rounds: int = 4, n_clients: int = 2, timeout: int = 300) -> dict | None:
    pkg_root = str(proj["python_dir"])
    script = (
        runner_template
        .replace("PKG_ROOT", repr(pkg_root))
        .replace("CHAIN_URL", repr(CHAIN_URL))
        .replace("ROUNDS", str(rounds))
        .replace("N_CLIENTS", str(n_clients))
        .replace("PROJECT_ID", str(proj["project_id"]))
    )

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"  {_col('Running:', BOLD)} {_col(proj['name'], CYAN)}")
    print(f"{'='*60}")

    t0 = time.time()
    try:
        proc = subprocess.run(
            [PYTHON, "-c", script],
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "PYTHONWARNINGS": "ignore"},
        )
        elapsed = time.time() - t0

        if proc.returncode != 0:
            print(_col(f"  ❌ FAILED (exit {proc.returncode}) in {elapsed:.1f}s", RED))
            if proc.stderr:
                for line in proc.stderr.strip().splitlines()[-20:]:
                    print(f"     {line}")
            return None

        # Extract JSON result
        result_line = next((l for l in proc.stdout.splitlines() if l.startswith("__RESULT__:")), None)
        if result_line is None:
            print(_col("  ❌ No __RESULT__ marker in output", RED))
            print(proc.stdout[-2000:])
            return None

        data = json.loads(result_line[len("__RESULT__:"):])
        print(_col(f"  ✅ Completed in {elapsed:.1f}s", GREEN))
        print(f"  Initial accuracy : {data['initial_accuracy']:.4f}")
        print(f"  Final accuracy   : {data['final_accuracy']:.4f}")
        print(f"  Accuracy delta   : +{data['final_accuracy'] - data['initial_accuracy']:.4f}")
        print(f"  Transactions     : {data['total_transactions']}  avg {data['avg_transaction_time_ms']:.1f}ms")
        print(f"  Operations       : {data['total_operations']}  avg {data['avg_operation_time_ms']:.2f}ms")
        if data.get("adaptive_enabled"):
            print(f"  L_j per round    : {data['L_j_per_round']}")
            print(f"  Threat levels    : {data['threat_level_per_round']}")
            print(f"  L_j adjustments  : {len(data['ratchet_adjustments'])}")
            print(f"  Threat events    : {len(data['threat_events'])}")
        return data

    except subprocess.TimeoutExpired:
        print(_col(f"  ❌ TIMEOUT after {timeout}s", RED))
        return None
    except Exception as e:
        print(_col(f"  ❌ ERROR: {e}", RED))
        return None


def verify_scr_primitives() -> bool:
    """Subprocess-based verification of SCR crypto layer."""
    script = f"""
import sys, warnings
warnings.filterwarnings("ignore")
sys.path.insert(0, {repr(str(BASE / "pqbfl_project new adaptive side channel resistant" / "python"))})

import numpy as np, os
from pqbfl.crypto.kyber import kyber_keygen, kyber_encap, kyber_decap
from pqbfl.crypto.ecdh import ecdh_keygen_x25519, ecdh_shared_secret_x25519
from pqbfl.crypto.eddsa import ed25519_keygen, ed25519_sign, ed25519_verify
from pqbfl.crypto.aead import aead_encrypt, aead_decrypt, nonce_for_round

checks = []

# Kyber
kp = kyber_keygen()
encap, enc_t = kyber_encap(kp.public_key)
ss, dec_t = kyber_decap(encap.ciphertext, kp.secret_key)
checks.append(("Kyber KEM roundtrip",       ss == encap.shared_secret, f"enc_trace={{enc_t.shape}}, dec_trace={{dec_t.shape}}"))

# All four defense modes
for mode in ["none", "masking", "noise", "adaptive"]:
    _, t = kyber_decap(encap.ciphertext, kp.secret_key, defense_mode=mode)
    checks.append((f"Kyber decap mode={{mode!r}}", t.shape[0] > 0, f"trace {{t.shape}}"))

# ECDH
a = ecdh_keygen_x25519()
b = ecdh_keygen_x25519()
ss1, t1 = ecdh_shared_secret_x25519(a.private_key, b.public_key_bytes)
ss2, t2 = ecdh_shared_secret_x25519(b.private_key, a.public_key_bytes)
checks.append(("ECDH X25519 roundtrip",    ss1 == ss2, f"trace {{t1.shape}}"))

# EdDSA
kpe = ed25519_keygen()
sig, st = ed25519_sign(kpe.private_key, b"hello pqbfl")
v1 = ed25519_verify(kpe.public_key_bytes, b"hello pqbfl", sig)
v2 = not ed25519_verify(kpe.public_key_bytes, b"tampered", sig)
checks.append(("Ed25519 sign+verify",       v1 and v2, f"trace {{st.shape}}"))

# AEAD
key32 = os.urandom(32)
nonce = nonce_for_round(1, "test")
ct, et = aead_encrypt(key32, b"plaintext", aad=b"aad", nonce=nonce)
pt, dt = aead_decrypt(key32, ct, aad=b"aad", nonce=nonce)
checks.append(("AEAD encrypt/decrypt",      pt == b"plaintext", f"enc={{et.shape}} dec={{dt.shape}}"))

tampered = bytearray(ct); tampered[-1] ^= 0xFF
try:
    aead_decrypt(key32, bytes(tampered), aad=b"aad", nonce=nonce)
    tamper_ok = False
except Exception:
    tamper_ok = True
checks.append(("AEAD tamper rejection",     tamper_ok, "Poly1305 tag"))

for name, ok, detail in checks:
    print(f"  {{('PASS' if ok else 'FAIL'):<6}}  {{name:<40}} {{detail}}")
"""
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"  {_col('SCR Crypto Primitive Verification', BOLD)}")
    print(f"{'='*60}")

    proc = subprocess.run(
        [PYTHON, "-c", script],
        capture_output=True, text=True, timeout=30,
        env={**os.environ, "PYTHONWARNINGS": "ignore"},
    )

    all_ok = True
    print(f"\n  {'Check':<44} {'Status':<8} Detail")
    print(f"  {'-'*80}")
    for line in proc.stdout.strip().splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) >= 2:
            status = parts[0]
            rest   = " ".join(parts[1:])
            colour = GREEN if status == "PASS" else RED
            icon   = "✅" if status == "PASS" else "❌"
            print(f"  {_col(icon + ' ' + status, colour):<20} {rest}")
            if status != "PASS":
                all_ok = False

    if proc.stderr:
        for l in proc.stderr.strip().splitlines():
            if "RuntimeWarning" not in l and l.strip():
                print(f"  {_col(l, YELLOW)}")

    summary = _col("All checks passed!", GREEN) if all_ok else _col("Some checks FAILED.", RED)
    print(f"\n  {summary}")
    return all_ok


def print_comparison(results: list[dict | None], names: list[str]):
    print(f"\n{BOLD}{'='*80}{RESET}")
    print(f"  {_col('COMPARISON TABLE', BOLD)}")
    print(f"{'='*80}")

    col_w = [30, 18, 22, 22]
    def row(cells, colours=None):
        out = "  "
        for i, (c, w) in enumerate(zip(cells, col_w)):
            text = str(c)
            if colours and i < len(colours) and colours[i]:
                text = _col(text, colours[i])
            out += text.ljust(w + (len(text) - len(str(c))) if colours and i < len(colours) and colours[i] else w)
        return out

    print(row(["Metric"] + names))
    print("  " + "-" * sum(col_w))

    def v(r, key, fmt=None):
        if r is None: return "N/A"
        val = r.get(key)
        if val is None: return "N/A"
        if fmt: return fmt.format(val)
        return str(val)

    def highlight_best(vals, lower_is_better=False):
        nums = []
        for val in vals:
            try: nums.append(float(val.replace(",", "")))
            except: nums.append(None)
        best = None
        for n in nums:
            if n is not None:
                if best is None: best = n
                elif lower_is_better and n < best: best = n
                elif not lower_is_better and n > best: best = n
        colours = []
        for n in nums:
            if n is None: colours.append(None)
            elif n == best: colours.append(GREEN)
            else: colours.append(None)
        return colours

    metrics = [
        ("Initial Accuracy",       [v(r, "initial_accuracy", "{:.4f}") for r in results],        False),
        ("Final Accuracy",         [v(r, "final_accuracy", "{:.4f}") for r in results],          False),
        ("Accuracy Delta",         [
            f"+{r['final_accuracy']-r['initial_accuracy']:.4f}" if r else "N/A" for r in results
        ],                                                                                         False),
        ("Total Transactions",     [v(r, "total_transactions") for r in results],                 True),
        ("Avg Tx Time (ms)",       [v(r, "avg_transaction_time_ms", "{:.2f}") for r in results], True),
        ("Min Tx Time (ms)",       [v(r, "min_transaction_time_ms", "{:.2f}") for r in results], True),
        ("Max Tx Time (ms)",       [v(r, "max_transaction_time_ms", "{:.2f}") for r in results], True),
        ("Total Operations",       [v(r, "total_operations") for r in results],                   True),
        ("Avg Op Time (ms)",       [v(r, "avg_operation_time_ms", "{:.2f}") for r in results],   True),
        ("Adaptive Enabled",       [str(r.get("adaptive_enabled", "N/A")) if r else "N/A" for r in results], False),
        ("L_j Adjustments",        [str(len(r.get("ratchet_adjustments", []))) if r else "N/A" for r in results], False),
        ("Threat Events",          [str(len(r.get("threat_events", []))) if r else "N/A" for r in results], False),
    ]

    for label, vals, lower_better in metrics:
        colours = highlight_best(vals, lower_is_better=lower_better)
        print(row([label] + vals, [None] + colours))

    print(f"\n{'='*80}\n")


def main():
    print(f"\n{BOLD}🔐 PQBFL Three-Way Demo Runner & Comparator{RESET}")
    print("=" * 60)

    # Step 1: Verify SCR primitives
    scr_ok = verify_scr_primitives()

    # Step 2: Run all three demos
    runners = [ORIGINAL_RUNNER, ADAPTIVE_RUNNER, ADAPTIVE_RUNNER]
    names   = [p["name"] for p in PROJECTS]
    results = []

    for proj, runner in zip(PROJECTS, runners):
        r = run_project(proj, runner, rounds=4, n_clients=2, timeout=600)
        results.append(r)

    # Step 3: Comparison
    print_comparison(results, names)

    # Summary
    success = all(r is not None for r in results)
    if success and scr_ok:
        print(_col("✅ All three projects ran successfully and SCR checks passed!", GREEN))
    else:
        failed = [names[i] for i, r in enumerate(results) if r is None]
        if failed:
            print(_col(f"⚠️  Failed projects: {', '.join(failed)}", RED))
        if not scr_ok:
            print(_col("⚠️  SCR primitive verification had failures.", RED))

    return 0 if success and scr_ok else 1


if __name__ == "__main__":
    sys.exit(main())
