import numpy as np

# -------- LEAKAGE MODEL --------
def _hw(x: int) -> int:
    return bin(x).count("1")

def simulate_trace(data: bytes, noise_std=1.0, jitter=True):
    base = np.array([_hw(b) for b in data], dtype=float)
    noise = np.random.normal(0, noise_std, size=len(base))
    trace = base + noise
    if jitter:
        shift = np.random.randint(0, 3)
        trace = np.roll(trace, shift)
    return trace

# -------- DEFENSES --------
def mask_bytes(data: bytes):
    arr = np.frombuffer(data, dtype=np.uint8)
    mask = np.random.randint(0, 256, size=len(arr), dtype=np.uint8)
    share1 = np.bitwise_xor(arr, mask)
    share2 = mask
    return share1, share2

def combine_shares(s1, s2):
    return np.bitwise_xor(s1, s2).tobytes()

def apply_defense(trace, mode="none"):
    if mode == "masking":
        trace = trace + np.random.normal(0, 0.5, size=len(trace))
    elif mode == "noise":
        trace = trace + np.random.normal(0, 2.0, size=len(trace))
    elif mode == "adaptive":
        trace = trace + np.random.normal(0, 2.5, size=len(trace))
        trace = np.roll(trace, np.random.randint(1, 5))
    return trace
