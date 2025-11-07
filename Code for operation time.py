# time.py
# -*- coding: utf-8 -*-
"""
Primitive runtime bench (same as before) BUT symmetric cipher is AES-128.
- Hash: SHA3-256  (unchanged)
- Chebyshev T_n  (unchanged)
- ECC scalar/double-scalar (unchanged)
- PUF emulator    (unchanged)
- BigInt mul/mod/mulmod (unchanged)
- Symmetric: AES-128 CTR (default); optional GCM via --aes gcm
Output: Operation | Mean(ms) | Stdev(ms)
"""

from __future__ import annotations
import argparse, hashlib, os, secrets, statistics, time
from typing import Callable, Tuple, List

# ========= utils =========
def now_ns() -> int:
    return time.perf_counter_ns()

def ns_to_ms(ns: int) -> float:
    return ns / 1_000_000.0

# ========= ECC (same as before) =========
from ecdsa import curves
from ecdsa.ellipticcurve import Point

CURVE = curves.NIST256p
G: Point = CURVE.generator
ORDER = CURVE.order

# ========= Chebyshev & PUF (same as before) =========
def chebyshev_T(n: int, x: int, p: int) -> int:
    if n == 0: return 1 % p
    if n == 1: return x % p
    T0, T1 = 1 % p, x % p
    for _ in range(2, n + 1):
        T0, T1 = T1, (2 * x * T1 - T0) % p
    return T1

def puf_emulator(challenge: bytes, size: int = 16, rounds: int = 1) -> bytes:
    buf = challenge
    for _ in range(rounds):
        buf = hashlib.sha3_256(b"PUF" + buf).digest()
    return buf[:size]

# ========= Benchmark harness (unchanged) =========
def benchmark(fn: Callable[[], None], iters: int) -> Tuple[float, float, List[float]]:
    times = []
    warm = min(10, max(1, iters // 50))
    for _ in range(warm):
        fn()
    for _ in range(iters):
        t0 = now_ns(); fn(); t1 = now_ns()
        times.append(ns_to_ms(t1 - t0))
    mean = statistics.fmean(times)
    stdev = statistics.pstdev(times) if len(times) > 1 else 0.0
    return mean, stdev, times

# ========= Primitive ops (unchanged except symmetric) =========
def op_Tcm_factory(n_degree: int = 128):
    def _fn():
        x = secrets.randbelow(ORDER - 1) + 1
        _ = chebyshev_T(n_degree, x, ORDER)
    return _fn

def op_Tsm():
    k = secrets.randbelow(ORDER - 1) + 1
    _ = G * k

def op_Tmsm():
    u = secrets.randbelow(ORDER - 1) + 1
    v = secrets.randbelow(ORDER - 1) + 1
    sk = secrets.randbelow(ORDER - 1) + 1
    Q = G * sk
    _ = (G * u) + (Q * v)

def op_Th():
    m = os.urandom(64)
    _ = hashlib.sha3_256(m).digest()

def op_Tpuf(rounds: int = 1):
    ch = os.urandom(16)
    _ = puf_emulator(ch, size=16, rounds=rounds)

# ========= BigInt ops (unchanged) =========
def rand_bits(bits: int) -> int:
    return secrets.randbits(bits) | (1 << (bits - 1))

def op_bigint_mul_factory(bits: int):
    a = rand_bits(bits); b = rand_bits(bits)
    def _fn():
        _ = a * b
    return _fn

def op_bigint_mod_factory(bits: int):
    M = rand_bits(bits) | 1
    # dividend ~ 2*bits 以匹配 mul 后约减
    x = rand_bits(bits * 2)
    def _fn():
        _ = x % M
    return _fn

def op_bigint_mulmod_factory(bits: int):
    a = rand_bits(bits); b = rand_bits(bits); M = rand_bits(bits) | 1
    def _fn():
        _ = (a * b) % M
    return _fn

# ========= Symmetric: AES-128 (CTR default) =========
# We only changed this part; others are untouched.
AES_BACKEND = None
def _select_aes():
    global AES_BACKEND
    try:
        from Crypto.Cipher import AES
        AES_BACKEND = ("pycryptodome", AES)
        return
    except Exception:
        pass
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        AES_BACKEND = ("cryptography", (Cipher, algorithms, modes, AESGCM))
        return
    except Exception:
        AES_BACKEND = None
_select_aes()

def op_Tsym_aes128_ctr_enc_factory(msg_len: int):
    if AES_BACKEND is None:
        def _fn(): pass
        return _fn
    if AES_BACKEND[0] == "pycryptodome":
        from Crypto.Cipher import AES
        key = os.urandom(16); nonce8 = os.urandom(8); pt = os.urandom(msg_len)
        def _fn():
            _ = AES.new(key, AES.MODE_CTR, nonce=nonce8).encrypt(pt)
        return _fn
    else:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        key = os.urandom(16); nonce16 = os.urandom(16); pt = os.urandom(msg_len)
        def _fn():
            enc = Cipher(algorithms.AES(key), modes.CTR(nonce16)).encryptor()
            _ = enc.update(pt) + enc.finalize()
        return _fn

def op_Tsym_aes128_ctr_dec_factory(msg_len: int):
    if AES_BACKEND is None:
        def _fn(): pass
        return _fn
    if AES_BACKEND[0] == "pycryptodome":
        from Crypto.Cipher import AES
        key = os.urandom(16); nonce8 = os.urandom(8); pt = os.urandom(msg_len)
        ct = AES.new(key, AES.MODE_CTR, nonce=nonce8).encrypt(pt)
        def _fn():
            _ = AES.new(key, AES.MODE_CTR, nonce=nonce8).decrypt(ct)
        return _fn
    else:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        key = os.urandom(16); nonce16 = os.urandom(16); pt = os.urandom(msg_len)
        ct = Cipher(algorithms.AES(key), modes.CTR(nonce16)).encryptor().update(pt)
        def _fn():
            dec = Cipher(algorithms.AES(key), modes.CTR(nonce16)).decryptor()
            _ = dec.update(ct) + dec.finalize()
        return _fn

def op_Tsym_aes128_gcm_enc_factory(msg_len: int):
    if AES_BACKEND is None:
        def _fn(): pass
        return _fn
    if AES_BACKEND[0] == "pycryptodome":
        from Crypto.Cipher import AES
        key = os.urandom(16); n12 = os.urandom(12); pt = os.urandom(msg_len)
        def _fn():
            _ = AES.new(key, AES.MODE_GCM, nonce=n12).encrypt_and_digest(pt)
        return _fn
    else:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = os.urandom(16); n12 = os.urandom(12); pt = os.urandom(msg_len); aead = AESGCM(key)
        def _fn():
            _ = aead.encrypt(n12, pt, None)
        return _fn

def op_Tsym_aes128_gcm_dec_factory(msg_len: int):
    if AES_BACKEND is None:
        def _fn(): pass
        return _fn
    if AES_BACKEND[0] == "pycryptodome":
        from Crypto.Cipher import AES
        key = os.urandom(16); n12 = os.urandom(12); pt = os.urandom(msg_len)
        ct, tag = AES.new(key, AES.MODE_GCM, nonce=n12).encrypt_and_digest(pt)
        def _fn():
            _ = AES.new(key, AES.MODE_GCM, nonce=n12).decrypt_and_verify(ct, tag)
        return _fn
    else:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = os.urandom(16); n12 = os.urandom(12); pt = os.urandom(msg_len); aead = AESGCM(key)
        out = aead.encrypt(n12, pt, None)
        def _fn():
            _ = aead.decrypt(n12, out, None)
        return _fn

# ========= main =========
def main():
    try:
        import pandas as pd
        have_pd = True
    except Exception:
        have_pd = False

    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=1000, help="each op repetitions")
    ap.add_argument("--cm-degree", type=int, default=128, help="Chebyshev degree")
    ap.add_argument("--puf-rounds", type=int, default=1, help="PUF emulate rounds")
    ap.add_argument("--msg", type=int, default=128, help="symmetric message size (bytes)")
    ap.add_argument("--aes", type=str, default="ctr", choices=["ctr","gcm"], help="AES mode for symmetric rows")
    ap.add_argument("--bigint-bits", type=int, default=3200, help="bit-length for BigInt mul/mod")
    args = ap.parse_args()

    results: List[Tuple[str, float, float]] = []

    # Unchanged primitives
    m, s, _ = benchmark(op_Tcm_factory(args.cm_degree), args.iters); results.append((f"Tcm (T_{args.cm_degree})", m, s))
    m, s, _ = benchmark(op_Tsm, args.iters);                           results.append(("Tsm (ECC scalar mult)", m, s))
    m, s, _ = benchmark(op_Tmsm, args.iters);                          results.append(("Tmsm (u·P + v·Q)", m, s))
    m, s, _ = benchmark(op_Th, args.iters);                            results.append(("Th (SHA3-256)", m, s))
    m, s, _ = benchmark(lambda: op_Tpuf(args.puf_rounds), args.iters); results.append((f"Tpuf (rounds={args.puf_rounds})", m, s))

    # Symmetric — replaced with AES-128 (message-level)
    if args.aes == "ctr":
        m, s, _ = benchmark(op_Tsym_aes128_ctr_enc_factory(args.msg), args.iters); results.append((f"Tsym_aes128_ctr_enc ({args.msg}B)", m, s))
        m, s, _ = benchmark(op_Tsym_aes128_ctr_dec_factory(args.msg), args.iters); results.append((f"Tsym_aes128_ctr_dec ({args.msg}B)", m, s))
    else:
        m, s, _ = benchmark(op_Tsym_aes128_gcm_enc_factory(args.msg), args.iters); results.append((f"Tsym_aes128_gcm_enc ({args.msg}B)", m, s))
        m, s, _ = benchmark(op_Tsym_aes128_gcm_dec_factory(args.msg), args.iters); results.append((f"Tsym_aes128_gcm_dec ({args.msg}B)", m, s))

    # BigInt (unchanged)
    bits = args.bigint_bits
    m, s, _ = benchmark(op_bigint_mul_factory(bits), args.iters);       results.append((f"BigInt_mul (|M|={bits}b)", m, s))
    m, s, _ = benchmark(op_bigint_mod_factory(bits), args.iters);       results.append((f"BigInt_mod (|M|={bits}b)", m, s))
    m, s, _ = benchmark(op_bigint_mulmod_factory(bits), args.iters);    results.append((f"BigInt_mulmod (|M|={bits}b)", m, s))

    if have_pd:
        import pandas as pd
        df = pd.DataFrame(results, columns=["Operation", "Mean (ms)", "Stdev (ms)"])
        print(df.to_string(index=False))
    else:
        print("Operation".ljust(34), "Mean (ms)".rjust(12), "Stdev (ms)".rjust(12))
        for op, mean, st in results:
            print(op.ljust(34), f"{mean:12.6f}", f"{st:12.6f}")

if __name__ == "__main__":
    main()
