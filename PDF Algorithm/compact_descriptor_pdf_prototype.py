import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from math import prod
from statistics import mean
from typing import Iterable, Sequence


K_MOD = bytes.fromhex(
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
)
K_SESSION_SEED = bytes.fromhex("aabbccddeeff00112233445566778899")

DEFAULT_L = 160
VERSION_BITS = 8
OFFSET_BITS = 16
DESCRIPTOR_BITS = VERSION_BITS + OFFSET_BITS
MAX_VERSION = (1 << VERSION_BITS) - 1
MAX_OFFSET = (1 << OFFSET_BITS) - 1
MR_ROUNDS = 32
TIMING_BATCHES = [10, 20, 50, 100]


@dataclass(frozen=True)
class RARecord:
    device_id: str | bytes
    delta: bytes
    version: int
    offset: int
    modulus: int
    base: int


def i2osp(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("integer must be non-negative")
    if x >= 1 << (8 * length):
        raise ValueError("integer does not fit in the requested length")
    return x.to_bytes(length, "big")


def os2ip(data: bytes) -> int:
    return int.from_bytes(data, "big")


def canon(device_id: str | bytes) -> bytes:
    """
    Canon(ID_j): prepend a two-byte big-endian length prefix to the identity.

    bytes inputs are treated as fixed binary identifiers. str inputs are
    stripped and encoded as UTF-8.
    """
    if isinstance(device_id, bytes):
        body = device_id
    elif isinstance(device_id, str):
        body = device_id.strip().encode("utf-8")
    else:
        raise TypeError("device_id must be str or bytes")

    if not body:
        raise ValueError("device identity must not be empty")
    if len(body) > 0xFFFF:
        raise ValueError("device identity is too long for a two-byte prefix")
    return i2osp(len(body), 2) + body


def h0_int(k_mod: bytes, message: bytes) -> int:
    """H_0(K_mod, message): HMAC-SHA256 interpreted as a nonnegative integer."""
    return os2ip(hmac.new(k_mod, message, hashlib.sha256).digest())


def pack_delta(v: int, s: int) -> bytes:
    """Encode delta_j = v_j || s_j as a three-byte public descriptor."""
    if not (0 <= v <= MAX_VERSION):
        raise ValueError("v must satisfy 0 <= v <= 255")
    if not (0 <= s <= MAX_OFFSET):
        raise ValueError("s must satisfy 0 <= s <= 65535")
    return i2osp(v, 1) + i2osp(s, 2)


def unpack_delta(delta_bytes: bytes) -> tuple[int, int]:
    """Decode the three-byte descriptor into (v_j, s_j)."""
    if not isinstance(delta_bytes, bytes):
        raise TypeError("delta_bytes must be bytes")
    if len(delta_bytes) != 3:
        raise ValueError("delta must be exactly three bytes")
    return delta_bytes[0], os2ip(delta_bytes[1:])


def validate_l(L: int) -> None:
    if L < 64:
        raise ValueError("L must be at least 64 bits")


def derive_base(k_mod: bytes, device_id: str | bytes, v: int, L: int) -> int:
    """
    Compute b_{j,v} from K_mod, Canon(ID_j), v_j, and L.

    b_{j,v} = 2^(L-1) + (H_0(K_mod, ID_j^* || v_j) mod 2^(L-1)),
    adjusted to be odd.
    """
    validate_l(L)
    if not (0 <= v <= MAX_VERSION):
        raise ValueError("v must satisfy 0 <= v <= 255")

    rho = h0_int(k_mod, canon(device_id) + i2osp(v, 1))
    b = (1 << (L - 1)) + (rho % (1 << (L - 1)))
    if b % 2 == 0:
        b += 1
    return b


def sieve_primes(limit: int) -> tuple[int, ...]:
    sieve = bytearray(b"\x01") * (limit + 1)
    sieve[:2] = b"\x00\x00"
    for p in range(2, int(limit**0.5) + 1):
        if sieve[p]:
            sieve[p * p : limit + 1 : p] = b"\x00" * (((limit - p * p) // p) + 1)
    return tuple(i for i, is_prime in enumerate(sieve) if is_prime)


SMALL_PRIMES = sieve_primes(4096)
MR_BASES_64 = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)


def mr_accepts_base(n: int, base: int, d: int, s: int) -> bool:
    a = base % n
    if a in (0, 1):
        return True

    x = pow(a, d, n)
    if x in (1, n - 1):
        return True

    for _ in range(s - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return True
    return False


def deterministic_mr_base(n: int, round_index: int) -> int:
    n_bytes = i2osp(n, (n.bit_length() + 7) // 8)
    material = b"PDF-MR-base-v1" + i2osp(round_index, 4) + n_bytes
    raw = hashlib.shake_256(material).digest(len(n_bytes) + 16)
    return 2 + (os2ip(raw) % (n - 3))


def is_probable_prime(n: int, rounds: int = MR_ROUNDS) -> bool:
    """
    Deterministic Miller-Rabin probable-prime test for experimental validation.

    Trial division removes small factors. Values below 2^64 use a complete
    deterministic Miller-Rabin base set. Larger values use SHAKE-derived bases
    so repeated runs make identical decisions.
    """
    if n < 2:
        return False

    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    if n < (1 << 64):
        bases: Iterable[int] = MR_BASES_64
    else:
        if rounds <= 0:
            raise ValueError("rounds must be positive")
        bases = (deterministic_mr_base(n, i) for i in range(rounds))

    return all(mr_accepts_base(n, base, d, s) for base in bases)


def generate_descriptor_ra(
    k_mod: bytes,
    device_id: str | bytes,
    assigned_moduli: set[int],
    L: int = DEFAULT_L,
) -> RARecord:
    """
    RA descriptor generation.

    Search v_j and s_j such that m_j = b_{j,v} + 2*s_j is an unassigned
    L-bit prime. The compact descriptor is delta_j = pack(v_j, s_j).
    """
    validate_l(L)

    for v in range(MAX_VERSION + 1):
        b = derive_base(k_mod, device_id, v, L)
        for s in range(MAX_OFFSET + 1):
            m = b + 2 * s
            if m >= (1 << L):
                break
            if m in assigned_moduli:
                continue
            if is_probable_prime(m):
                delta = pack_delta(v, s)
                assigned_moduli.add(m)
                return RARecord(
                    device_id=device_id,
                    delta=delta,
                    version=v,
                    offset=s,
                    modulus=m,
                    base=b,
                )

    raise RuntimeError("failed to generate a descriptor for all 8-bit versions")


def reconstruct_modulus_user(
    k_mod: bytes,
    device_id: str | bytes,
    delta: bytes,
    L: int = DEFAULT_L,
) -> int:
    """
    User-side compact PDF reconstruction.

    The user parses delta_j, recomputes b_{j,v}, and returns b_{j,v}+2*s_j.
    No primality testing and no prime search are performed here.
    """
    validate_l(L)
    v, s = unpack_delta(delta)
    b = derive_base(k_mod, device_id, v, L)
    m = b + 2 * s
    if m >= (1 << L):
        raise ValueError("descriptor reconstructs a value outside the L-bit range")
    return m


def old_pdf_user_prime_search(
    k_mod: bytes,
    device_id: str | bytes,
    delta: bytes,
    L: int = DEFAULT_L,
) -> int:
    """
    Old baseline PDF.

    The user derives an L-bit odd starting point from H_0(K_mod, ID_j^*||delta_j)
    and searches x, x+2, x+4, ... until a prime is found.
    """
    validate_l(L)
    if len(delta) != 3:
        raise ValueError("delta must be exactly three bytes")

    rho = h0_int(k_mod, canon(device_id) + delta)
    x = (1 << (L - 1)) + (rho % (1 << (L - 1)))
    if x % 2 == 0:
        x += 1

    while x < (1 << L):
        if is_probable_prime(x):
            return x
        x += 2

    raise RuntimeError("old PDF search reached the end of the L-bit interval")


def deterministic_residue(k_session_seed: bytes, device_id: str | bytes, modulus: int) -> int:
    digest = hmac.new(k_session_seed, canon(device_id), hashlib.sha256).digest()
    return os2ip(digest) % modulus


def crt_aggregate(residues: Sequence[int], moduli: Sequence[int]) -> tuple[int, int]:
    """
    CRT aggregation:
        SR = sum_j a_j * Gamma_j mod M,
        Gamma_j = M_j * inverse(M_j mod m_j).
    """
    if len(residues) != len(moduli):
        raise ValueError("residues and moduli must have the same length")
    if not residues:
        raise ValueError("CRT input must not be empty")

    for index, (a_j, m_j) in enumerate(zip(residues, moduli)):
        if m_j <= 1:
            raise ValueError(f"moduli[{index}] must be greater than one")
        if not (0 <= a_j < m_j):
            raise ValueError(f"residues[{index}] must be in Z_mj")

    M = prod(moduli)
    SR = 0

    for a_j, m_j in zip(residues, moduli):
        M_j = M // m_j
        mu_j = pow(M_j % m_j, -1, m_j)
        gamma_j = M_j * mu_j
        SR += a_j * gamma_j

    return SR % M, M


def make_device_ids(n: int) -> list[str]:
    return [f"SD-{j:06d}" for j in range(1, n + 1)]


def generate_batch_ra(device_ids: Sequence[str | bytes], L: int = DEFAULT_L) -> list[RARecord]:
    assigned: set[int] = set()
    records: list[RARecord] = []
    for device_id in device_ids:
        records.append(generate_descriptor_ra(K_MOD, device_id, assigned, L))
    return records


def run_correctness_tests(L: int = DEFAULT_L, n: int = 100) -> dict[str, bool]:
    device_ids = make_device_ids(n)
    records = generate_batch_ra(device_ids, L)
    moduli_ra = [record.modulus for record in records]
    moduli_user = [
        reconstruct_modulus_user(K_MOD, record.device_id, record.delta, L)
        for record in records
    ]

    descriptor_match = moduli_user == moduli_ra
    all_l_bit = all((1 << (L - 1)) <= m < (1 << L) for m in moduli_ra)
    all_prime = all(is_probable_prime(m) for m in moduli_ra)
    all_unique = len(set(moduli_ra)) == len(moduli_ra)

    residues = [
        deterministic_residue(K_SESSION_SEED, record.device_id, record.modulus)
        for record in records
    ]
    SR, _ = crt_aggregate(residues, moduli_ra)
    crt_recovery = all(SR % m == a for a, m in zip(residues, moduli_user))
    if not crt_recovery:
        raise AssertionError("CRT recovery failed")

    return {
        "descriptor_reconstruction_match": descriptor_match,
        "all_moduli_are_L_bit": all_l_bit,
        "all_moduli_are_prime": all_prime,
        "all_moduli_are_unique": all_unique,
        "CRT_recovery": crt_recovery,
    }


def ns_to_ms(ns: int) -> float:
    return ns / 1_000_000.0


def fmt_ms(value: float) -> str:
    return f"{value:.6f}"


def time_compact_method(device_ids: Sequence[str], L: int) -> dict[str, float | int]:
    assigned: set[int] = set()
    records: list[RARecord] = []

    t0 = time.perf_counter_ns()
    for device_id in device_ids:
        records.append(generate_descriptor_ra(K_MOD, device_id, assigned, L))
    ra_ns = time.perf_counter_ns() - t0

    t0 = time.perf_counter_ns()
    moduli_user = [
        reconstruct_modulus_user(K_MOD, record.device_id, record.delta, L)
        for record in records
    ]
    user_ns = time.perf_counter_ns() - t0

    moduli_ra = [record.modulus for record in records]
    if moduli_user != moduli_ra:
        raise AssertionError("user reconstruction did not match RA moduli")

    residues = [
        deterministic_residue(K_SESSION_SEED, record.device_id, record.modulus)
        for record in records
    ]

    t0 = time.perf_counter_ns()
    SR, _ = crt_aggregate(residues, moduli_ra)
    crt_build_ns = time.perf_counter_ns() - t0

    t0 = time.perf_counter_ns()
    recovered = [SR % m for m in moduli_user]
    crt_recover_ns = time.perf_counter_ns() - t0
    if recovered != residues:
        raise AssertionError("CRT recovery failed")

    offsets = [record.offset for record in records]
    versions = [record.version for record in records]

    return {
        "n": len(device_ids),
        "ra_total_ms": ns_to_ms(ra_ns),
        "ra_avg_per_device_ms": ns_to_ms(ra_ns) / len(device_ids),
        "avg_offset": mean(offsets),
        "max_offset": max(offsets),
        "version_increments": sum(versions),
        "max_version": max(versions),
        "user_reconstruction_total_ms": ns_to_ms(user_ns),
        "user_reconstruction_avg_per_device_ms": ns_to_ms(user_ns) / len(device_ids),
        "crt_aggregate_construction_ms": ns_to_ms(crt_build_ns),
        "crt_residue_recovery_ms": ns_to_ms(crt_recover_ns),
    }


def time_old_user_baseline(records: Sequence[RARecord], L: int) -> dict[str, float | int]:
    t0 = time.perf_counter_ns()
    moduli = [
        old_pdf_user_prime_search(K_MOD, record.device_id, record.delta, L)
        for record in records
    ]
    elapsed_ns = time.perf_counter_ns() - t0
    if len(moduli) != len(records):
        raise AssertionError("baseline derivation returned the wrong number of moduli")
    return {
        "n": len(records),
        "old_user_prime_search_total_ms": ns_to_ms(elapsed_ns),
        "old_user_prime_search_avg_per_device_ms": ns_to_ms(elapsed_ns) / len(records),
    }


def run_timing_experiments(L: int = DEFAULT_L) -> dict[str, list[dict[str, float | int]]]:
    compact_rows: list[dict[str, float | int]] = []
    comparison_rows: list[dict[str, float | int]] = []

    for n in TIMING_BATCHES:
        device_ids = make_device_ids(n)

        compact = time_compact_method(device_ids, L)
        compact_rows.append(compact)

        records = generate_batch_ra(device_ids, L)
        old = time_old_user_baseline(records, L)

        new_total = compact["user_reconstruction_total_ms"]
        old_total = old["old_user_prime_search_total_ms"]
        speedup = old_total / new_total if new_total > 0 else float("inf")

        comparison_rows.append(
            {
                "n": n,
                "old_user_prime_search_total_ms": old_total,
                "new_compact_reconstruction_total_ms": new_total,
                "speedup_factor": speedup,
                "old_user_prime_search_avg_per_device_ms": old[
                    "old_user_prime_search_avg_per_device_ms"
                ],
                "new_compact_reconstruction_avg_per_device_ms": compact[
                    "user_reconstruction_avg_per_device_ms"
                ],
            }
        )

    return {
        "compact_descriptor_method": compact_rows,
        "baseline_comparison": comparison_rows,
    }


def pass_fail(value: bool) -> str:
    return "PASS" if value else "FAIL"


def print_configuration() -> None:
    print("=== Configuration ===")
    print(f"L: {DEFAULT_L} bits")
    print(f"descriptor size: {DESCRIPTOR_BITS} bits")
    print(f"version bits: {VERSION_BITS}")
    print(f"offset bits: {OFFSET_BITS}")
    print("HMAC function: HMAC-SHA256")
    print(f"Miller-Rabin: {MR_ROUNDS} deterministic SHAKE-derived bases")
    print()


def print_correctness(correctness: dict[str, bool]) -> None:
    print("=== Correctness ===")
    print(
        "descriptor reconstruction match: "
        f"{pass_fail(correctness['descriptor_reconstruction_match'])}"
    )
    print(f"all moduli are L-bit: {pass_fail(correctness['all_moduli_are_L_bit'])}")
    print(f"all moduli are prime: {pass_fail(correctness['all_moduli_are_prime'])}")
    print(f"all moduli are unique: {pass_fail(correctness['all_moduli_are_unique'])}")
    print(f"CRT recovery: {pass_fail(correctness['CRT_recovery'])}")
    print()


def print_compact_timing(rows: Sequence[dict[str, float | int]]) -> None:
    print("=== Compact Descriptor Method Timing ===")
    print(
        "n    RA total(ms)   RA avg(ms)    avg s      max s   "
        "v inc   User total(ms) User avg(ms)   CRT build(ms) CRT recover(ms)"
    )
    for row in rows:
        print(
            f"{int(row['n']):<4} "
            f"{fmt_ms(float(row['ra_total_ms'])):>12} "
            f"{fmt_ms(float(row['ra_avg_per_device_ms'])):>12} "
            f"{float(row['avg_offset']):>9.3f} "
            f"{int(row['max_offset']):>8} "
            f"{int(row['version_increments']):>7} "
            f"{fmt_ms(float(row['user_reconstruction_total_ms'])):>14} "
            f"{fmt_ms(float(row['user_reconstruction_avg_per_device_ms'])):>12} "
            f"{fmt_ms(float(row['crt_aggregate_construction_ms'])):>13} "
            f"{fmt_ms(float(row['crt_residue_recovery_ms'])):>15}"
        )
    print()


def print_baseline_comparison(rows: Sequence[dict[str, float | int]]) -> None:
    print("=== User-Side PDF Timing Comparison ===")
    print(
        "n    old prime-search total(ms)   new descriptor total(ms)   speedup"
    )
    for row in rows:
        print(
            f"{int(row['n']):<4} "
            f"{fmt_ms(float(row['old_user_prime_search_total_ms'])):>26} "
            f"{fmt_ms(float(row['new_compact_reconstruction_total_ms'])):>26} "
            f"{float(row['speedup_factor']):>9.2f}x"
        )
    print()


def main() -> None:
    print_configuration()

    correctness = run_correctness_tests(DEFAULT_L, n=max(TIMING_BATCHES))
    print_correctness(correctness)

    timing = run_timing_experiments(DEFAULT_L)
    print_compact_timing(timing["compact_descriptor_method"])
    print_baseline_comparison(timing["baseline_comparison"])

    raw_results = {
        "configuration": {
            "L": DEFAULT_L,
            "descriptor_bits": DESCRIPTOR_BITS,
            "version_bits": VERSION_BITS,
            "offset_bits": OFFSET_BITS,
            "hmac_function": "HMAC-SHA256",
            "miller_rabin_rounds": MR_ROUNDS,
            "timing_batches": TIMING_BATCHES,
            "K_mod_hex": K_MOD.hex(),
            "K_session_seed_hex": K_SESSION_SEED.hex(),
        },
        "correctness": correctness,
        "timing": timing,
    }

    print("=== JSON RESULTS ===")
    print(json.dumps(raw_results, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
