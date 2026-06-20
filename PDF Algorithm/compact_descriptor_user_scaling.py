import hashlib
import json
import time
from statistics import mean, median

import compact_descriptor_pdf_prototype as pdf


BATCH_SIZES = [10, 100, 500, 1000, 1500, 2000]
REPEATS = 10


def moduli_digest(moduli: list[int]) -> str:
    h = hashlib.sha256()
    for modulus in moduli:
        h.update(modulus.to_bytes((pdf.DEFAULT_L + 7) // 8, "big"))
    return h.hexdigest()


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * p))
    return ordered[index]


def measure_user_reconstruction(records: list[pdf.RARecord]) -> dict[str, object]:
    expected_moduli = [record.modulus for record in records]
    expected_digest = moduli_digest(expected_moduli)

    samples_ms: list[float] = []
    reconstructed_digest = ""
    deterministic_repeat_match = True
    descriptor_match = True

    previous_moduli: list[int] | None = None
    for _ in range(REPEATS):
        start = time.perf_counter_ns()
        reconstructed = [
            pdf.reconstruct_modulus_user(pdf.K_MOD, record.device_id, record.delta, pdf.DEFAULT_L)
            for record in records
        ]
        elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
        samples_ms.append(elapsed_ms)

        descriptor_match = descriptor_match and (reconstructed == expected_moduli)
        if previous_moduli is not None and reconstructed != previous_moduli:
            deterministic_repeat_match = False
        previous_moduli = reconstructed
        reconstructed_digest = moduli_digest(reconstructed)

    all_l_bit = all((1 << (pdf.DEFAULT_L - 1)) <= m < (1 << pdf.DEFAULT_L) for m in expected_moduli)
    all_unique = len(set(expected_moduli)) == len(expected_moduli)
    digest_match = reconstructed_digest == expected_digest

    first = records[0]
    last = records[-1]

    return {
        "n": len(records),
        "repeats": REPEATS,
        "avg_total_ms": mean(samples_ms),
        "p50_total_ms": median(samples_ms),
        "p95_total_ms": percentile(samples_ms, 0.95),
        "min_total_ms": min(samples_ms),
        "max_total_ms": max(samples_ms),
        "avg_per_device_ms": mean(samples_ms) / len(records),
        "avg_per_device_us": (mean(samples_ms) * 1000) / len(records),
        "descriptor_match": descriptor_match,
        "deterministic_repeat_match": deterministic_repeat_match,
        "digest_match": digest_match,
        "all_l_bit": all_l_bit,
        "all_unique": all_unique,
        "moduli_sha256": expected_digest,
        "first_record": {
            "device_id": first.device_id,
            "delta_hex": first.delta.hex(),
            "version": first.version,
            "offset": first.offset,
            "m_j_hex": hex(first.modulus),
        },
        "last_record": {
            "device_id": last.device_id,
            "delta_hex": last.delta.hex(),
            "version": last.version,
            "offset": last.offset,
            "m_j_hex": hex(last.modulus),
        },
    }


def main() -> None:
    rows: list[dict[str, object]] = []

    print("=== Compact Descriptor User Reconstruction Scaling ===")
    print(f"L: {pdf.DEFAULT_L} bits")
    print(f"descriptor: {pdf.DESCRIPTOR_BITS} bits = v({pdf.VERSION_BITS}) || s({pdf.OFFSET_BITS})")
    print(f"repeats per n: {REPEATS}")
    print("method: user reconstructs m_j = derive_base(K_mod, ID_j, v_j, L) + 2*s_j")
    print("PrimeTest on user side: NO")
    print()

    print(
        "n     avg total(ms)   p50 total(ms)   p95 total(ms)   "
        "avg/device(us)   match   repeat   digest   unique"
    )

    for n in BATCH_SIZES:
        device_ids = pdf.make_device_ids(n)
        records = pdf.generate_batch_ra(device_ids, pdf.DEFAULT_L)
        row = measure_user_reconstruction(records)
        rows.append(row)

        print(
            f"{n:<5} "
            f"{float(row['avg_total_ms']):>13.6f} "
            f"{float(row['p50_total_ms']):>15.6f} "
            f"{float(row['p95_total_ms']):>15.6f} "
            f"{float(row['avg_per_device_us']):>16.6f} "
            f"{'PASS' if row['descriptor_match'] else 'FAIL':>7} "
            f"{'PASS' if row['deterministic_repeat_match'] else 'FAIL':>8} "
            f"{'PASS' if row['digest_match'] else 'FAIL':>8} "
            f"{'PASS' if row['all_unique'] else 'FAIL':>8}"
        )

    print()
    print("=== Deterministic Correctness Meaning ===")
    print("match  : user reconstructed moduli equal RA-generated moduli")
    print("repeat : repeated user reconstructions produce identical moduli")
    print("digest : SHA-256 digest of reconstructed moduli equals RA digest")
    print("unique : generated moduli are pairwise unique")
    print()
    print("=== Sample Mapping Per Batch ===")
    for row in rows:
        first = row["first_record"]
        last = row["last_record"]
        print(
            f"n={row['n']}: first {first['device_id']} delta={first['delta_hex']} "
            f"m_j={first['m_j_hex']}; last {last['device_id']} delta={last['delta_hex']} "
            f"m_j={last['m_j_hex']}"
        )

    print()
    print("=== JSON RESULTS ===")
    print(json.dumps(rows, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
