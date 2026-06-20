# PDF Code Overview

This note summarizes the Python files related to the compact-descriptor based Deterministic Prime Derivation Function (PDF) prototype.

## Main Implementation File

The main PDF implementation is:

```text
compact_descriptor_pdf_prototype.py
```

This file implements the complete compact descriptor PDF workflow, including:

- RA-side modulus generation;
- compact descriptor generation;
- user-side modulus reconstruction;
- deterministic primality testing;
- CRT aggregation and recovery;
- baseline comparison with user-side prime search;
- timing and correctness output.

## Core Protocol Logic

The implemented PDF follows the compact descriptor design:

```text
delta_j = v_j || s_j
```

where:

```text
v_j : modulus version
s_j : prime offset
```

The RA searches for a valid offset `s_j` such that:

```text
m_j = b_{j,v} + 2*s_j
```

is an L-bit prime modulus and is not already assigned to another device.

The user receives only the compact descriptor `delta_j` and reconstructs:

```text
m_j' = b_{j,v} + 2*s_j
```

The user-side reconstruction does not perform primality testing or prime search.

## Important Functions

In `compact_descriptor_pdf_prototype.py`:

```text
canon()
```

Canonicalizes device identities.

```text
h0_int()
```

Implements HMAC-SHA256 as the keyed PRF.

```text
pack_delta(), unpack_delta()
```

Encode and decode the compact descriptor.

```text
derive_base()
```

Derives the deterministic base value `b_{j,v}`.

```text
generate_descriptor_ra()
```

RA-side descriptor and modulus generation.

```text
reconstruct_modulus_user()
```

User-side reconstruction of `m_j` from `K_mod`, `ID_j`, `delta_j`, and `L`.

```text
is_probable_prime()
```

Deterministic Miller-Rabin probable-prime test used by the RA.

```text
crt_aggregate()
```

Constructs the CRT aggregate and supports CRT recovery verification.

## Timing and Scaling File

The user-side scaling experiment is implemented in:

```text
compact_descriptor_user_scaling.py
```

This script measures the user-side reconstruction time for different numbers of devices:

```text
10, 100, 500, 1000, 1500, 2000
```

It also checks:

```text
match  : user-reconstructed moduli equal RA-assigned moduli
repeat : repeated reconstructions are deterministic
digest : SHA-256 digest of reconstructed moduli equals RA digest
unique : generated moduli are pairwise unique
```

## How to Run

Run the complete prototype:

```bash
python compact_descriptor_pdf_prototype.py
```

Run the user-side scaling experiment:

```bash
python compact_descriptor_user_scaling.py
```

If using the Codex bundled Python runtime:

```powershell
C:\Users\guozh\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe compact_descriptor_pdf_prototype.py
```

## Expected Evidence

The prototype verifies that:

- user-reconstructed moduli exactly match RA-assigned moduli;
- generated moduli have the required bit length;
- generated moduli pass deterministic primality testing;
- generated moduli are unique;
- CRT recovery succeeds.

Therefore, `compact_descriptor_pdf_prototype.py` is the primary file corresponding to the PDF algorithm implementation, while `compact_descriptor_user_scaling.py` is the auxiliary file used to evaluate user-side reconstruction overhead.

