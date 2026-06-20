# ProVerif Model Explanation for O2N-AKA

This note briefly explains the ProVerif model used to verify the revised
O2N-AKA protocol. The executable baseline model is:

```text
O2N_AKA_single_session_checked.pv
```

The model is designed for ProVerif 2.05.

## 1. Model Scope

The model verifies one complete AKA session among:

- a user `U_i`,
- an edge gateway `EG`,
- one representative device `SD_j`.

The one-to-many case is represented by applying the same per-device process to
each selected device. The CRT aggregation is abstracted by a constructor and a
destructor:

```prolog
crt(a,idj,delta,kmod)
recover_crt(crt(a,idj,delta,kmod), idj, delta, kmod) = a
```

This abstraction captures the security-relevant property that the user can
recover the device contribution `a_j` from the CRT aggregate when the correct
`ID_j`, `delta_j`, and `K_mod` are used.

## 2. Attacker and Channels

The model uses an active Dolev-Yao attacker:

```prolog
set attacker = active.
free c : channel.
```

All protocol messages `M1` to `M4` are sent over the public channel `c`.
Therefore, the attacker can eavesdrop, block, replay, modify, and inject
messages on this channel.

## 3. Cryptographic Abstractions

The following symbolic primitives are used:

- `h1`--`h5`: hash functions with different arities.
- `hs3`: the short hash function `h_s`.
- `senc/sdec`: symmetric encryption and decryption.
- `xor/unxor_left/unxor_right`: symbolic XOR abstraction.
- `puf`: private PUF function; the attacker cannot evaluate it.
- `crt/recover_crt`: CRT aggregation and recovery abstraction.

The model focuses on symbolic secrecy and correspondence properties. It does
not model computational hardness or concrete bit-level arithmetic.

## 4. Entity Processes

### User Process

The user process models:

1. local login verification using `ID_i`, `PW_i`, `BIO_i`, and `Log_i`;
2. recovery of `X_i` from `DTC_i`;
3. generation of nonce `N`;
4. construction and transmission of `M1`;
5. reception and verification of `M4`;
6. recovery of `a_j` from the CRT aggregate;
7. derivation of the session key `sk = h(N,ID_j,a_j)`;
8. user credential update after successful verification.

The events `UserSendsM1`, `UserSessionKey`, and `UserAcceptsGateway` are used
to mark key security-relevant points in the user process.

### Device Process

The device process models:

1. reception of `M2`;
2. recovery of the PUF challenge `C_j`;
3. computation of `R_j = PUF(C_j)`;
4. recovery of nonce `N`;
5. verification of `B_j`;
6. generation of fresh device contribution `a_j`;
7. computation of `M3`;
8. derivation of `sk = h(N,ID_j,a_j)`.

The events `DeviceAcceptsGateway`, `DeviceSessionKey`, and `DeviceSendsM3`
record gateway authentication, device-side key generation, and device response
generation.

### Gateway Process

The gateway process models:

1. reception and verification of `M1`;
2. recovery of `X_i` from `C_i` and `mk`;
3. construction and transmission of `M2`;
4. reception and verification of `M3`;
5. safe device-state update after valid `M3`;
6. CRT aggregate construction;
7. construction and transmission of `M4`;
8. retention of the previous pseudonym-bound credential for failed user update.

The gateway also includes a failed device-update branch. If `M3` is missing or
rejected, the event `GatewayKeepsOldDevice` is recorded before
`DeviceUpdateFailed`, representing that the old device state `{C_j,R_j}` is
preserved.

## 5. Verified Queries

The model contains ten main queries.

| No. | ProVerif query | Security goal |
|---|---|---|
| Q1 | `not (event(UserSessionKey(sk)) && attacker(sk))` | User-side session-key secrecy |
| Q2 | `not (event(DeviceSessionKey(sk)) && attacker(sk))` | Device-side session-key secrecy |
| Q3 | `GatewayAcceptsUser(pid,N,idj) ==> UserSendsM1(pid,N,idj)` | User authentication to gateway |
| Q4 | `DeviceAcceptsGateway(idj,N) ==> GatewaySendsM2(idj,N)` | Gateway authentication to device |
| Q5 | `GatewayAcceptsDevice(idj,N,a_j) ==> DeviceSendsM3(idj,N,a_j)` | Device authentication to gateway |
| Q6 | `UserAcceptsGateway(pid,idj,sk) ==> GatewaySendsM4(pid,idj,sk)` | Gateway authentication to user |
| Q7 | `UserAcceptsGateway(pid,idj,sk) ==> DeviceSessionKey(sk)` | User-device key agreement |
| Q8 | `UserUpdateFailed(pid) ==> GatewayKeepsPrevious(pid)` | User-side failed-update recovery |
| Q9 | `GatewayUpdatesDevice(idj,N,a_j) ==> GatewayAcceptsDevice(idj,N,a_j)` | Safe device-state update after valid `M3` |
| Q10 | `DeviceUpdateFailed(idj,N) ==> GatewayKeepsOldDevice(idj,N)` | Device-side failed-update recovery |

Q1 and Q2 are secrecy queries. They verify that accepted session keys cannot be
derived by the Dolev-Yao attacker from public-channel messages.

Q3--Q6 are correspondence queries for mutual authentication.

Q7 verifies that the user and the device derive the same session key.

Q8--Q10 verify the dynamic-update logic, including recovery from failed user
updates and failed device-state updates.

## 6. Verification Result

All ten queries return `true` in ProVerif 2.05. The normalized verification
summary is provided in:

```text
O2N_AKA_normalized_summary.txt
```

The raw ProVerif output may contain automatically renamed variables such as
`sk_2`, `pid_2`, `n_3`, and `idj_4`. These correspond to the source-level
variables `sk`, `pid`, `N`, and `ID_j`.

## 7. Extended Oracle Model

The file:

```text
O2N_AKA_revised_model.pv
```

contains an extended model template with state tables and reveal-oracle
templates, including long-term-key reveal, gateway-state reveal, cloud/seed
reveal, user-state reveal, device-state reveal, and failed-update behavior.

The executable baseline model is used for the terminating ProVerif results,
while the extended model documents how stronger compromise and failed-update
oracles are represented.
