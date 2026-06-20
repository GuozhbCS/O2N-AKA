### Experimental code for the paper "One-to-Many Authentication and Key Agreement Scheme with Desynchronization Resilience and Forward Secrecy for Multi-Device IoT"

# O2N-AKA (ProVerif · ns-3 · PDF ·Baseline Timing)

This repository contains four parts used to reproduce the paper’s evaluations:

- **proverif/** — ProVerif security models (version **2.05**).  
  Run the `.pv` files to verify secrecy queries and correspondence assertions.

- **ns3/** — One-to-many scenario simulations on **ns-3.27**.  
  This folder also includes the paper’s simulation code and results **NS3 Simulation Result.pdf**.

- **PDF/** — The compact-descriptor based Deterministic Prime Derivation Function (PDF) prototype **Python 3.10**.  
  This file implements the complete compact descriptor PDF workflow.

- **baseline/** — Baseline timing code in Python **3.10** (e.g., hash/PUF/CRT-related operations).  
  Run the scripts to generate simple CSV outputs for computation-overhead tables.

**Environment versions:** ProVerif 2.05 · ns-3.27 · Python 3.10

