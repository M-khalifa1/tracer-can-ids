# TRACER 2.0 CAN-IDS — revision kit (v3)

Everything needed to answer the reviewers: a hardened detector + authenticated
signer, a reproducible evaluation harness that computes all numbers from data,
the minimal lab protocol, the response letter, and the verified reference set.

## Contents

```
tracer_ids.h / tracer_ids.c   detector engine v3 (rules R1-R9, auth, freshness)
sha256.h                      standalone HMAC-SHA-256 (unchanged, correct)
signed_sender.c               legitimate authenticated sender (0x111/0x421/0x441)
ids_daemon.c                  live passive monitor (sudo ./ids_daemon can0)
ids_runner.c                  deterministic offline replay of a trace (+ config)
bench_hmac.c                  HMAC timing distribution on the deployment host
test_v3.c                     8 regression tests for the v3 fixes/rules

canframes.py                  labelled trace generator (test vectors) + signer
evaluate.py                   per-attack detection + 95% Wilson CI, benign FPR
sweep.py                      threshold sensitivity / ROC-knee analysis
make_figures.py               paper figures, 100% from measured data
candump2csv.py                real candump -L log  ->  frames CSV
score_physical.py             score one real lab session (auto phase segmentation)

RESPONSE_TO_REVIEWERS.md      point-by-point English response (R1 1-13, R2 1-7, editor)
RUN_PROTOCOL.md               minimal one-session lab protocol
refs.bib / refs_table.md / notes.md   39 verified references + comparison table + positioning
results/                      metrics.json, sweeps.json, charts/, hmac_bench_*.json
```

## Quick start (no robot)

```bash
make                 # builds all C tools, runs test_v3 (must be 8/8)
python3 evaluate.py        # detection + CIs + benign FPR   -> results/metrics.json
python3 sweep.py           # sensitivity / ROC knee          -> results/sweeps.json
python3 make_figures.py    # figures from the data           -> results/charts/
./bench_hmac 200000 > results/hmac_bench_host.json
```

## With the robot

See `RUN_PROTOCOL.md` — one `candump` capture + `score_physical.py`.

## What changed from the submitted version (v1 -> v3)

Bug fixes
- **Replay cascade:** R4 used to leave `last_ctr` frozen after firing, so one
  replayed frame produced hundreds of false alerts. Replaced by proper
  sequence-freshness (`STALE_SEQ`); the counter state always advances.
- **Silent auth overwrite:** a second command arriving before its companion used
  to overwrite the pending state silently; it now raises `NO_AUTH` for the first.
- **Log flooding:** identical alerts in a tight burst are collapsed in the live
  log (with a count), but never across distinct events; scoring runs with
  suppression off.
- **Fig. 7 reference line** drew the CAN period at 20 µs instead of 20 ms.
- **Fabricated numbers removed:** `detect_rates`, `fp_rates`, the ROC arrays and
  the "simulated µs timings" are gone; every figure is regenerated from data.

Protocol corrections (per AgileX `ugv_sdk` protocol_v2 + manual)
- 0x111 `byte[7]` is Reserved (no stock counter); freshness is carried only by
  our companion frame.
- 0x241 is RC-transmitter state (~50 Hz), not battery detail.

New capability (reviewer-driven)
- Sequence freshness enforced (R2-6, R1-11).
- Authentication generalised to 0x111/0x421/0x441 (R1-8).
- R2 authentication-aware mode handling (R1-2).
- New rule R9 BRUTE_FORCE (R1-11, R2-6).
- All thresholds runtime-configurable for sensitivity sweeps (R2-7).

## Reproducibility note

`ids_runner` is deterministic: given a frame CSV and a config it always produces
the same alerts (no wall clock). The Python signer in `canframes.py` is
byte-identical to `sign_make` in `tracer_ids.c`, so generated traces verify
against the C verifier. The same `ids_runner` scores synthetic traces and real
`candump` captures.
