# Minimal Lab Run Protocol (one TRACER 2.0, one session)

Goal: produce every physical number the reviewers asked for with **one recording
session** and **one benchmark**, using the released harness to compute the rest.
No Jetson or extra hardware is needed.

## What actually needs the robot vs. what is already done in software

| Reviewer ask | How it is answered | Needs robot? |
|---|---|---|
| Per-rule detection + 95% CI (R2-4) | `evaluate.py` offline + confirm on the one capture | confirm only |
| Benign false-positive rate | benign phase of the capture | yes (short) |
| Threshold sensitivity / ROC knee (R2-7, R1-9) | `sweep.py` offline (deterministic detector) | no |
| Sequence-freshness / replay (R1-11, R2-6) | `test_v3`, `evaluate.py` A5 | confirm only |
| Brute-force (R1-11, R2-6) | `evaluate.py` A8 | confirm only |
| HMAC overhead on real host (R1-12) | `bench_hmac` on the deployment laptop | no robot |
| Everything else (R1-1,5,7,10,13; R2-1,2,3,5,6; editor) | text + references | no |

So the robot is used for **one capture** (benign + attacks) plus optional
confirmation; the heavy statistics come from the deterministic detector.

## 0. Build (deployment laptop)

```bash
cd v3
gcc -Wall -Wextra -O2 -I. ids_runner.c    tracer_ids.c -lm -o ids_runner
gcc -Wall -Wextra -O2 -I. signed_sender.c tracer_ids.c -lm -o signed_sender
gcc -Wall -Wextra -O2 -I. test_v3.c       tracer_ids.c -lm -o test_v3
gcc -O2 -I. bench_hmac.c tracer_ids.c -lm -o bench_hmac
./test_v3            # must print 8 passed, 0 failed
```

## 1. HMAC overhead (no robot) — answers R1-12

Run on the same laptop you use for SocketCAN:
```bash
./bench_hmac 200000 > results/hmac_bench_host.json
# then edit the "platform" field to your CPU/OS (e.g. "Ubuntu 24.04, Intel i7-...")
```

## 2. One recording session — answers benign FPR + detection on real traffic

Bring up CAN and start logging the whole session once:
```bash
sudo modprobe gs_usb
sudo ip link set can0 up type can bitrate 500000
candump -L can0 > results/session.log &      # keep running for the whole session
CANDUMP_PID=$!
```

Run the phases **in this exact order**, leaving **≥ 2 s idle between phases**
(the idle gaps are how the scorer segments the session — do not skip them):

1. **benign** (~30 s): normal operation. Put the robot on blocks. Drive it with
   your legitimate signed sender and/or RC so the bus shows real feedback:
   `sudo ./signed_sender can0`  (forward, spin, stop, standby). Then **idle ≥2 s**.
2. **A1** unauthenticated motion ×30: your existing A1 script, 30 injections,
   then **idle ≥2 s**.
3. **A2** mode hijack ×30 (unsigned 0x421#01), **idle ≥2 s**.
4. **A4** flooding: one bounded session (your 1 kHz / 5 s flood), **idle ≥2 s**.
5. **A5** knowledgeable replay ×30: capture one *validly signed* 0x111+0x112 pair,
   then retransmit that same captured pair 30 times during live signed traffic
   (so its sequence is stale). **idle ≥2 s**.
6. **A6** forged MAC ×30 (0x111 + 0x112 with wrong 4-byte tag), **idle ≥2 s**.
7. **A7** velocity jump ×30 (signed 100→1800 mm/s steps), **idle ≥2 s**.
8. **A8** MAC brute-force ×30 (0x111 + 0x112 with guessed tags), **idle ≥2 s**.
9. **A9** rogue node ×30 (e.g. 0x666), **idle ≥2 s**.

Safety: wheels on blocks, RC e-stop in hand, injected velocity capped at
200 mm/s except the single A7 jump test.

Stop logging:
```bash
kill $CANDUMP_PID
```

> If your existing attack scripts drive A5/A8 differently, that is fine — the
> scorer only needs the phase order and the idle gaps. A5 must replay a pair whose
> signature is valid but whose sequence is old; A8 must send wrong tags repeatedly.

## 3. Score the session (no robot) — produces the physical numbers

```bash
python3 candump2csv.py results/session.log results/session_frames.csv
python3 score_physical.py results/session.log \
    "benign,A1,A2,A4,A5,A6,A7,A8,A9" \
    --reps "A1:30,A2:30,A4:1,A5:30,A6:30,A7:30,A8:30,A9:30" \
    --frames_csv results/session_frames.csv
# -> results/physical_metrics.json  (per-attack detection + 95% CI, benign FPR)
```
If it warns that the number of detected phases ≠ 9, your idle gaps were too short
or too long; adjust `--gap_s` (default 1.5) or re-check the pauses.

## 4. Offline statistics (no robot) — the rest of the numbers

```bash
python3 evaluate.py      # per-attack detection + CI, benign FPR  -> results/metrics.json
python3 sweep.py         # threshold sensitivity / ROC knee       -> results/sweeps.json
python3 make_figures.py  # all figures from the data above        -> results/charts/
```

## 5. Put numbers in the paper

- Detection table + CIs: from `results/physical_metrics.json` (real) and
  `results/metrics.json` (offline validation).
- Fig. sensitivity: `results/charts/fig_sensitivity.*`
- Fig. detection: `results/charts/fig_detection_ci.*`
- Fig. HMAC: `results/charts/fig_hmac_overhead.*` + `hmac_bench_host.json`
- Bus load: a 0x111+0x112 pair ≈ 2×130 bits at 500 kbps ≈ 0.52 ms; report the
  measured pre/post bus-load % from `candump` if you want the empirical figure
  (`canbusload can0@500000` during the signed-sender phase).

That is the whole physical campaign: one capture + one benchmark. Everything else
is deterministic and reproducible from the released code.
