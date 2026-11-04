#!/usr/bin/env python3
"""
sweep.py — threshold sensitivity analysis (R2-7) and an honest operating
characteristic for the one tunable behavioural rule (R1-9).

Exact-match rules (NO_AUTH, BAD_MAC, UNKNOWN_ID, STALE_SEQ, BRUTE_FORCE) are
deterministic: given the protocol they are 100% detection / 0% FP by
construction, so they have no ROC. The rate rule (FLOOD) and the plausibility
rules (VEL_JUMP, BURST) DO depend on a numeric threshold, so we sweep those and
report detection and false-positive rate as a function of the threshold. The
velocity threshold additionally yields a genuine TPR-vs-FPR operating curve.

All numbers come from running the C detector; nothing is hand-set.
"""
import os, json, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evaluate as E

OUT = E.OUT

def sweep(kind, knob, values, expect):
    """Return list of (value, detection_%, benign_fpr_%)."""
    atk = E.attack_session(kind, n=30)
    acsv = os.path.join(OUT, f"sweep_atk_{kind}.csv"); atk.write_csv(acsv)
    ben = E.benign_session(30_000_000)
    bcsv = os.path.join(OUT, f"sweep_ben.csv"); ben.write_csv(bcsv)
    rows = []
    for v in values:
        cfg = {'seq_window': 64, 'require_auth_mode': 1, 'suppress': 0, knob: v}
        al = E.run_detector(acsv, cfg)
        det, tot = E.score_detection(atk, al, expect)
        bal = E.run_detector(bcsv, cfg)
        fp, bf, _ = E.benign_fpr(ben, bal)
        rows.append((v, round(100*det/tot,1), round(100*fp/max(bf,1),3)))
    return rows

def main():
    sweeps = {}
    # FLOOD rate threshold (Hz): too low -> benign feedback flagged; A4 at 1 kHz
    sweeps['flood_hz'] = dict(
        knob='flood_hz', kind='A4', expect='FLOOD',
        rows=sweep('A4','flood_hz',[40,60,80,100,150,200,300,400],'FLOOD'))
    # VEL_JUMP threshold (mm/s): the genuine TPR/FPR operating curve. Swept
    # across the full range so both knees show: benign ramps (<=40 mm/s/step)
    # raise FPR below ~40, and the attack jump (100->1800, delta 1700) stops
    # being detected once the threshold exceeds 1700.
    sweeps['vel_jump'] = dict(
        knob='vel_jump', kind='A7', expect='VEL_JUMP',
        rows=sweep('A7','vel_jump',[20,30,40,60,100,200,400,600,1000,1400,1700,1800,2000],'VEL_JUMP'))
    # BURST idle threshold (ms)
    sweeps['burst_idle_ms'] = dict(
        knob='burst_idle_ms', kind='A1', expect='NO_AUTH',
        rows=sweep('A1','burst_idle_ms',[100,200,300,400,500,700,1000],'NO_AUTH'))
    # AUTH window (us): NO_AUTH timeliness vs benign false NO_AUTH
    sweeps['auth_win_us'] = dict(
        knob='auth_win_us', kind='A1', expect='NO_AUTH',
        rows=sweep('A1','auth_win_us',[2000,4000,6000,8000,12000,16000,20000],'NO_AUTH'))

    with open(os.path.join(OUT,'sweeps.json'),'w') as f:
        json.dump(sweeps, f, indent=2)

    print("\n=== Threshold sensitivity (detection% / benign FPR%) ===")
    for name, s in sweeps.items():
        print(f"\n  {name}  (attack {s['kind']} -> {s['expect']})")
        print(f"    {'value':>8} {'det%':>6} {'fpr%':>7}")
        for v,d,fp in s['rows']:
            print(f"    {v:>8} {d:>6} {fp:>7}")
    print(f"\n  wrote {os.path.join(OUT,'sweeps.json')}")

if __name__ == "__main__":
    main()
