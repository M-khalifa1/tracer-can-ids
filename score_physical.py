#!/usr/bin/env python3
"""
score_physical.py — score ONE real lab capture against the detector and produce
the same metrics (per-attack detection + Wilson CI, benign FPR) as the offline
evaluation, so the paper's physical results are computed, not hand-set.

Minimal-effort protocol (see RUN_PROTOCOL.md):
  * One `candump -L can0 > session.log` for the whole session.
  * Phases run in a fixed order with >=2 s idle between them; the attack phases
    repeat the attack n times each. You pass the phase order on the command line.
  * This script segments the capture into phases by idle gaps (default >1.5 s),
    assigns your phase labels in order, runs the detector, and scores each phase.

Usage:
  python3 score_physical.py session.log "benign,A1,A2,A4,A5,A6,A7,A8,A9" \
      --reps "benign:1,A1:30,A2:30,A4:1,A5:30,A6:30,A7:30,A8:30,A9:30"

Phase->expected-alert map matches evaluate.ATTACKS. A 'benign' phase is scored
only for false positives.
"""
import os, sys, json, math, subprocess, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evaluate as E   # reuse wilson(), run_detector(), ATTACKS, GRACE_US

HERE = os.path.dirname(os.path.abspath(__file__))
GAP_US = 1_500_000

def load_frames(csv):
    fr = []
    with open(csv) as f:
        for ln in f:
            if ln.startswith("ts_us"): continue
            p = ln.split(",")
            if len(p) < 4: continue
            fr.append((int(p[0]), p[1]))
    return fr

def segment(frames, gap=GAP_US):
    """split frame timestamps into phases separated by idle gaps > gap."""
    phases = []
    cur = [frames[0]]
    for i in range(1, len(frames)):
        if frames[i][0] - frames[i-1][0] > gap:
            phases.append((cur[0][0], cur[-1][0])); cur = []
        cur.append(frames[i])
    if cur: phases.append((cur[0][0], cur[-1][0]))
    return phases

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log"); ap.add_argument("order")
    ap.add_argument("--reps", default="")
    ap.add_argument("--gap_s", type=float, default=1.5)
    ap.add_argument("--frames_csv", default=None,
                    help="already-converted frames CSV (skip candump conversion)")
    args = ap.parse_args()

    order = [x.strip() for x in args.order.split(",") if x.strip()]
    reps = {}
    for kv in args.reps.split(","):
        if ":" in kv:
            k, v = kv.split(":"); reps[k.strip()] = int(v)

    frames_csv = args.frames_csv
    if frames_csv is None:
        frames_csv = args.log.rsplit(".", 1)[0] + "_frames.csv"
        subprocess.run([sys.executable,
                        os.path.join(HERE, "candump2csv.py"), args.log, frames_csv],
                       check=True)

    frames = load_frames(frames_csv)
    segs = segment(frames, gap=int(args.gap_s * 1e6))
    if len(segs) != len(order):
        print(f"WARNING: detected {len(segs)} phases but {len(order)} labels given.")
        print("  Detected phase spans (s):",
              [(round(a/1e6,1), round(b/1e6,1)) for a,b in segs])
        print("  Increase/lower --gap_s or check the idle gaps between phases.")
    # run the detector on the whole capture, suppression OFF for scoring
    alerts = E.run_detector(frames_csv, {"seq_window":64,"require_auth_mode":1,"suppress":0})

    results = {"phases": []}
    for label, (t0, t1) in zip(order, segs):
        in_phase = [(ts,ty) for ts,ty in alerts if t0-E.GRACE_US <= ts <= t1+E.GRACE_US]
        if label == "benign":
            nfr = sum(1 for ts,_ in frames if t0 <= ts <= t1)
            fp = len(in_phase)
            results["phases"].append(dict(label=label, span_s=[round(t0/1e6,1),round(t1/1e6,1)],
                frames=nfr, false_positives=fp,
                fpr_percent=round(100*fp/max(nfr,1),3),
                by_rule={ty:sum(1 for _,t in in_phase if t==ty) for ty in set(t for _,t in in_phase)}))
        else:
            accept = E.ATTACKS.get(label,({None},None))[0]
            expect = E.PRIMARY.get(label, None)
            n = reps.get(label, None)
            hits = sum(1 for _,ty in in_phase if ty in accept)
            # if reps known, treat as n events uniformly; detection = hits bounded by n
            if n:
                det = min(hits, n)
                p, lo, hi = E.wilson(det, n)
                results["phases"].append(dict(label=label, expect=expect,
                    span_s=[round(t0/1e6,1),round(t1/1e6,1)], reps=n,
                    expected_alerts=hits, detection_rate=round(100*p,1),
                    ci95=[round(100*lo,1),round(100*hi,1)]))
            else:
                results["phases"].append(dict(label=label, expect=expect,
                    span_s=[round(t0/1e6,1),round(t1/1e6,1)],
                    expected_alerts=hits, detected=hits>0))

    outp = os.path.join(HERE, "results", "physical_metrics.json")
    os.makedirs(os.path.dirname(outp), exist_ok=True)
    json.dump(results, open(outp, "w"), indent=2)
    print(json.dumps(results, indent=2))
    print("\nwrote", outp)

if __name__ == "__main__":
    main()
