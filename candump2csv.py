#!/usr/bin/env python3
"""
candump2csv.py — convert a real `candump -L` log from the lab into the frame
CSV format the evaluation harness consumes, so the SAME detector and SAME
metrics run on physical captures.

`candump -L can0` lines look like:
    (1739531234.123456) can0 111#00C8000000000000
    (1739531234.124010) can0 112#A1B2C3D40001F0E2

Usage:
    candump -L can0 > session.log            # in the lab, during the run
    python3 candump2csv.py session.log frames.csv
The first frame's timestamp becomes t=0 (monotonic microseconds).
"""
import sys, re

LINE = re.compile(r'\(([0-9]+\.[0-9]+)\)\s+\S+\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]*)')

def main(inp, outp):
    rows = []
    t0 = None
    with open(inp) as f:
        for ln in f:
            m = LINE.search(ln)
            if not m:
                continue
            ts = float(m.group(1))
            if t0 is None:
                t0 = ts
            can_id = int(m.group(2), 16)
            data = m.group(3)
            dlc = len(data) // 2
            rows.append((int((ts - t0) * 1e6), can_id, dlc, data.upper()))
    rows.sort(key=lambda r: r[0])
    with open(outp, 'w') as f:
        f.write("ts_us,can_id,dlc,data_hex\n")
        for ts, cid, dlc, data in rows:
            f.write("%d,0x%03X,%d,%s\n" % (ts, cid, dlc, data))
    print("wrote %d frames -> %s" % (len(rows), outp))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: candump2csv.py session.log frames.csv"); sys.exit(2)
    main(sys.argv[1], sys.argv[2])
