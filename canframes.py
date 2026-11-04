"""
canframes.py — build labelled CAN traces for *offline detector evaluation*.

This module produces frame records (ts_us, id, dlc, data_hex) plus ground-truth
event labels, so the IDS detector can be scored reproducibly. It does NOT talk
to any hardware; it generates test vectors for the software detector only.

The HMAC signing here is byte-for-byte identical to tracer_ids.c (sign_make):
  msg(12) = id_hi,id_lo, payload[0:8], seq_hi,seq_lo
  mac4    = HMAC_SHA256(key, msg)[:4]
  0x112   = mac4, seq_hi, seq_lo, ts_hi, ts_lo
so a trace generated here verifies against the C verifier.
"""
import hmac, hashlib, struct

KEY = bytes([0xC4,0x7A,0x3E,0x91,0x5F,0xB2,0xD0,0x88,
             0x1C,0x4E,0xA7,0x6D,0x39,0xF8,0x02,0x5B])

MOTION, AUTH, LIGHT = 0x111, 0x112, 0x121
SYS, MOT_FB, LIGHT_FB, RC = 0x211, 0x221, 0x231, 0x241
HS_L, HS_R, LS_L, LS_R, ODO = 0x251, 0x252, 0x261, 0x262, 0x311
MODE, ERRCLR = 0x421, 0x441

def _mac4(can_id, payload8, seq):
    msg = bytes([(can_id >> 8) & 0xFF, can_id & 0xFF]) + bytes(payload8[:8]) \
          + bytes([(seq >> 8) & 0xFF, seq & 0xFF])
    return hmac.new(KEY, msg, hashlib.sha256).digest()[:4]

def auth_payload(can_id, payload8, seq, ts_ms=0):
    m = _mac4(can_id, payload8, seq)
    return bytes([m[0], m[1], m[2], m[3],
                  (seq >> 8) & 0xFF, seq & 0xFF,
                  (ts_ms >> 8) & 0xFF, ts_ms & 0xFF])

def motion_payload(lin_mm_s, ang_mrad_s=0):
    lin = int(lin_mm_s) & 0xFFFF
    ang = int(ang_mrad_s) & 0xFFFF
    return bytes([(lin >> 8) & 0xFF, lin & 0xFF,
                  (ang >> 8) & 0xFF, ang & 0xFF, 0, 0, 0, 0])

def hx(b):
    return ''.join('%02X' % x for x in b)

class Trace:
    """Accumulates (ts_us, id, dlc, payload) and ground-truth events.

    Legitimate authenticated commands are added with add_signed(); their
    sequence numbers are assigned in *time order* at finalize(), exactly as a
    real sender with a single monotonic seq counter would produce them. Literal
    frames (benign feedback, attacks, forged/replayed companions) are added
    with add() and are never resigned.
    """
    def __init__(self):
        self.frames = []    # literal (ts_us, id, dlc, bytes)
        self.signed = []    # legit (ts_us, id, bytes payload) -> seq at finalize
        self.events = []    # dict(type, expect, t0, t1)

    def add(self, ts_us, can_id, payload, dlc=None):
        p = bytes(payload)
        self.frames.append((int(ts_us), can_id, dlc if dlc is not None else len(p), p))

    def add_signed(self, ts_us, can_id, payload, dlc=None):
        self.signed.append((int(ts_us), can_id, bytes(payload),
                            dlc if dlc is not None else len(payload)))

    # ---- benign building blocks -------------------------------------
    def benign_feedback(self, t0_us, dur_us):
        """Periodic chassis feedback mirroring the observed cadence."""
        periodic = [(SYS,20000),(MOT_FB,20000),(RC,21000),(LIGHT_FB,100000),
                    (HS_L,20000),(HS_R,20000),(LS_L,100000),(LS_R,100000),
                    (ODO,50000)]
        for cid, per in periodic:
            t = t0_us
            k = 0
            while t < t0_us + dur_us:
                # RC state carries 0xAA sticks-up pattern + counter in byte7
                if cid == RC:
                    pl = bytes([0xAA,0,0,0,0,0,0,k & 0xFF])
                else:
                    pl = bytes([0,0,0,0,0,0,0,k & 0xFF])
                self.add(t, cid, pl)
                t += per; k += 1

    def benign_signed_motion(self, t0_us, dur_us, lin=200, period=20000):
        """Legitimate signed 0x111+0x112 pairs at ~50 Hz (monotonic seq)."""
        t = t0_us
        while t < t0_us + dur_us:
            self.add_signed(t, MOTION, motion_payload(lin))
            t += period

    def benign_signed_mode(self, t_us, mode=0x01):
        self.add_signed(t_us, MODE, bytes([mode,0,0,0,0,0,0,0]), dlc=1)

    def benign_signed_ramp(self, t0_us, vmax=800, step=40, period=20000, hold_us=400_000):
        """Legitimate smooth accel/cruise/decel profile: velocity changes by
        <= `step` mm/s per 20 ms control cycle, as a real operator or planner
        would command. Used so that an over-aggressive VEL_JUMP/BURST threshold
        produces *benign* false positives, giving the sensitivity sweep a real
        operating knee. Returns the end time."""
        t = t0_us; v = 0
        # ramp up
        while v < vmax:
            v = min(vmax, v + step); self.add_signed(t, MOTION, motion_payload(v)); t += period
        # cruise
        tend = t + hold_us
        while t < tend:
            self.add_signed(t, MOTION, motion_payload(vmax)); t += period
        # ramp down to 0
        while v > 0:
            v = max(0, v - step); self.add_signed(t, MOTION, motion_payload(v)); t += period
        return t

    # ---- attack injectors (produce labelled events) ------------------
    def atk_unsigned_motion(self, t_us, lin=200):
        self.add(t_us, MOTION, motion_payload(lin))   # no companion
        self.events.append(dict(type='A1', expect='NO_AUTH', t0=t_us, t1=t_us+10000))

    def atk_mode_hijack(self, t_us, mode=0x01):
        self.add(t_us, MODE, bytes([mode,0,0,0,0,0,0,0]), dlc=1)  # no companion
        self.events.append(dict(type='A2', expect='NO_AUTH', t0=t_us, t1=t_us+10000))

    def atk_forged_mac(self, t_us, lin=200):
        pl = motion_payload(lin)
        self.add(t_us, MOTION, pl)
        self.add(t_us+400, AUTH, bytes([0xDE,0xAD,0xBE,0xEF,0,1,0,0]))
        self.events.append(dict(type='A6', expect='BAD_MAC', t0=t_us, t1=t_us+10000))

    def atk_vel_jump(self, t_us, lo=100, hi=1800):
        self.add_signed(t_us, MOTION, motion_payload(lo))
        self.add_signed(t_us+20000, MOTION, motion_payload(hi))
        self.events.append(dict(type='A7', expect='VEL_JUMP', t0=t_us+20000, t1=t_us+30000))

    def atk_flood(self, t_us, dur_us=5_000_000, hz=1000):
        per = int(1e6/hz); t=t_us; k=0
        while t < t_us+dur_us:
            self.add(t, MOTION, motion_payload(0)); t+=per; k+=1
        self.events.append(dict(type='A4', expect='FLOOD', t0=t_us, t1=t_us+dur_us))

    def atk_replay_fresh(self, t_us, captured_seq=3):
        """Knowledgeable replay: the attacker captured a valid signed pair
        (with an old, low sequence number) earlier in the session and now
        retransmits it verbatim. The MAC is valid, but the sequence is stale,
        so seq-freshness must surface it as STALE_SEQ. The lead-in legitimate
        traffic that advanced last_seq past captured_seq is provided by the
        surrounding benign_signed_motion in the scenario."""
        pl = motion_payload(200)
        ap = auth_payload(MOTION, pl, captured_seq)   # valid MAC, old seq
        self.add(t_us, MOTION, pl)
        self.add(t_us+400, AUTH, ap)
        self.events.append(dict(type='A5', expect='STALE_SEQ', t0=t_us, t1=t_us+10000))

    def atk_brute_force(self, t_us, n=8):
        """Knowledgeable attacker guesses the 4-byte MAC repeatedly."""
        t=t_us
        for i in range(n):
            pl=motion_payload(200)
            self.add(t, MOTION, pl)
            guess=bytes([(i*37)&0xFF,(i*91)&0xFF,0x12,0x34,0,i&0xFF,0,0])
            self.add(t+400, AUTH, guess)
            t+=20000
        self.events.append(dict(type='A8', expect='BRUTE_FORCE', t0=t_us, t1=t))

    def atk_unknown_node(self, t_us, rogue=0x666):
        self.add(t_us, rogue, bytes([0xDE,0xAD,0xBE,0xEF,0,0,0,0]))
        self.events.append(dict(type='A9', expect='UNKNOWN_ID', t0=t_us, t1=t_us+10000))

    # ---- finalise: assign monotonic seq to legit signed commands -----
    def _materialise(self):
        """Merge literal frames with legit signed pairs. Sequence numbers are
        assigned to add_signed() commands in time order (one shared monotonic
        counter), then each command frame and its 0x112 companion are emitted."""
        out = list(self.frames)
        seq = 1
        for ts, cid, pl, dlc in sorted(self.signed, key=lambda s: s[0]):
            out.append((ts, cid, dlc, bytes(pl)))
            out.append((ts + 400, AUTH, 8, auth_payload(cid, pl, seq)))
            seq += 1
        out.sort(key=lambda f: f[0])
        return out

    def write_csv(self, path):
        rows = self._materialise()
        with open(path, 'w') as f:
            f.write("ts_us,can_id,dlc,data_hex\n")
            for ts, cid, dlc, pl in rows:
                f.write("%d,0x%03X,%d,%s\n" % (ts, cid, dlc, hx(pl)))
        return rows

    def benign_frame_count(self):
        """frames outside any attack event window (for FPR denominator)."""
        n = 0
        for ts, _, _, _ in self._materialise():
            if not any(e['t0'] <= ts <= e['t1'] for e in self.events):
                n += 1
        return n
