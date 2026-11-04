/*
 * tracer_ids.c  –  TRACER 2.0 IDS engine (v3)
 *
 * See tracer_ids.h for the list of v3 changes and reviewer mappings.
 */
#include "tracer_ids.h"
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>

const char * const ALERT_NAMES[ALERT_TYPE_N] = {
    "NONE","FLOOD","MODE_CHANGE","VEL_JUMP","REPLAY",
    "UNKNOWN_ID","NO_AUTH","BAD_MAC","BURST","BRUTE_FORCE","STALE_SEQ"
};
const char * const SEV_NAMES[3] = { "INFO","WARNING","CRITICAL" };

static const char *SEV_COL[3]  = { "\033[36m","\033[33m","\033[31m" };
#define RST "\033[0m"

/* ── Monotonic timestamp (µs) ────────────────────────────────────── */
static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)(ts.tv_nsec / 1000);
}

void ids_default_config(IDSConfig *c) {
    c->flood_hz        = DEF_FLOOD_HZ_THRESH;
    c->flood_win_us    = DEF_FLOOD_WIN_US;
    c->vel_jump        = DEF_VEL_JUMP_THRESH;
    c->auth_win_us     = DEF_AUTH_WIN_US;
    c->burst_idle_ms   = DEF_BURST_IDLE_MS;
    c->burst_vel_min   = DEF_BURST_VEL_MIN;
    c->seq_window      = DEF_SEQ_WINDOW;
    c->brute_win_us    = DEF_BRUTE_WIN_US;
    c->brute_count     = DEF_BRUTE_COUNT;
    c->require_auth_for_mode = true;
    c->log_suppress    = true;
}

/* ── Whitelist check ─────────────────────────────────────────────── */
static bool whitelisted(uint32_t id) {
    for (size_t i = 0; i < IDS_WHITELIST_N; i++)
        if (IDS_WHITELIST[i] == id) return true;
    return false;
}

/* ── Build alert struct ──────────────────────────────────────────── */
static Alert mk(uint64_t ts, AlertType t, Severity s, uint32_t id,
                const uint8_t *d, uint8_t dlc, const char *fmt, ...) {
    Alert a; memset(&a,0,sizeof(a));
    a.ts_us=ts; a.type=t; a.sev=s; a.can_id=id; a.dlc=dlc;
    if (d && dlc) memcpy(a.raw, d, dlc>8?8:dlc);
    va_list ap; va_start(ap,fmt); vsnprintf(a.detail,sizeof(a.detail),fmt,ap); va_end(ap);
    return a;
}

/* ── Emit: print + log CSV, with repeated-alert suppression ────────
 * v3 bugfix: an unknown-ID flood or a stuck condition used to emit one
 * row per frame and drown the CSV. We collapse an identical (type,id)
 * run and annotate the first alert of the next run with the count. */
static void flush_suppressed(IDS *ids) {
    if (ids->suppressed && ids->csv) {
        fprintf(ids->csv, "# ... %u further %s alerts on 0x%03X suppressed\n",
                ids->suppressed, ALERT_NAMES[ids->last_alert_type],
                ids->last_alert_id);
        fflush(ids->csv);
    }
    ids->suppressed = 0;
}

/* only collapse identical alerts closer together than this (µs) */
#define SUPPRESS_GAP_US 250000ULL

static void emit(IDS *ids, Alert *a) {
    ids->total_alerts++;
    ids->by_type[a->type]++;

    /* Suppress consecutive identical (type,id) alerts ONLY when they are
     * bursting close together (e.g. an unknown-ID flood). Distinct events
     * separated by more than SUPPRESS_GAP_US are all logged. The full count
     * is always kept in by_type/total for the statistics. */
    bool same = ids->cfg.log_suppress
                && a->type == ids->last_alert_type && a->can_id == ids->last_alert_id
                && a->ts_us - ids->last_alert_ts < SUPPRESS_GAP_US;
    if (same) { ids->suppressed++; ids->last_alert_ts = a->ts_us; return; }
    flush_suppressed(ids);
    ids->last_alert_type = a->type;
    ids->last_alert_id   = a->can_id;
    ids->last_alert_ts   = a->ts_us;

    printf("%s[%-11s][%-8s] ID=0x%03X  %s%s\n",
           SEV_COL[a->sev], ALERT_NAMES[a->type],
           SEV_NAMES[a->sev], a->can_id, a->detail, RST);
    fflush(stdout);

    if (ids->csv) {
        char hex[24]="";
        for(int i=0;i<a->dlc&&i<8;i++) sprintf(hex+i*2,"%02X",a->raw[i]);
        fprintf(ids->csv, "%llu,%s,%s,0x%03X,\"%s\",%s\n",
            (unsigned long long)a->ts_us,
            ALERT_NAMES[a->type], SEV_NAMES[a->sev],
            a->can_id, a->detail, hex);
        fflush(ids->csv);
    }
}

/* ── Rate tracker ────────────────────────────────────────────────── */
static RateTrack *get_track(IDS *ids, uint32_t id) {
    for (int i=0;i<ids->n_tracks;i++)
        if (ids->tracks[i].id==id) return &ids->tracks[i];
    if (ids->n_tracks>=MAX_TRACK) return NULL;
    RateTrack *t=&ids->tracks[ids->n_tracks++];
    memset(t,0,sizeof(*t)); t->id=id; return t;
}

static bool rate_check(IDS *ids, uint32_t id, uint64_t ts, float *out_hz) {
    RateTrack *t=get_track(ids,id); if(!t) return false;
    if (t->win_start==0) t->win_start=ts;
    t->count++;
    uint64_t el=ts-t->win_start;
    if (el >= ids->cfg.flood_win_us) {
        t->rate_hz=(float)t->count/((float)el/1e6f);
        if (out_hz) *out_hz=t->rate_hz;
        t->count=0; t->win_start=ts;
        t->flooding=(t->rate_hz>ids->cfg.flood_hz);
        return t->flooding;
    }
    return false;
}

/* ══════════════════════════════════════════════════════════════════
 *  SIGNING
 * ══════════════════════════════════════════════════════════════════ */
static void build_msg(uint32_t id, const uint8_t *d, uint16_t seq,
                      uint8_t msg[12]) {
    msg[0]=(id>>8)&0xFF; msg[1]=id&0xFF;
    memcpy(&msg[2],d,8);
    msg[10]=(seq>>8)&0xFF; msg[11]=seq&0xFF;
}

void sign_make(const uint8_t *key, uint16_t seq,
               uint32_t can_id, const uint8_t *payload,
               AuthFrame *out) {
    uint8_t msg[12];
    build_msg(can_id,payload,seq,msg);
    out->seq=seq;
    out->ts_low=(uint16_t)(now_us()/1000&0xFFFF);
    hmac_sha256_4(key,HMAC_KEY_LEN,msg,12,out->mac4);
}

bool sign_check(const uint8_t *key,
                const uint8_t *cmd_payload,
                uint32_t can_id,
                const uint8_t *auth_payload) {
    uint16_t seq=(uint16_t)((auth_payload[4]<<8)|auth_payload[5]);
    uint8_t msg[12]; build_msg(can_id,cmd_payload,seq,msg);
    uint8_t exp[4];  hmac_sha256_4(key,HMAC_KEY_LEN,msg,12,exp);
    uint8_t diff=0;
    for(int i=0;i<4;i++) diff|=(exp[i]^auth_payload[i]);
    return diff==0;
}

/* ── Sequence freshness check (v3) ─────────────────────────────────
 * Accept seq in (last_seq, last_seq + window] with 16-bit wrap. This is
 * the SecOC-style freshness value that actually prevents replay of a
 * validly-signed companion. Returns true if fresh. */
static bool seq_is_fresh(IDS *ids, uint16_t seq) {
    if (ids->cfg.seq_window == 0) return true;        /* freshness disabled */
    if (!ids->seq_valid) { return true; }             /* first authenticated frame */
    uint16_t delta = (uint16_t)(seq - (uint16_t)ids->last_seq);
    return (delta >= 1 && delta <= ids->cfg.seq_window);
}

/* ══════════════════════════════════════════════════════════════════
 *  INIT
 * ══════════════════════════════════════════════════════════════════ */
void ids_init_cfg(IDS *ids, const uint8_t *key, const IDSConfig *cfg) {
    memset(ids,0,sizeof(*ids));
    if (cfg) ids->cfg = *cfg; else ids_default_config(&ids->cfg);
    ids->last_ctr=0xFF;
    ids->last_alert_type = ALERT_NONE;
    ids->last_alert_id   = 0xFFFFFFFFu;
    memcpy(ids->hmac_key, key?key:DEFAULT_HMAC_KEY, HMAC_KEY_LEN);
}

void ids_init(IDS *ids, const uint8_t *key) {
    ids_init_cfg(ids, key, NULL);
}

void ids_set_csv(IDS *ids, FILE *f) {
    ids->csv=f;
    if(f) fprintf(f,"timestamp_us,alert_type,severity,can_id,detail,raw\n");
}

/* Fire NO_AUTH for a pending command that was never authenticated, then
 * clear it. Used both by ids_tick (timeout) and when a new command
 * arrives while one is still pending (v3 bugfix: no silent overwrite). */
static void expire_pending(IDS *ids, uint64_t ts, bool timeout) {
    if (!ids->pauth.pending) return;
    Alert a = mk(ts, ALERT_NO_AUTH, SEV_CRIT, ids->pauth.cmd_id,
                 ids->pauth.data, ids->pauth.dlc,
                 "0x%03X command UNAUTHENTICATED — no valid 0x112 %s",
                 ids->pauth.cmd_id,
                 timeout ? "within auth window" : "before next command");
    ids->pauth.pending=false;
    emit(ids,&a);
}

/* ══════════════════════════════════════════════════════════════════
 *  MAIN FEED FUNCTION
 * ══════════════════════════════════════════════════════════════════ */
Alert ids_feed(IDS *ids, uint32_t can_id, uint8_t dlc,
               const uint8_t *data, uint64_t ts_us) {

    ids->total_frames++;
    Alert a; memset(&a,0,sizeof(a));

    /* ── R5: Unknown ID ─────────────────────────────────────────── */
    if (!whitelisted(can_id)) {
        a = mk(ts_us,ALERT_UNKNOWN,SEV_WARN,can_id,data,dlc,
               "CAN ID 0x%03X not in TRACER 2.0 whitelist — rogue node?",can_id);
        goto out;
    }

    /* ── R1: Flood ──────────────────────────────────────────────── */
    {
        float hz=0;
        if (rate_check(ids,can_id,ts_us,&hz)) {
            a = mk(ts_us,ALERT_FLOOD,SEV_CRIT,can_id,data,dlc,
                   "FLOOD on 0x%03X: %.0f Hz > %.0f Hz threshold — DoS",
                   can_id, hz, ids->cfg.flood_hz);
            goto out;
        }
    }

    /* A new authenticated command arrived while a previous one is still
     * pending its companion: the previous one is unauthenticated. */
    if (ids_is_authenticated_cmd(can_id) && ids->pauth.pending)
        expire_pending(ids, ts_us, false);

    /* ── R2: Mode switch via 0x421 (authentication-aware) ──────────
     * We record the mode change and mark auth pending. Whether it is an
     * ALERT depends on whether a valid companion follows (checked when
     * 0x112 arrives / times out). In require_auth_for_mode mode we do not
     * raise MODE_CHANGE here for a change that MIGHT be authenticated;
     * instead an unauthenticated mode change surfaces as NO_AUTH on
     * timeout. If require_auth_for_mode is false we keep legacy behaviour
     * (every transition is MODE_CHANGE). */
    if (can_id==ID_MODE_SET && dlc>=1) {
        uint8_t nm=data[0];
        bool changed = (nm!=ids->cur_mode);
        ids->cur_mode=nm;
        /* mark pending auth for the mode command */
        ids->pauth.pending=true; ids->pauth.cmd_id=ID_MODE_SET;
        ids->pauth.ts_us=ts_us; ids->pauth.dlc=dlc<8?dlc:8;
        memset(ids->pauth.data,0,8); memcpy(ids->pauth.data,data,ids->pauth.dlc);
        if (changed && !ids->cfg.require_auth_for_mode) {
            const char *mname[]={"STANDBY/RC","CAN_CMD","RC_CTRL","?"};
            uint8_t mi=nm<3?nm:3;
            Severity s=(nm==0x01)?SEV_CRIT:SEV_WARN;
            a = mk(ts_us,ALERT_MODE_CHG,s,can_id,data,dlc,
                   "Mode transition ->0x%02X (%s) via 0x421",
                   nm, mname[mi]);
            goto out;
        }
        /* authenticated-mode deployment: defer to companion verification */
        return a;
    }

    /* ── R3 + R8: Velocity anomalies (0x111) ───────────────────────
     * v3 bugfix: last_vel / last_ctr / last_motion_ts are updated on a
     * single clearly-marked path so an early return never freezes state. */
    if (can_id==ID_MOTION_CMD && dlc>=4) {
        int16_t vel=(int16_t)((data[0]<<8)|data[1]);
        int dv = vel>ids->last_vel ? vel-ids->last_vel : ids->last_vel-vel;

        AlertType vt = ALERT_NONE; Severity vs = SEV_INFO; char vmsg[160]="";

        if (ids->last_motion_ts>0 && dv>ids->cfg.vel_jump) {
            vt=ALERT_VEL_JUMP; vs=SEV_CRIT;
            snprintf(vmsg,sizeof(vmsg),
                     "Velocity jump %d->%d mm/s (delta=%d > %d) — injection",
                     ids->last_vel,vel,dv,ids->cfg.vel_jump);
        } else if (ids->last_motion_ts>0 &&
                   (ts_us-ids->last_motion_ts) > ids->cfg.burst_idle_ms*1000ULL &&
                   (vel>ids->cfg.burst_vel_min || vel<-ids->cfg.burst_vel_min)) {
            vt=ALERT_BURST; vs=SEV_WARN;
            snprintf(vmsg,sizeof(vmsg),
                     "Burst %d mm/s after %llu ms idle — possible replay/inject",
                     vel,(unsigned long long)((ts_us-ids->last_motion_ts)/1000));
        }

        /* update motion state BEFORE any early return (cascade fix) */
        ids->last_vel=vel;
        ids->last_motion_ts=ts_us;

        /* mark auth pending for the motion command */
        ids->pauth.pending=true; ids->pauth.cmd_id=ID_MOTION_CMD;
        ids->pauth.ts_us=ts_us; ids->pauth.dlc=dlc<8?dlc:8;
        memset(ids->pauth.data,0,8); memcpy(ids->pauth.data,data,ids->pauth.dlc);

        if (vt!=ALERT_NONE) {
            a = mk(ts_us,vt,vs,can_id,data,dlc,"%s",vmsg);
            goto out;
        }
        return a;
    }

    /* ── 0x441 error-clear: authenticated command, mark pending ──── */
    if (can_id==ID_ERR_CLEAR && dlc>=1) {
        ids->pauth.pending=true; ids->pauth.cmd_id=ID_ERR_CLEAR;
        ids->pauth.ts_us=ts_us; ids->pauth.dlc=dlc<8?dlc:8;
        memset(ids->pauth.data,0,8); memcpy(ids->pauth.data,data,ids->pauth.dlc);
        return a;
    }

    /* ── R7 / R4 / R9: Verify auth companion (0x112) ─────────────── */
    if (can_id==ID_AUTH_MAC && dlc>=8) {
        if (!ids->pauth.pending) {
            a = mk(ts_us,ALERT_NO_AUTH,SEV_WARN,can_id,data,dlc,
                   "0x112 companion without a preceding command frame");
            goto out;
        }
        uint32_t cid = ids->pauth.cmd_id;
        bool ok=sign_check(ids->hmac_key, ids->pauth.data, cid, data);
        if (!ok) {
            /* R9: count consecutive BAD_MACs in a window */
            if (ids->brute_win_start==0 ||
                ts_us-ids->brute_win_start > ids->cfg.brute_win_us) {
                ids->brute_win_start=ts_us; ids->brute_count=0;
            }
            ids->brute_count++;
            ids->pauth.pending=false;
            uint16_t seq=(uint16_t)((data[4]<<8)|data[5]);
            uint8_t msg[12]; build_msg(cid,ids->pauth.data,seq,msg);
            uint8_t exp[4];  hmac_sha256_4(ids->hmac_key,HMAC_KEY_LEN,msg,12,exp);
            if (ids->brute_count >= ids->cfg.brute_count) {
                a = mk(ts_us,ALERT_BRUTE_FORCE,SEV_CRIT,can_id,data,dlc,
                       "MAC brute-force: %u failed companions within %llu ms",
                       ids->brute_count,
                       (unsigned long long)(ids->cfg.brute_win_us/1000));
            } else {
                a = mk(ts_us,ALERT_BAD_MAC,SEV_CRIT,can_id,data,dlc,
                       "MAC FAIL on 0x%03X: got %02X%02X%02X%02X exp %02X%02X%02X%02X — FORGED",
                       cid, data[0],data[1],data[2],data[3],
                       exp[0],exp[1],exp[2],exp[3]);
            }
            goto out;
        }
        /* MAC valid — now enforce freshness (R4 replay, SecOC-style) */
        uint16_t seq=(uint16_t)((data[4]<<8)|data[5]);
        if (!seq_is_fresh(ids, seq)) {
            ids->pauth.pending=false;
            a = mk(ts_us,ALERT_STALE_SEQ,SEV_CRIT,can_id,data,dlc,
                   "REPLAY: valid MAC but stale seq %u (last=%u) — captured frame replayed",
                   seq, (unsigned)ids->last_seq);
            goto out;
        }
        ids->last_seq=seq; ids->seq_valid=true;
        ids->brute_count=0;
        ids->pauth.pending=false;   /* authenticated & fresh: no alert */
        return a;
    }

    return a;

out:
    if (a.type!=ALERT_NONE) emit(ids,&a);
    return a;
}

/* ── R6: Flush pending auth on timeout (call every ~10ms) ─────────── */
void ids_tick(IDS *ids, uint64_t ts_now) {
    if (!ids->pauth.pending) return;
    if (ts_now - ids->pauth.ts_us < ids->cfg.auth_win_us) return;
    expire_pending(ids, ts_now, true);
}

/* ── Summary ─────────────────────────────────────────────────────── */
void ids_summary(const IDS *ids) {
    printf("\n\033[1m==== IDS SESSION SUMMARY ====\033[0m\n");
    printf("  Frames processed : %u\n", ids->total_frames);
    printf("  Total alerts     : %u\n", ids->total_alerts);
    for(int i=1;i<ALERT_TYPE_N;i++)
        if(ids->by_type[i])
            printf("  %-14s : %u\n",ALERT_NAMES[i],ids->by_type[i]);
}

void ids_write_json(const IDS *ids, FILE *f) {
    if(!f) return;
    fprintf(f,"{\n  \"total_frames\":%u,\n  \"total_alerts\":%u,\n",
            ids->total_frames,ids->total_alerts);
    fprintf(f,"  \"by_type\":{\n");
    for(int i=1;i<ALERT_TYPE_N;i++)
        fprintf(f,"    \"%s\":%u%s\n",ALERT_NAMES[i],ids->by_type[i],
                i<ALERT_TYPE_N-1?",":"");
    fprintf(f,"  }\n}\n");
}
