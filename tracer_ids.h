/*
 * tracer_ids.h  –  TRACER 2.0 IDS: types, rules, API   (v3)
 * =========================================================
 * v3 changes (driven by journal reviewer comments):
 *   - All thresholds moved into a runtime IDSConfig struct so they can be
 *     swept for sensitivity analysis (R2-7) and documented (R1-3,4,6,10).
 *   - Sequence-freshness verification added to the authentication path so
 *     replay of a *validly signed* frame is rejected, not just bad MACs
 *     (R2-6, R1-11). This makes the "replay resistance" claim real.
 *   - Authentication generalised from 0x111 to all host->robot command
 *     frames (0x111 motion, 0x421 mode, 0x441 error-clear) (R1-8).
 *   - R2 is now authentication-aware: an operating-mode change carrying a
 *     valid companion is treated as legitimate, so R2 no longer flags every
 *     transition as malicious (R1-2).
 *   - New rule R9 BRUTE_FORCE: repeated BAD_MAC within a window, to detect
 *     online tag-guessing against the 4-byte MAC (R2-6, R1-11).
 *   - Bug fixes: REPLAY counter cascade, silent pending-auth overwrite,
 *     and repeated-alert log flooding (see tracer_ids.c).
 *
 * Protocol note (corrected per AgileX ugv_sdk protocol_v2 and manual):
 *   byte[7] of 0x111 is Reserved (0x00) in the stock protocol; it carries
 *   NO counter. The freshness counter used by the replay rule is supplied by
 *   our own signed sender inside the authenticated message, not by the stock
 *   frame. This is stated explicitly in the paper's vulnerability analysis.
 */
#ifndef TRACER_IDS_H
#define TRACER_IDS_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>

/* ── Host->robot command frames (AgileX TRACER 2.0, protocol_v2) ──── */
#define ID_MOTION_CMD   0x111  /* host->tracer: velocity            */
#define ID_AUTH_MAC     0x112  /* host->tracer: HMAC companion (ours)*/
#define ID_LIGHT_CMD    0x121  /* host->tracer: lights              */
#define ID_SYS_STATUS   0x211  /* tracer->host: state+battery       */
#define ID_MOTION_FB    0x221  /* tracer->host: velocity feedback   */
#define ID_LIGHT_FB     0x231  /* tracer->host: light feedback      */
#define ID_RC_STATE     0x241  /* tracer->host: RC transmitter state*/
#define ID_MOTOR_HS_L   0x251  /* tracer->host: actuator1 HS        */
#define ID_MOTOR_HS_R   0x252  /* tracer->host: actuator2 HS        */
#define ID_MOTOR_LS_L   0x261  /* tracer->host: actuator1 LS        */
#define ID_MOTOR_LS_R   0x262  /* tracer->host: actuator2 LS        */
#define ID_ODOMETER     0x311  /* tracer->host: odometry            */
#define ID_MODE_SET     0x421  /* host->tracer: mode switch         */
#define ID_ERR_CLEAR    0x441  /* host->tracer: error clear         */

/* Whitelist: every ID the Tracer legitimately sends or receives.
 * 0x241 is RC-transmitter state (NOT battery detail); it is whitelisted
 * because it appears continuously (~50 Hz) during normal operation. */
static const uint32_t IDS_WHITELIST[] = {
    0x111, 0x112, 0x121,
    0x211, 0x221, 0x231, 0x241,
    0x251, 0x252, 0x261, 0x262,
    0x311, 0x421, 0x441
};
#define IDS_WHITELIST_N (sizeof(IDS_WHITELIST)/sizeof(IDS_WHITELIST[0]))

/* Set of host->robot command IDs that MUST carry a 0x112 companion.
 * Generalises authentication beyond motion (R1-8). */
static inline bool ids_is_authenticated_cmd(uint32_t id) {
    return id == ID_MOTION_CMD || id == ID_MODE_SET || id == ID_ERR_CLEAR;
}

/* ── Tunable thresholds (defaults justified against the manual) ────── *
 * Manual TRACER (V2.0.x) Table 3.4: 0x111 cycle = 20 ms, timeout = 500 ms,
 * effective linear velocity |v| <= 1800 mm/s. Feedback frames at 20 ms
 * (~50 Hz). These constants are the DEFAULTS; ids_default_config() fills an
 * IDSConfig that the harness overrides for sensitivity sweeps.            */
#define DEF_FLOOD_HZ_THRESH   200.0f /* > ~4x the 50 Hz feedback rate      */
#define DEF_FLOOD_WIN_US   100000    /* sliding window = 100 ms            */
#define DEF_VEL_JUMP_THRESH   600    /* mm/s delta in one 20 ms step       */
#define DEF_AUTH_WIN_US      8000    /* < 20 ms cycle, >> 0.5 ms send gap  */
#define DEF_COUNTER_BACK_MAX    3    /* legacy byte[7] heuristic (unused by
                                      * default; superseded by seq check)  */
#define DEF_BURST_IDLE_MS     300    /* < 500 ms command timeout           */
#define DEF_BURST_VEL_MIN     150    /* mm/s to count as active motion     */
#define DEF_SEQ_WINDOW         64    /* accept seq in (last, last+window]   */
#define DEF_BRUTE_WIN_US  1000000    /* 1 s window for repeated BAD_MAC     */
#define DEF_BRUTE_COUNT        5     /* >=5 BAD_MAC in window -> BRUTE_FORCE*/

typedef struct {
    float    flood_hz;
    uint64_t flood_win_us;
    int      vel_jump;
    uint64_t auth_win_us;
    uint64_t burst_idle_ms;
    int      burst_vel_min;
    uint16_t seq_window;     /* 0 disables freshness (legacy behaviour)   */
    uint64_t brute_win_us;
    uint32_t brute_count;
    bool     require_auth_for_mode; /* R2 authenticated-mode handling      */
    bool     log_suppress;          /* collapse tight identical bursts in   *
                                     * the log (live daemon); OFF for       *
                                     * offline scoring so every alert shows */
} IDSConfig;

void ids_default_config(IDSConfig *c);

/* ── HMAC key (16 bytes – change before deployment) ──────────────── */
#define HMAC_KEY_LEN 16
static const uint8_t DEFAULT_HMAC_KEY[HMAC_KEY_LEN] = {
    0xC4,0x7A,0x3E,0x91,0x5F,0xB2,0xD0,0x88,
    0x1C,0x4E,0xA7,0x6D,0x39,0xF8,0x02,0x5B
};

/* ── Alert types (indices are stable; new ones appended) ─────────── */
typedef enum {
    ALERT_NONE        = 0,
    ALERT_FLOOD       = 1,
    ALERT_MODE_CHG    = 2,
    ALERT_VEL_JUMP    = 3,
    ALERT_REPLAY      = 4,
    ALERT_UNKNOWN     = 5,
    ALERT_NO_AUTH     = 6,
    ALERT_BAD_MAC     = 7,
    ALERT_BURST       = 8,
    ALERT_BRUTE_FORCE = 9,  /* v3: repeated MAC-guessing                 */
    ALERT_STALE_SEQ   = 10, /* v3: valid MAC but non-fresh sequence      */
} AlertType;
#define ALERT_TYPE_N 11

typedef enum { SEV_INFO=0, SEV_WARN=1, SEV_CRIT=2 } Severity;

extern const char * const ALERT_NAMES[ALERT_TYPE_N];
extern const char * const SEV_NAMES[3];

/* ── Alert record ────────────────────────────────────────────────── */
typedef struct {
    uint64_t  ts_us;
    AlertType type;
    Severity  sev;
    uint32_t  can_id;
    char      detail[200];
    uint8_t   raw[8];
    uint8_t   dlc;
} Alert;

/* ── Rate tracker ────────────────────────────────────────────────── */
typedef struct {
    uint32_t id;
    uint32_t count;
    uint64_t win_start;
    float    rate_hz;
    bool     flooding;
} RateTrack;
#define MAX_TRACK 48

/* ── Pending auth (now records which command id is awaiting 0x112) ── */
typedef struct {
    bool     pending;
    uint32_t cmd_id;
    uint64_t ts_us;
    uint8_t  data[8];
    uint8_t  dlc;
} PendingAuth;

/* ── Auth frame (0x112 payload) ──────────────────────────────────── */
typedef struct {
    uint8_t  mac4[4];
    uint16_t seq;
    uint16_t ts_low;
} AuthFrame;

/* ── IDS state ───────────────────────────────────────────────────── */
typedef struct {
    IDSConfig   cfg;
    int16_t     last_vel;
    uint8_t     last_ctr;
    bool        ctr_valid;
    uint8_t     cur_mode;
    uint64_t    last_motion_ts;
    PendingAuth pauth;
    /* sequence-freshness state (v3) */
    uint32_t    last_seq;
    bool        seq_valid;
    /* brute-force state (v3) */
    uint64_t    brute_win_start;
    uint32_t    brute_count;
    /* repeated-alert suppression (v3 bugfix for log flooding).
     * Only consecutive identical (type,id) alerts within SUPPRESS_GAP_US of
     * each other are collapsed, so distinct spaced events are all logged. */
    AlertType   last_alert_type;
    uint32_t    last_alert_id;
    uint64_t    last_alert_ts;
    uint32_t    suppressed;
    RateTrack   tracks[MAX_TRACK];
    int         n_tracks;
    uint8_t     hmac_key[HMAC_KEY_LEN];
    /* counters */
    uint32_t    total_frames;
    uint32_t    total_alerts;
    uint32_t    by_type[ALERT_TYPE_N];
    /* output */
    FILE       *csv;
} IDS;

/* ── API ─────────────────────────────────────────────────────────── */
void  ids_init        (IDS *ids, const uint8_t *key);            /* defaults */
void  ids_init_cfg    (IDS *ids, const uint8_t *key, const IDSConfig *cfg);
void  ids_set_csv     (IDS *ids, FILE *f);
Alert ids_feed        (IDS *ids, uint32_t id, uint8_t dlc,
                       const uint8_t *data, uint64_t ts_us);
void  ids_tick        (IDS *ids, uint64_t now_us);   /* call every ~10ms */
void  ids_summary     (const IDS *ids);
void  ids_write_json  (const IDS *ids, FILE *f);

/* ── Signing ─────────────────────────────────────────────────────── */
void  sign_make  (const uint8_t *key, uint16_t seq,
                  uint32_t can_id, const uint8_t *payload,
                  AuthFrame *out);
bool  sign_check (const uint8_t *key,
                  const uint8_t *cmd_payload,
                  uint32_t can_id,
                  const uint8_t *auth_payload);

#endif
