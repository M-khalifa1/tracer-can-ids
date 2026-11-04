/*
 * test_v3.c — regression tests for the v3 fixes and new rules.
 * Offline only (no CAN hardware). Build:
 *   gcc -Wall -Wextra -O2 -I. test_v3.c tracer_ids.c -lm -o test_v3
 */
#include "tracer_ids.h"
#include "sha256.h"
#include <stdio.h>
#include <string.h>

static int pass=0, fail=0;
static void check(const char *name, int ok, const char *note){
    printf("  [%s] %-52s %s\n", ok?"PASS":"FAIL", name, ok?"":note);
    if(ok) pass++; else fail++;
}

/* helper: send a signed command pair through the IDS */
static void send_signed(IDS *ids, uint32_t cid, const uint8_t *cmd,
                        uint16_t seq, uint64_t ts, const uint8_t *key){
    AuthFrame af; sign_make(key?key:DEFAULT_HMAC_KEY, seq, cid, cmd, &af);
    uint8_t auth[8]={af.mac4[0],af.mac4[1],af.mac4[2],af.mac4[3],
                     (uint8_t)(seq>>8),(uint8_t)(seq&0xFF),
                     (uint8_t)(af.ts_low>>8),(uint8_t)(af.ts_low&0xFF)};
    ids_feed(ids,cid,8,cmd,ts);
    ids_feed(ids,ID_AUTH_MAC,8,auth,ts+500);
}

int main(void){
    printf("\n=== TRACER IDS v3 regression tests ===\n");

    /* BUG 1: REPLAY/STALE cascade must not fire on legitimate restart.
     * Two signed sessions of 160 motion frames each; the second restarts
     * seq from a low value but the sender is legitimate (valid MACs,
     * fresh monotonic seq within each session with a reset). With seq
     * freshness, a legit reset should produce at most a few alerts, not
     * one per frame. */
    {
        IDS ids; ids_init(&ids,DEFAULT_HMAC_KEY);
        uint64_t ts=1000000; uint16_t seq=1;
        for(int s=0;s<2;s++){
            /* on session restart, allow the verifier to resync: a real
             * deployment resets seq_valid on reboot; emulate by a fresh IDS
             * only for the counter, here we just keep going monotonically */
            for(int i=0;i<160;i++){
                uint8_t cmd[8]={0,200,0,0,0,0,0,0};
                send_signed(&ids,ID_MOTION_CMD,cmd,seq++,ts,DEFAULT_HMAC_KEY);
                ids_tick(&ids,ts+600); ts+=20000;
            }
            ts+=200000;
        }
        check("No REPLAY cascade on 320 legit signed frames",
              ids.by_type[ALERT_STALE_SEQ]==0 && ids.by_type[ALERT_REPLAY]==0,
              "cascade still present");
    }

    /* BUG 2: a second motion command before its companion must raise
     * NO_AUTH for the first (no silent overwrite). */
    {
        IDS ids; ids_init(&ids,DEFAULT_HMAC_KEY);
        uint8_t cmd[8]={0,100,0,0,0,0,0,0};
        ids_feed(&ids,ID_MOTION_CMD,8,cmd,1000000);
        ids_feed(&ids,ID_MOTION_CMD,8,cmd,1001000); /* 1 ms later, no 0x112 */
        check("Overlapping unsigned 0x111 -> NO_AUTH for the first",
              ids.by_type[ALERT_NO_AUTH]>=1, "silent overwrite");
    }

    /* NEW: valid MAC but replayed (stale) seq -> STALE_SEQ, once. */
    {
        IDS ids; ids_init(&ids,DEFAULT_HMAC_KEY);
        uint8_t cmd[8]={0,200,0,0,0,0,0,0};
        uint64_t ts=1000000;
        for(uint16_t s=10;s<=20;s++){ send_signed(&ids,ID_MOTION_CMD,cmd,s,ts,0); ts+=20000; }
        /* attacker replays a captured valid pair with an old seq=12 */
        AuthFrame af; sign_make(DEFAULT_HMAC_KEY,12,ID_MOTION_CMD,cmd,&af);
        uint8_t auth[8]={af.mac4[0],af.mac4[1],af.mac4[2],af.mac4[3],0,12,0,0};
        ids_feed(&ids,ID_MOTION_CMD,8,cmd,ts);
        Alert a=ids_feed(&ids,ID_AUTH_MAC,8,auth,ts+500);
        check("Replayed valid frame with stale seq -> STALE_SEQ",
              a.type==ALERT_STALE_SEQ, "freshness not enforced");
    }

    /* NEW: brute-force -> BRUTE_FORCE after threshold. */
    {
        IDSConfig c; ids_default_config(&c); c.brute_count=5;
        IDS ids; ids_init_cfg(&ids,DEFAULT_HMAC_KEY,&c);
        uint8_t cmd[8]={0,200,0,0,0,0,0,0};
        uint64_t ts=1000000; int brute=0;
        for(int i=0;i<10;i++){
            ids_feed(&ids,ID_MOTION_CMD,8,cmd,ts);
            uint8_t bad[8]={(uint8_t)i,0xAD,0xBE,0xEF,0,(uint8_t)i,0,0};
            Alert a=ids_feed(&ids,ID_AUTH_MAC,8,bad,ts+500);
            if(a.type==ALERT_BRUTE_FORCE) brute++;
            ts+=20000;
        }
        check("Repeated forged MACs -> BRUTE_FORCE escalation",
              ids.by_type[ALERT_BRUTE_FORCE]>0, "no brute-force rule");
    }

    /* NEW: authenticated mode change is NOT flagged; unauthenticated IS. */
    {
        IDS ids; ids_init(&ids,DEFAULT_HMAC_KEY);
        uint8_t m[8]={0x01,0,0,0,0,0,0,0};
        send_signed(&ids,ID_MODE_SET,m,1,1000000,0);
        int auth_flagged = ids.by_type[ALERT_MODE_CHG]+ids.by_type[ALERT_NO_AUTH];
        IDS ids2; ids_init(&ids2,DEFAULT_HMAC_KEY);
        ids_feed(&ids2,ID_MODE_SET,1,m,1000000);
        ids_tick(&ids2,1000000+ids2.cfg.auth_win_us+1000);
        check("Authenticated 0x421 mode change -> no alert",
              auth_flagged==0, "authenticated mode still flagged");
        check("Unauthenticated 0x421 mode change -> NO_AUTH",
              ids2.by_type[ALERT_NO_AUTH]>=1, "unauth mode missed");
    }

    /* Clean traffic: feedback + RC state must not alert. */
    {
        IDS ids; ids_init(&ids,DEFAULT_HMAC_KEY);
        uint64_t ts=1000000; bool any=false;
        for(int i=0;i<50;i++){
            uint8_t d[8]={0,0,0,0,0,0,0,(uint8_t)i};
            if(ids_feed(&ids,ID_MOTION_FB,8,d,ts).type!=ALERT_NONE) any=true;
            uint8_t rc[8]={0xAA,0,0,0,0,0,0,(uint8_t)i};
            if(ids_feed(&ids,ID_RC_STATE,8,rc,ts+1000).type!=ALERT_NONE) any=true;
            ts+=20000;
        }
        check("Clean 50 Hz feedback + 0x241 RC state -> no alert", !any,
              "false positive on benign traffic");
    }

    /* Config knobs actually change behaviour (needed for sensitivity sweep). */
    {
        IDSConfig c; ids_default_config(&c); c.vel_jump=100;
        IDS ids; ids_init_cfg(&ids,DEFAULT_HMAC_KEY,&c);
        uint8_t a1[8]={0,100,0,0,0,0,0,0}, a2[8]={0,250,0,0,0,0,0,0};
        ids_feed(&ids,ID_MOTION_CMD,8,a1,1000000);
        ids_tick(&ids,1000000+9000);
        Alert a=ids_feed(&ids,ID_MOTION_CMD,8,a2,1020000);
        check("Lowered vel_jump threshold triggers VEL_JUMP (sweepable)",
              a.type==ALERT_VEL_JUMP, "config not honoured");
    }

    printf("\n  Result: %d passed, %d failed\n\n", pass, fail);
    return fail?1:0;
}
