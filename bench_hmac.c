/*
 * bench_hmac.c — measure companion-frame signing/verification cost on the
 * ACTUAL target, reporting a distribution (min/mean/median/p99/max), not a
 * single hand-set number (reviewer R1-12). Run this on the ACTUAL deployment
 * host that runs the SocketCAN signer/IDS (the same Ubuntu machine used in the
 * paper) — no separate embedded board is required. It writes JSON.
 *
 * Build (on the deployment host):
 *   gcc -O2 -I. bench_hmac.c tracer_ids.c -lm -o bench_hmac
 * Run:
 *   ./bench_hmac 200000 > results/hmac_bench.json
 */
#include "tracer_ids.h"
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t ns_now(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
    return (uint64_t)ts.tv_sec*1000000000ULL + ts.tv_nsec;
}
static int cmp_u64(const void*a,const void*b){
    uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b;
    return x<y?-1:x>y?1:0;
}

int main(int argc, char**argv){
    int N = argc>1 ? atoi(argv[1]) : 200000;
    if(N<1000) N=1000;
    uint64_t *s = malloc(sizeof(uint64_t)*N);
    uint8_t cmd[8]={0x00,0xC8,0,0,0,0,0,0};
    AuthFrame af;

    /* warm up */
    for(int i=0;i<1000;i++) sign_make(DEFAULT_HMAC_KEY,i,ID_MOTION_CMD,cmd,&af);

    /* time sign_make (full companion-frame authenticator over 12-byte msg) */
    for(int i=0;i<N;i++){
        cmd[7]=(uint8_t)i;
        uint64_t t0=ns_now();
        sign_make(DEFAULT_HMAC_KEY,(uint16_t)i,ID_MOTION_CMD,cmd,&af);
        s[i]=ns_now()-t0;
    }
    qsort(s,N,sizeof(uint64_t),cmp_u64);
    double sum=0; for(int i=0;i<N;i++) sum+=s[i];
    double mean=sum/N;
    uint64_t p50=s[N/2], p99=s[(int)(N*0.99)], mn=s[0], mx=s[N-1];

    /* verify cost (sign + full recompute + compare) */
    uint8_t auth[8]={af.mac4[0],af.mac4[1],af.mac4[2],af.mac4[3],0,0,0,0};
    uint64_t vmin=~0ULL,vmax=0; double vsum=0;
    for(int i=0;i<N;i++){
        uint64_t t0=ns_now();
        volatile bool ok=sign_check(DEFAULT_HMAC_KEY,cmd,ID_MOTION_CMD,auth);
        uint64_t d=ns_now()-t0; (void)ok;
        vsum+=d; if(d<vmin)vmin=d; if(d>vmax)vmax=d;
    }

    printf("{\n");
    printf("  \"platform\": \"FILL_ME (deployment host, e.g. Ubuntu 24.04, Intel i7-xxxx)\",\n");
    printf("  \"iterations\": %d,\n", N);
    printf("  \"sign_us\": {\"min\":%.3f,\"mean\":%.3f,\"median\":%.3f,\"p99\":%.3f,\"max\":%.3f},\n",
           mn/1000.0, mean/1000.0, p50/1000.0, p99/1000.0, mx/1000.0);
    printf("  \"verify_us\": {\"min\":%.3f,\"mean\":%.3f,\"max\":%.3f},\n",
           vmin/1000.0, (vsum/N)/1000.0, vmax/1000.0);
    printf("  \"can_control_period_us\": 20000,\n");
    printf("  \"overhead_percent_of_control_period\": %.4f\n", (mean/1000.0)/20000.0*100.0);
    printf("}\n");
    free(s);
    return 0;
}
