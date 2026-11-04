/*
 * ids_runner.c — deterministic offline replay of a CAN trace through the IDS.
 *
 * Reads a frame CSV (no wall clock, fully reproducible) and writes an alert
 * CSV. The SAME binary processes synthetic evaluation traces and real lab
 * candump captures (convert with candump2csv.py first), so offline metrics
 * and live metrics use identical detection logic.
 *
 * Input CSV columns (header required):
 *   ts_us,can_id,dlc,data_hex
 *     ts_us   : monotonic microseconds (integer)
 *     can_id  : hex like 0x111 or 111
 *     dlc     : 0..8
 *     data_hex: up to 16 hex chars (dlc bytes), e.g. 00C80000000000 00
 *
 * Thresholds come from argv so a harness can sweep them:
 *   ids_runner IN.csv OUT.csv [key=val ...]
 *   keys: flood_hz flood_win_us vel_jump auth_win_us burst_idle_ms
 *         burst_vel_min seq_window brute_win_us brute_count require_auth_mode
 *
 * Build: gcc -Wall -Wextra -O2 -I. ids_runner.c tracer_ids.c -lm -o ids_runner
 */
#include "tracer_ids.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexval(char c){
    if(c>='0'&&c<='9')return c-'0';
    if(c>='a'&&c<='f')return c-'a'+10;
    if(c>='A'&&c<='F')return c-'A'+10;
    return -1;
}

/* parse up to 8 bytes from a hex string (spaces allowed) */
static int parse_hex(const char *s, uint8_t out[8]){
    int n=0; int hi=-1;
    for(; *s && n<8; s++){
        if(*s==' '||*s=='"') continue;
        int v=hexval(*s); if(v<0) break;
        if(hi<0) hi=v; else { out[n++]=(uint8_t)(hi*16+v); hi=-1; }
    }
    return n;
}

static void apply_kv(IDSConfig *c, const char *kv){
    char key[64]; double val;
    if(sscanf(kv,"%63[^=]=%lf",key,&val)!=2) return;
    if(!strcmp(key,"flood_hz")) c->flood_hz=(float)val;
    else if(!strcmp(key,"flood_win_us")) c->flood_win_us=(uint64_t)val;
    else if(!strcmp(key,"vel_jump")) c->vel_jump=(int)val;
    else if(!strcmp(key,"auth_win_us")) c->auth_win_us=(uint64_t)val;
    else if(!strcmp(key,"burst_idle_ms")) c->burst_idle_ms=(uint64_t)val;
    else if(!strcmp(key,"burst_vel_min")) c->burst_vel_min=(int)val;
    else if(!strcmp(key,"seq_window")) c->seq_window=(uint16_t)val;
    else if(!strcmp(key,"brute_win_us")) c->brute_win_us=(uint64_t)val;
    else if(!strcmp(key,"brute_count")) c->brute_count=(uint32_t)val;
    else if(!strcmp(key,"require_auth_mode")) c->require_auth_for_mode=(val!=0);
    else if(!strcmp(key,"suppress")) c->log_suppress=(val!=0);
}

int main(int argc, char **argv){
    if(argc<3){ fprintf(stderr,"usage: %s IN.csv OUT.csv [key=val ...]\n",argv[0]); return 2; }
    IDSConfig cfg; ids_default_config(&cfg);
    for(int i=3;i<argc;i++) apply_kv(&cfg,argv[i]);

    FILE *in=fopen(argv[1],"r"); if(!in){ perror("in"); return 1; }
    FILE *out=fopen(argv[2],"w"); if(!out){ perror("out"); fclose(in); return 1; }

    IDS ids; ids_init_cfg(&ids,DEFAULT_HMAC_KEY,&cfg);
    ids_set_csv(&ids,out);

    char line[512]; int first=1; uint64_t last_ts=0;
    while(fgets(line,sizeof(line),in)){
        if(first){ first=0; if(strstr(line,"ts_us")) continue; }
        uint64_t ts; char idbuf[16]; int dlc; char hex[64]={0};
        /* ts_us,can_id,dlc,data_hex */
        char *p=line;
        if(sscanf(p,"%llu,%15[^,],%d,%63[^\n\r]",
                  (unsigned long long*)&ts,idbuf,&dlc,hex)<3) continue;
        uint32_t id=(uint32_t)strtol(idbuf,NULL,16);
        uint8_t data[8]={0}; parse_hex(hex,data);
        /* advance timeout state up to this frame's time */
        ids_tick(&ids,ts);
        ids_feed(&ids,id,(uint8_t)(dlc<0?0:dlc>8?8:dlc),data,ts);
        last_ts=ts;
    }
    ids_tick(&ids,last_ts+1000000ULL); /* final flush */

    /* summary JSON next to the alert CSV */
    char jpath[512]; snprintf(jpath,sizeof(jpath),"%s",argv[2]);
    char *dot=strrchr(jpath,'.'); if(dot) strcpy(dot,".json"); else strcat(jpath,".json");
    FILE *jf=fopen(jpath,"w"); if(jf){ ids_write_json(&ids,jf); fclose(jf); }

    fclose(in); fclose(out);
    fprintf(stderr,"frames=%u alerts=%u\n",ids.total_frames,ids.total_alerts);
    return 0;
}
