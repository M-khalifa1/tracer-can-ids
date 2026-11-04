/*
 * ids_daemon.c  –  TRACER 2.0 Live IDS (v2, warning-free)
 *
 * Build:  gcc -Wall -Wextra -O2 -I. ids_daemon.c tracer_ids.c -lm -o ids_daemon
 * Run:    sudo ./ids_daemon can0
 *         sudo ./ids_daemon can0 results/ids_alerts.csv   (custom log path)
 *
 * Ctrl+C → SecOps summary + JSON stats file
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <net/if.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include "tracer_ids.h"
#include "sha256.h"

static volatile int g_stop = 0;
static IDS g_ids;
static void on_sig(int s) { (void)s; g_stop=1; }

static uint64_t now_us(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
    return (uint64_t)ts.tv_sec*1000000ULL+(uint64_t)(ts.tv_nsec/1000);
}

static int can_open(const char *iface) {
    int s=socket(PF_CAN,SOCK_RAW,CAN_RAW); if(s<0){perror("socket");return -1;}
    struct ifreq ifr; strncpy(ifr.ifr_name,iface,IFNAMSIZ-1);
    if(ioctl(s,SIOCGIFINDEX,&ifr)<0){perror("ioctl");close(s);return -1;}
    struct sockaddr_can addr={0};
    addr.can_family=AF_CAN; addr.can_ifindex=ifr.ifr_ifindex;
    if(bind(s,(struct sockaddr*)&addr,sizeof(addr))<0){perror("bind");close(s);return -1;}
    can_err_mask_t em=CAN_ERR_MASK;
    setsockopt(s,SOL_CAN_RAW,CAN_RAW_ERR_FILTER,&em,sizeof(em));
    return s;
}

/* Auto-create directory portion of a file path */
static void mkdir_p(const char *filepath) {
    char tmp[256]; snprintf(tmp,sizeof(tmp),"%s",filepath);
    char *slash=strrchr(tmp,'/');
    if(slash){ *slash='\0'; mkdir(tmp,0755); }
}

int main(int argc, char *argv[]) {
    const char *iface    = argc>1 ? argv[1] : "can0";
    const char *csvpath  = argc>2 ? argv[2] : "results/ids_alerts.csv";

    signal(SIGINT,on_sig); signal(SIGTERM,on_sig);

    ids_init(&g_ids, DEFAULT_HMAC_KEY);

    /* Auto-create results directory */
    mkdir_p(csvpath);

    FILE *csv = fopen(csvpath,"w");
    if (!csv) { perror("Cannot open log file"); return 1; }
    ids_set_csv(&g_ids, csv);

    int sock = can_open(iface);
    if (sock<0) { fclose(csv); return 1; }

    printf("\033[1m");
    printf("╔══════════════════════════════════════════╗\n");
    printf("║   TRACER 2.0 IDS Daemon  v2              ║\n");
    printf("║   8 rules  |  HMAC-SHA256 auth           ║\n");
    printf("╠══════════════════════════════════════════╣\n");
    printf("║  Interface : %-10s                 ║\n", iface);
    printf("║  Log       : %-28s ║\n", csvpath);
    printf("╠══════════════════════════════════════════╣\n");
    printf("║  WHITELIST (no alert for these IDs):     ║\n");
    printf("║  0x111 0x112 0x121 0x211 0x221 0x231     ║\n");
    printf("║  0x241 0x251 0x252 0x261 0x262           ║\n");
    printf("║  0x311 0x421 0x441                       ║\n");
    printf("╠══════════════════════════════════════════╣\n");
    printf("║  R1:FLOOD R2:MODE R3:VJUMP R4:REPLAY     ║\n");
    printf("║  R5:UNKNWN R6:NO_AUTH R7:BADMAC R8:BURST ║\n");
    printf("╚══════════════════════════════════════════╝\n");
    printf("\033[0m");
    printf("Waiting for CAN frames... (Ctrl+C to stop)\n\n");

    uint64_t t_start   = now_us();
    uint64_t t_status  = t_start;
    struct can_frame fr;

    while (!g_stop) {
        fd_set rfs; FD_ZERO(&rfs); FD_SET(sock,&rfs);
        struct timeval tv={0,10000};
        int r=select(sock+1,&rfs,NULL,NULL,&tv);
        uint64_t now=now_us();

        if (r>0) {
            if(read(sock,&fr,sizeof(fr))<0) continue;
            if(fr.can_id & CAN_ERR_FLAG) continue;   /* skip error frames */
            uint32_t id=fr.can_id & CAN_SFF_MASK;
            ids_feed(&g_ids, id, fr.can_dlc, fr.data, now);
        }

        /* Flush auth pending every 10ms */
        ids_tick(&g_ids, now);

        /* Status line every 5 seconds */
        if (now-t_status > 5000000ULL) {
            uint64_t up=(now-t_start)/1000000ULL;
            printf("\r\033[K\033[90m[IDS] up=%llus frames=%u alerts=%u"
                   " [FLD=%u MOD=%u VJP=%u RPL=%u AUTH=%u MAC=%u]\033[0m",
                (unsigned long long)up,
                g_ids.total_frames, g_ids.total_alerts,
                g_ids.by_type[ALERT_FLOOD],  g_ids.by_type[ALERT_MODE_CHG],
                g_ids.by_type[ALERT_VEL_JUMP],g_ids.by_type[ALERT_REPLAY],
                g_ids.by_type[ALERT_NO_AUTH], g_ids.by_type[ALERT_BAD_MAC]);
            fflush(stdout); t_status=now;
        }
    }

    printf("\n\n[IDS] Shutting down...\n");
    ids_tick(&g_ids, now_us());   /* flush any pending auth */
    fclose(csv);

    /* Write JSON */
    char jpath[256]; snprintf(jpath,sizeof(jpath),"%s",csvpath);
    char *dot=strrchr(jpath,'.'); if(dot) strcpy(dot,"_stats.json");
    FILE *jf=fopen(jpath,"w");
    if(jf){ ids_write_json(&g_ids,jf); fclose(jf); }

    ids_summary(&g_ids);
    printf("\n  CSV   : %s\n  JSON  : %s\n\n", csvpath, jpath);
    close(sock);
    return 0;
}
