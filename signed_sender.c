/*
 * signed_sender.c — legitimate authenticated command sender (v3).
 *
 * Sends every safety-relevant host->robot command (0x111 motion, 0x421 mode,
 * 0x441 error-clear) together with a 0x112 companion carrying a 4-byte
 * HMAC-SHA-256 tag over {CAN id, payload, monotonic seq}. One shared seq
 * counter is used across all authenticated commands (freshness).
 *
 * Build: gcc -Wall -Wextra -O2 -I. signed_sender.c tracer_ids.c -lm -o signed_sender
 * Run:   sudo ./signed_sender can0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include "tracer_ids.h"
#include "sha256.h"

static volatile int g_stop = 0;
static uint16_t     g_seq  = 1;   /* one monotonic counter for all commands */
static void on_sig(int s){(void)s;g_stop=1;}

static int can_open(const char *iface){
    int s=socket(PF_CAN,SOCK_RAW,CAN_RAW); if(s<0){perror("socket");return -1;}
    struct ifreq ifr; strncpy(ifr.ifr_name,iface,IFNAMSIZ-1);
    if(ioctl(s,SIOCGIFINDEX,&ifr)<0){perror("ioctl");close(s);return -1;}
    struct sockaddr_can addr={0};
    addr.can_family=AF_CAN; addr.can_ifindex=ifr.ifr_ifindex;
    if(bind(s,(struct sockaddr*)&addr,sizeof(addr))<0){perror("bind");close(s);return -1;}
    return s;
}
static int raw_send(int s, uint32_t id, uint8_t dlc, const uint8_t *d){
    struct can_frame f={0}; f.can_id=id; f.can_dlc=dlc; memcpy(f.data,d,dlc);
    return write(s,&f,sizeof(f))==(ssize_t)sizeof(f)?0:-1;
}

/* Send any authenticated command + its 0x112 companion. */
static void signed_cmd(int s, uint32_t cid, const uint8_t *payload, uint8_t dlc){
    uint8_t p8[8]={0}; memcpy(p8,payload,dlc<8?dlc:8);
    AuthFrame af; sign_make(DEFAULT_HMAC_KEY, g_seq, cid, p8, &af);
    uint8_t auth[8]={af.mac4[0],af.mac4[1],af.mac4[2],af.mac4[3],
                     (uint8_t)(af.seq>>8),(uint8_t)(af.seq&0xFF),
                     (uint8_t)(af.ts_low>>8),(uint8_t)(af.ts_low&0xFF)};
    g_seq++;
    raw_send(s, cid, dlc, payload);
    usleep(400);                 /* companion < 0.5 ms after command */
    raw_send(s, ID_AUTH_MAC, 8, auth);
}

static void signed_mode(int s, uint8_t mode){
    uint8_t d[1]={mode}; signed_cmd(s, ID_MODE_SET, d, 1); usleep(50000);
}
static void signed_motion(int s, int16_t lin, int16_t ang){
    uint8_t cmd[8]={0};
    cmd[0]=(lin>>8)&0xFF; cmd[1]=lin&0xFF;
    cmd[2]=(ang>>8)&0xFF; cmd[3]=ang&0xFF;      /* bytes 4-7 reserved = 0x00 */
    signed_cmd(s, ID_MOTION_CMD, cmd, 8);
}

int main(int argc, char *argv[]){
    const char *iface=argc>1?argv[1]:"can0";
    signal(SIGINT,on_sig); signal(SIGTERM,on_sig);
    int s=can_open(iface); if(s<0) return 1;

    printf("Signed Sender v3 (authenticates 0x111 / 0x421 / 0x441)\n");
    printf("[1] signed mode -> CAN command (0x421#01)\n");
    signed_mode(s, 0x01);
    printf("[2] forward 200 mm/s for 2 s (signed)\n");
    for(int i=0;i<100&&!g_stop;i++){ signed_motion(s,200,0); usleep(20000); }
    printf("[3] spin 300 mrad/s for 1 s (signed)\n");
    for(int i=0;i<50&&!g_stop;i++){ signed_motion(s,0,300); usleep(20000); }
    printf("[4] stop\n");
    for(int i=0;i<20;i++){ signed_motion(s,0,0); usleep(20000); }
    printf("[5] signed mode -> standby (0x421#00)\n");
    signed_mode(s, 0x00);
    printf("done. commands sent, each with a signed 0x112 companion.\n");
    close(s);
    return 0;
}
