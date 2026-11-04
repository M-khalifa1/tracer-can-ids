/*
 * sha256.h  –  Standalone SHA-256 / HMAC-SHA-256
 * Zero external dependencies. Single header drop-in.
 */
#ifndef SHA256_H
#define SHA256_H
#include <stdint.h>
#include <string.h>

typedef struct { uint32_t state[8]; uint64_t count; uint8_t buf[64]; } SHA256_CTX;

static const uint32_t K256[64]={
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define ROR32(x,n)(((x)>>(n))|((x)<<(32-(n))))
#define CH(e,f,g)(((e)&(f))^(~(e)&(g)))
#define MAJ(a,b,c)(((a)&(b))^((a)&(c))^((b)&(c)))
#define EP0(a)(ROR32(a,2)^ROR32(a,13)^ROR32(a,22))
#define EP1(e)(ROR32(e,6)^ROR32(e,11)^ROR32(e,25))
#define SIG0(x)(ROR32(x,7)^ROR32(x,18)^((x)>>3))
#define SIG1(x)(ROR32(x,17)^ROR32(x,19)^((x)>>10))

static void sha256_transform(SHA256_CTX*ctx,const uint8_t*blk){
    uint32_t W[64],a,b,c,d,e,f,g,h,T1,T2; int i;
    for(i=0;i<16;i++) W[i]=((uint32_t)blk[i*4]<<24)|((uint32_t)blk[i*4+1]<<16)|((uint32_t)blk[i*4+2]<<8)|(uint32_t)blk[i*4+3];
    for(;i<64;i++) W[i]=SIG1(W[i-2])+W[i-7]+SIG0(W[i-15])+W[i-16];
    a=ctx->state[0];b=ctx->state[1];c=ctx->state[2];d=ctx->state[3];
    e=ctx->state[4];f=ctx->state[5];g=ctx->state[6];h=ctx->state[7];
    for(i=0;i<64;i++){T1=h+EP1(e)+CH(e,f,g)+K256[i]+W[i];T2=EP0(a)+MAJ(a,b,c);h=g;g=f;f=e;e=d+T1;d=c;c=b;b=a;a=T1+T2;}
    ctx->state[0]+=a;ctx->state[1]+=b;ctx->state[2]+=c;ctx->state[3]+=d;
    ctx->state[4]+=e;ctx->state[5]+=f;ctx->state[6]+=g;ctx->state[7]+=h;
}
static void sha256_init(SHA256_CTX*ctx){
    ctx->state[0]=0x6a09e667;ctx->state[1]=0xbb67ae85;ctx->state[2]=0x3c6ef372;ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f;ctx->state[5]=0x9b05688c;ctx->state[6]=0x1f83d9ab;ctx->state[7]=0x5be0cd19;ctx->count=0;
}
static void sha256_update(SHA256_CTX*ctx,const uint8_t*data,size_t len){
    size_t i,used=ctx->count&63; ctx->count+=len;
    if(used){size_t av=64-used; if(len<av){memcpy(ctx->buf+used,data,len);return;} memcpy(ctx->buf+used,data,av); sha256_transform(ctx,ctx->buf); data+=av; len-=av;}
    for(i=0;i+64<=len;i+=64) sha256_transform(ctx,data+i);
    memcpy(ctx->buf,data+i,len-i);
}
static void sha256_final(SHA256_CTX*ctx,uint8_t out[32]){
    uint64_t bits=ctx->count*8; uint8_t pad=0x80;
    sha256_update(ctx,&pad,1); pad=0;
    while((ctx->count&63)!=56) sha256_update(ctx,&pad,1);
    uint8_t lb[8]; for(int i=7;i>=0;i--){lb[i]=bits&0xFF;bits>>=8;} sha256_update(ctx,lb,8);
    for(int i=0;i<8;i++){out[i*4]=(ctx->state[i]>>24)&0xFF;out[i*4+1]=(ctx->state[i]>>16)&0xFF;out[i*4+2]=(ctx->state[i]>>8)&0xFF;out[i*4+3]=ctx->state[i]&0xFF;}
}
static inline void sha256(const uint8_t*data,size_t len,uint8_t out[32]){SHA256_CTX ctx;sha256_init(&ctx);sha256_update(&ctx,data,len);sha256_final(&ctx,out);}

static void hmac_sha256(const uint8_t*key,size_t klen,const uint8_t*msg,size_t mlen,uint8_t out[32]){
    uint8_t k[64]={0},ipad[64],opad[64],inner[32];
    if(klen>64) sha256(key,klen,k); else memcpy(k,key,klen);
    for(int i=0;i<64;i++){ipad[i]=k[i]^0x36;opad[i]=k[i]^0x5c;}
    SHA256_CTX ctx; sha256_init(&ctx); sha256_update(&ctx,ipad,64); sha256_update(&ctx,msg,mlen); sha256_final(&ctx,inner);
    sha256_init(&ctx); sha256_update(&ctx,opad,64); sha256_update(&ctx,inner,32); sha256_final(&ctx,out);
}
static inline void hmac_sha256_4(const uint8_t*key,size_t klen,const uint8_t*msg,size_t mlen,uint8_t out4[4]){
    uint8_t full[32]; hmac_sha256(key,klen,msg,mlen,full); memcpy(out4,full,4);
}
#endif
