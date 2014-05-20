#define decshake(bits) int shake##bits(unsigned char* o, unsigned long, unsigned char*, unsigned long);                   /*begin keccak.h*/
#define decsha3(bits) int sha3_##bits(unsigned char*,unsigned long,unsigned char*,unsigned long);
decshake(128) decshake(256) decsha3(224) decsha3(256) decsha3(384) decsha3(512)                                             /*end keccak.h*/
#define K static const /* Keccak constants: */                                                                            /*begin keccak.c*/
typedef unsigned char byte;typedef unsigned char* bytes;typedef unsigned long z;typedef unsigned long long u8;K byte rho[24]={1,3,6,10,15,21
,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};K u8 V=1ULL<<63;K u8 W=1ULL<<31;K u8 RC[24]={1,0x8082,V|0x808a,V|W|0x8000,0x808b,W|1,V
|W|0x8081,V|0x8009,138,136,W|0x8009,W|10,W|0x808b,V|0x8b,V|0x8089,V|0x8003,V|0x8002,V|0x80,0x800a,V|W|0xa,V|W|0x8081,V|0x8080,W|1,V|W|0x8008
};K byte pi[25]={10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1}; /**/ static inline z min(z a,z b){return (a<b)?a:b;}
#define ROL(x, s) (((x) << s) | ((x) >> (64-s))) /* :some helper macros to unroll Keccak-f */
#define R24(e) e e e e e e e e e e e e e e e e e e e e e e e e
#define L5(v,s,e) v=0; e; v+=s; e; v+=s; e; v+=s; e; v+=s; e; v+=s; /* the permutation: */
static inline void keccakf(u8* a){u8 b[5]={0};u8 t=0;byte x,y,i=0; /*24 rounds:*/ R24(/*parity*/L5(x,1, b[x]=0; L5(y,5, b[x] ^= a[x+y]))
/*theta*/L5(x,1, L5(y,5, a[y+x] ^= b[(x+4)%5]^ROL(b[(x+1)%5],1)))/*rho*/t=a[1];x=0; R24(b[0]=a[pi[x]]; a[pi[x]]=ROL(t, rho[x]); t=b[0];x++;)
/*chi*/L5(y,5, L5(x,1, b[x] = a[y+x]) L5(x,1, a[y+x] = b[x] ^ ~b[(x+1)%5] & b[(x+2)%5])) /*iota*/ a[0] ^= RC[i]; i++;) } /*:keccakf!*/
#define FOR(i, ST, L, S) do { for (z i = 0; i < L; i += ST) { S; } } while (0)
#define appl(NAME, S) static inline void NAME(bytes dst, bytes src, z len) { FOR(i, 1, len, S); }
#define foldP(I, L, F) while (L >= r) { /*apply F*/ F(a, I, r); /*permute*/ keccakf((u8*)a); I += r; L -= r; }
static inline void clear(bytes a) { FOR(i, 1, 200, a[i] = 0); } appl(xorin, dst[i] ^= src[i])  appl(set, src[i] = dst[i])
static inline int hash(bytes o,z olen,bytes in,z ilen,z r,byte D){if ((o == (void*)0)||((in == (void*)0)&&ilen != 0)||(r >= 200)) return -1;
/*sponge:*/ byte a[200]={0};/*absorb full blocks:*/foldP(in, ilen, xorin);/*delimit:*/a[ilen]^=D;/*pad:*/a[r - 1]^=0x80;
/*absorb last block:*/xorin(a, in, ilen); keccakf((u8*)a);/*squeeze:*/foldP(o, olen, set); /*mop up:*/set(a, o, olen); clear(a); return 0;}
#define defshake(bits) int shake##bits(bytes o, z olen, bytes in, z ilen) {return hash(o,olen,in,ilen,200-(bits/4),0x1f);}
#define defsha3(bits) int sha3_##bits(bytes o,z olen,bytes in,z ilen) {return hash(o,min(olen,200-(bits/4)),in,ilen,200-(bits/4),0x06);}
/*Define the SHA3 and SHAKE instances:*/ defshake(128) defshake(256) defsha3(224) defsha3(256) defsha3(384) defsha3(512)    /*end keccak.c*/
