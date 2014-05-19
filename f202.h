#ifndef F202_H
#define F202_H
#include "k.h"
#include "u.h"

#define decshake(bits) \
    F2 shake##bits(bytes, size, bytes, size);

decshake(128)
decshake(256)

#define decsha3(bits) \
    F2 sha3_##bits(bytes, size, bytes, size);

decsha3(224)
decsha3(256)
decsha3(384)
decsha3(512)

// Can substitute an arbitrary permutation for Keccak-f.
#define P keccakf
#define Plen 200

// Fold P*F over the full blocks of an input.
#define foldP(I, L, F)  \
    while (L >= rate) { \
        F(a, I, rate);  \
        P(a);           \
        I += rate;      \
        L -= rate;      \
    }

#endif // F202_H
