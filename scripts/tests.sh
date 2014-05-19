#!/usr/bin/env sh
mkdir -p build/kats
t=./scripts/test.sh
$t sha3_224 SHA3-224
$t sha3_256 SHA3-256
$t sha3_384 SHA3-384
$t sha3_512 SHA3-512
$t shake128 SHAKE128
$t shake256 SHAKE256
#diff=$(which opendiff | diff)
diff -r build/answers kats/answers | diffstat
