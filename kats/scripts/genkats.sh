#!/usr/bin/env sh
s=scripts/genkats.sh
sh $s SHA3-224 &&
sh $s SHA3-256 &&
sh $s SHA3-384 &&
sh $s SHA3-512 &&
sh $s SHAKE128 &&
sh $s SHAKE256
