#!/usr/bin/env sh
s=./scripts/genkat.sh
$s SHA3-224 &&
$s SHA3-256 &&
$s SHA3-384 &&
$s SHA3-512 &&
$s SHAKE128 &&
$s SHAKE256
