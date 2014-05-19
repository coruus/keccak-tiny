#!/usr/bin/env sh
o=build/answers/${2}
mkdir -p $o
find kats/in -type f | parallel --verbose -j16 "./build/${1}sum {} > ${o}/{/}"
