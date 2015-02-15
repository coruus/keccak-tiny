#!/usr/bin/env sh
ninja
test -d build/answers && rm -rf build/answers
mkdir build/answers &&
parallel -j8 './build/shake256sum {} > build/answers/{/}' ::: kats/input/*
