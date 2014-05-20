#!/usr/bin/env sh
sources="f202.c f202.h kcku.c u.h"
cat $sources | grep -v "//" | grep -v "#include" | tr -d ' \n' | wc
cloc $sources | grep SUM
cloc $sources kcksum.c | grep SUM
