#!/usr/bin/env python
from __future__ import division, print_function

import sys
from more_itertools import grouper

with open(sys.argv[1]) as f:
    lines = f.read().split('\n')[:-1]

for length, md in grouper(2, lines):
    length = int(length)
    if length % 8 != 0:
        continue
    with open('{}/{}'.format(sys.argv[1].split('.')[0], length), 'wb') as f:
        f.write(md)
