#!/usr/bin/env python
from __future__ import division, print_function

from binascii import unhexlify
import sys
from more_itertools import grouper

with open(sys.argv[1]) as f:
    lines = f.read().split('\n')[:-1]

for len, msg in grouper(2, lines):
    length = int(length)
    if length % 8 != 0:
        continue
    with open('in/{}'.format(length), 'wb') as f:
        if length != 0:
            f.write(unhexlify(msg))
