# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import string
import random

def _rand_string(a, b):
    return "".join(random.choice(string.ascii_lowercase)
                   for x in xrange(random.randint(a, b)))

# Typically OS X has a $TMPDIR set, otherwise go with /tmp
for tmp in [os.environ.get("TMPDIR"), os.environ.get("TEMP"), "/tmp"]:
    if tmp and os.path.isdir(tmp):
        TEMP=tmp # Just in case.
        TMP=tmp


# This was DriveLetter:\[6-10]\ in Windows, but that doesn't make
# sense in the Unix world.  Let's go with /tmp instead.  I am also
# changing it to OUTPUT because this is where we are outputting all
# our analysis data.
OUTPUT = os.path.join(TMP, _rand_string(6, 10))

PATHS = {"output" : OUTPUT,
         "logs"   : os.path.join(OUTPUT, "logs"),
         "files"  : os.path.join(OUTPUT, "files"),
         "shots"  : os.path.join(OUTPUT, "shots"),
         "memory" : os.path.join(OUTPUT, "memory"),
         "drop"   : os.path.join(OUTPUT, "drop")}
