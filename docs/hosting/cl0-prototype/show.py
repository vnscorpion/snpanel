#!/usr/bin/env python3
"""show.py RESULT.json - summarise a probe run."""
import collections
import json
import sys

d = json.load(open(sys.argv[1]))
c = collections.Counter(("/" + k.split("/", 1)[1], v["status"]) for k, v in d.items())
for k, v in sorted(c.items()):
    print(f"{k[0]:<36} {k[1]:>4}  x{v}")
print()
for k, v in sorted(d.items()):
    if k.endswith("snptest.php") and v["status"] == 200:
        print(f"  {k.split('/')[0]:<22} {v['body']}  [{v.get('server','')}]")
