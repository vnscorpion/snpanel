#!/usr/bin/env python3
"""outage.py LOOP.log EVENT_EPOCH - how long port 80 was unavailable after an event."""
import sys

k = float(sys.argv[2])
rows = [line.split() for line in open(sys.argv[1]) if len(line.split()) == 2]
after = [(float(t), s) for t, s in rows if float(t) >= k]
bad = [t for t, s in after if s != "200"]
print(f"samples={len(rows)} after_event={len(after)} failed={len(bad)}")
if bad:
    back = next((t for t, s in after if s == "200" and t > bad[-1]), None)
    print(f"first failure +{bad[0] - k:.2f}s, last failure +{bad[-1] - k:.2f}s, "
          f"service back +{(back - k) if back else float('nan'):.2f}s")
else:
    print("no failed request")
