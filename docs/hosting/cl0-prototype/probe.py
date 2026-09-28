#!/usr/bin/env python3
"""probe.py PORT OUT.json [BASELINE.json]

Ask every site (and alias) the same set of questions through 127.0.0.1:PORT
with a Host header, and record status, size and - for the PHP probe - what
the PHP that answered says about itself (version|sapi|euid|owner).
With a baseline, print every answer that changed.
"""
import http.client
import json
import subprocess
import sys

port = int(sys.argv[1])
out = sys.argv[2]
sites = json.loads(subprocess.check_output(["/root/api.sh", "GET", "/websites"]))
hosts = []
for s in sites:
    hosts.append(s["domain"])
    for a in s.get("aliases", []):
        hosts.append(a["domain"])
paths = [
    "/",
    "/snptest.php",
    "/wp-config.php",
    "/.git/config",
    "/wp-content/uploads/x.php",
    "/.well-known/acme-challenge/probe",
    "/xmlrpc.php",
]
res = {}
for h in hosts:
    for p in paths:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        try:
            c.request("GET", p, headers={"Host": h})
            r = c.getresponse()
            b = r.read()
            body = ""
            if p == "/snptest.php" and r.status == 200:
                body = b.decode("utf-8", "replace").strip()[:80]
            res[h + p] = {
                "status": r.status,
                "len": len(b),
                "body": body,
                "loc": r.getheader("Location") or "",
                "server": r.getheader("Server") or "",
            }
        except Exception as e:  # noqa: BLE001
            res[h + p] = {"status": 0, "err": str(e)}
with open(out, "w") as f:
    json.dump(res, f, indent=1, sort_keys=True)
print(f"{len(res)} requests -> {out}")

if len(sys.argv) > 3:
    with open(sys.argv[3]) as f:
        base = json.load(f)
    diff = 0
    for k in sorted(base):
        a, b = base[k], res.get(k, {})
        same_status = a.get("status") == b.get("status")
        same_php = True
        if k.endswith("snptest.php"):
            # major.minor and effective uid must match; the patch level
            # (Remi vs alt-php builds) and the sapi are expected to change
            av = a.get("body", "").split("|")
            bv = b.get("body", "").split("|")
            mm = lambda v: ".".join(v[0].split(".")[:2]) if v and v[0] else ""  # noqa: E731
            same_php = mm(av) == mm(bv) and av[2:3] == bv[2:3]
        if not (same_status and same_php):
            diff += 1
            print(f"DIFF {k}: {a.get('status')} {a.get('body', '')!r} -> "
                  f"{b.get('status')} {b.get('body', '')!r}")
    print(f"{diff} differences")
