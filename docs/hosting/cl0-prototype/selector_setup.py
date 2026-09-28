#!/usr/bin/env python3
"""selector_setup.py - stage S10 of `snpanel upgrade cloudlinux`, done by hand.

Every PHP/WordPress site must keep the PHP version it runs today:
  * each owner is put in CageFS
  * the owner's Selector version = the version most of their PHP sites use
    (a tie goes to the server default, 8.4)
  * every site on another version gets CloudLinux Isolates and a per-domain
    Selector version. That needs the CPAPI `domains` script to say who owns it.
"""
import collections
import json
import subprocess

DEFAULT = "8.4"


def run(*cmd, user=None):
    if user:
        cmd = ("runuser", "-u", user, "--") + cmd
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


sites = json.loads(subprocess.check_output(["/root/api.sh", "GET", "/websites"]))
by_user = collections.defaultdict(list)
for s in sites:
    if s["app_type"] in ("php", "wordpress"):
        by_user[s["linux_user"]].append(s)

for user, ss in sorted(by_user.items()):
    counts = collections.Counter(s["php_version"] for s in ss)
    top = max(counts.values())
    winners = sorted(v for v, c in counts.items() if c == top)
    chosen = DEFAULT if DEFAULT in winners else winners[-1]
    run("cagefsctl", "--enable", user)
    rc, o = run("cloudlinux-selector", "set", "--json", "--interpreter", "php",
                "--user", user, "--current-version", chosen)
    print(f"{user}: user version {chosen} ({dict(counts)}) -> {json.loads(o).get('result')}")
    odd = [s for s in ss if s["php_version"] != chosen]
    if odd:
        run("install", "-d", "-o", user, "-g", user, "-m", "0771", f"/home/{user}/.cagefs/websites")
        run("cagefsctl", "--isolates-allow", user)
    for s in odd:
        run("cagefsctl", "--isolates-enable", s["domain"])
        rc, o = run("cloudlinux-selector", "set", "--json", "--interpreter", "php",
                    "--domain", s["domain"], "--current-version", s["php_version"], user=user)
        print(f"  {s['domain']}: domain version {s['php_version']} -> {o[-60:]}")
