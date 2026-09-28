#!/usr/bin/env python3
"""Copy snptest.php into the docroot of every PHP/WordPress site, owned by the site user."""
import json
import os
import pwd
import shutil
import subprocess

sites = json.loads(subprocess.check_output(["/root/api.sh", "GET", "/websites"]))
n = 0
for s in sites:
    if s["app_type"] not in ("php", "wordpress"):
        continue
    root = os.path.join(s["root_path"], s["document_root"])
    if s["nginx_rewrite_mode"] == "laravel":
        root = os.path.join(root, "public")
    os.makedirs(root, exist_ok=True)
    p = os.path.join(root, "snptest.php")
    shutil.copy("/root/cl0/snptest.php", p)
    u = pwd.getpwnam(s["linux_user"])
    os.chown(p, u.pw_uid, u.pw_gid)
    os.chown(root, u.pw_uid, u.pw_gid)
    os.chmod(p, 0o644)
    n += 1
print(f"probe in {n} sites")
