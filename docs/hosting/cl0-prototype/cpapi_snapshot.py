#!/usr/bin/env python3
"""Write /var/lib/snpanel-cpapi/data.json from the panel's API (CL-0 prototype).

In the product this is the panel's own job, done on every change to users,
sites, aliases or packages. Nothing secret goes in: it is mounted into CageFS.
"""
import json
import os
import pwd
import subprocess


def api(path):
    return json.loads(subprocess.check_output(["/root/api.sh", "GET", path]))


users = api("/users")
sites = api("/websites")
packages = api("/packages")
by_owner = {}
domains = {}
for s in sites:
    first = s["linux_user"] not in by_owner
    by_owner.setdefault(s["linux_user"], s["domain"])
    docroot = os.path.join(s["root_path"], s["document_root"])
    if s["nginx_rewrite_mode"] == "laravel":
        docroot = os.path.join(docroot, "public")
    domains[s["domain"]] = {"owner": s["linux_user"], "document_root": docroot,
                            "is_main": first, "php_version": s["php_version"]}
    for a in s.get("aliases", []):
        domains[a["domain"]] = {"owner": s["linux_user"], "document_root": docroot,
                                "is_main": False, "php_version": s["php_version"]}
cl_users = []
for u in users:
    if u["role"] == "admin":
        continue
    try:
        uid = pwd.getpwnam(u["username"]).pw_uid
    except KeyError:
        continue
    cl_users.append({
        "id": uid, "username": u["username"], "owner": "admin",
        "domain": by_owner.get(u["username"], ""),
        "package": {"name": u["package_name"], "owner": "admin"} if u.get("package_name") else None,
        "email": u["email"], "locale_code": "EN_us",
    })
snap = {
    "version": open("/opt/snpanel/VERSION").read().strip(),
    "login_url": os.environ.get("SNPANEL_PANEL_URL", "https://panel.example.com:2222/"),
    "admin_email": next((u["email"] for u in users if u["role"] == "admin"), None),
    "users": cl_users,
    "domains": domains,
    "packages": [p["name"] for p in packages],
    "php_versions": ["81", "82", "83", "84", "85"],
}
os.makedirs("/var/lib/snpanel-cpapi", exist_ok=True)
os.chmod("/var/lib/snpanel-cpapi", 0o755)
tmp = "/var/lib/snpanel-cpapi/data.json.tmp"
with open(tmp, "w") as f:
    json.dump(snap, f, indent=1)
os.chmod(tmp, 0o644)
os.replace(tmp, "/var/lib/snpanel-cpapi/data.json")
print(f"{len(cl_users)} users, {len(domains)} domains")
