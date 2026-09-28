# CL-0 prototype

Scripts used by hand during the CloudLinux + Apache/LSPHP + LiteSpeed trial
(`../CL-0-REPORT.md`). They are **reference material for the Rust
implementation, not product code**: they call the panel through a local
`/root/api.sh` helper (login + `curl`), assume the trial's paths, and are
written in shell/Python for speed of iteration.

| File | What it stands in for |
|---|---|
| `gen_apache.py` | the Apache renderer in `snpanel-web` (vhosts with literal ports, `SetHandler application/x-httpd-lsphp`) |
| `00-snpanel.conf`, `00-snpanel-tools.vhost` | global Apache config and the default vhost (ACME + phpMyAdmin as `snpanel-pma`) |
| `selector_setup.py` | stage S7: CageFS per user, Selector per user, Isolates + Selector per domain |
| `snpanel-cpapi`, `cpapi_snapshot.py`, `integration.ini`, `snpanel-cagefs.cfg` | the CloudLinux vendors integration (`snpanel-cpapi` binary + snapshot the panel writes) |
| `snpanel-webswitch`, `snpanel-webwatch`, `units.sh` | `snpanel web switch`, `snpanel-webwatch.service`, and keeping the nft redirect across reboots and firewall reloads |
| `probe.py`, `show.py`, `outage.py`, `put_probe.py`, `snptest.php` | the behaviour comparison used at every stage (147 requests, 21 hosts) and the downtime measurement |
