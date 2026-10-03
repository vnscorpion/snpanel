# Kế hoạch: giới hạn CPU / RAM / tiến trình / IO cho từng người dùng

Trạng thái: bản thảo để triển khai, chưa có dòng code nào.
Phạm vi: Ubuntu 24.04, Debian 12/13, AlmaLinux 10 (cgroup v2 + systemd).
Điều kiện thuận lợi: SNPanel chưa cài trên VPS nào, nên **không cần đường
nâng cấp dữ liệu cũ**. Mọi thứ dưới đây là thiết kế cho bản cài mới; mục 11
chỉ ghi lại việc phải làm nếu sau này có máy cũ cần chuyển.

Mục tiêu một câu: mỗi tài khoản panel là một `user-<uid>.slice` của systemd,
mọi tiến trình của họ (PHP-FPM, cron, SFTP, terminal, WP-CLI, app Node) nằm
trong slice đó, panel ghi giới hạn vào slice và đọc mức dùng từ cgroup.

---

## 1. Hiện trạng liên quan (đã khảo sát trong code)

| Thành phần | Hiện tại | Hệ quả cho tính năng |
|---|---|---|
| PHP-FPM | Một master root cho mỗi phiên bản PHP (`php8.4-fpm.service`, trên EL là alias của `php84-php-fpm`). Pool `snpanel-<user>-<hash>-<ver>` của **mọi** user nằm chung trong master đó (`crates/snpanel-helper/src/ops/php.rs:430-572`). | Worker của user nằm trong `system.slice/php8.4-fpm.service`, giới hạn trên slice user không chạm tới web request. Phải tách master theo user. |
| Socket | `/run/php/snpanel-<user>-<hash>-<ver>.sock`, tên được tính ở 4 chỗ (API websites.rs:841, 4174; maintenance.rs:6341; helper php.rs:444). | Giữ nguyên đường dẫn socket thì nginx và 4 chỗ này **không phải sửa**. |
| Lệnh chạy thay user | `runuser -u <user> --` từ helper cho terminal, WP-CLI, giải nén (terminal.rs:374, site.rs:886, 570). PAM của `runuser` không có `pam_systemd`. | Tiến trình nằm trong cgroup của `snpanel-helper.service`. Cần bọc bằng `systemd-run --scope --slice=`. |
| Cron | crontab thường, ghi qua `runuser -u <user> -- crontab -` (misc.rs:197-230). | Trên EL job cron vào `user-<uid>.slice` nhờ `pam_systemd` trong `password-auth`. Trên Debian `/etc/pam.d/cron` dùng `common-session-noninteractive`, **không** có `pam_systemd`, phải thêm. |
| SSH/SFTP | `Match Group snpanel-sftp` chroot, qua sshd + PAM. | Tự vào `user-<uid>.slice`, không phải làm gì. |
| App Node/Docker | Unit riêng `snpanel-app-<user>-<app>.service` có `MemoryMax`, `TasksMax` (siteapp.rs:703-768). | Thêm `Slice=` là xong; Docker cần `--cgroup-parent`. |
| Gói dịch vụ | Bảng `user_packages`, giới hạn copy sang cột trên `users` khi gán gói (`PackageRepo::update` cascade). | Quy tắc C12 (`schema.rs:19-25`) cấm `ALTER TABLE`, cột mới phải ở **bảng phụ**. |
| Dashboard | `/api/services/resource-usage` đọc `/proc` toàn máy; không có số liệu theo user. | Thêm reader cgroup theo user. |
| Hardening | `snpanel-api.service` và `snpanel-helper.service` đều `ProtectControlGroups=true`. | `/sys/fs/cgroup` chỉ đọc: **đọc** số liệu được, **ghi** phải qua systemd (`systemctl`, D-Bus), không ghi file trực tiếp. Đúng với thiết kế bên dưới. |
| Tài liệu osabi | `Platform` có `php_service`, `php_fpm_pool_dir`, `php_binary` nhưng **chưa có đường dẫn binary `php-fpm`**. Nhiều chỗ helper vẫn hardcode `/etc/php/<v>/fpm` và `php<v>-fpm`, EL chạy được nhờ symlink shim. | Thêm `php_fpm_binary()`; master theo user dùng osabi, không dựa vào shim. |

Tương ứng với CloudLinux LVE:

| CloudLinux | systemd / cgroup v2 | Ghi chú |
|---|---|---|
| SPEED | `CPUQuota=` trên slice (`cpu.max`) | 100% = 1 core |
| PMEM | `MemoryMax=` + `MemoryHigh=` (`memory.max`, `memory.high`) | VMEM không có tương đương, bỏ |
| NPROC | `TasksMax=` (`pids.max`) | |
| IO | `IOReadBandwidthMax=` / `IOWriteBandwidthMax=` (`io.max`) | tuỳ chọn, phụ thuộc block device |
| IOPS | `IO*IOPSMax=` | không làm ở đợt này |
| EP | `process.max` trong `php-fpm.conf` của master riêng từng user | không phải khái niệm cgroup |
| CageFS | `ProtectHome=tmpfs` + `BindPaths=/home/<user>`, `PrivateTmp` trên unit FPM | "CageFS-lite", chỉ cho FPM |
| lveinfo | đọc `cpu.stat`, `memory.current`, `memory.peak`, `memory.events`, `pids.current`, `io.stat` | |

---

## 2. Quyết định thiết kế

### 2.1 Dùng `user-<uid>.slice` của logind, không tạo cây slice riêng

Hai lựa chọn:

- **A. `user-<uid>.slice`** (chọn). SSH/SFTP, cron (sau khi sửa PAM trên
  Debian) tự vào đây nhờ `pam_systemd`. Panel chỉ cần đưa thêm FPM, app Node
  và lệnh helper vào. Một ngân sách duy nhất cho mỗi user.
- B. `snpanel-<user>.slice` riêng. Template unit gọn hơn (`Slice=snpanel-%i.slice`)
  nhưng SSH/SFTP/cron vẫn nằm ở `user-<uid>.slice`, user có hai ngân sách và
  giới hạn phải ghi hai nơi. Loại.

Giá phải trả của A: `Slice=` trong unit cần **uid**, không template theo tên
được. Chấp nhận: helper sinh **một unit đầy đủ cho mỗi cặp (user, phiên bản
PHP)**, giống cách đã làm cho app Node.

### 2.2 Một master PHP-FPM cho mỗi cặp (user, phiên bản PHP)

- Unit: `/etc/systemd/system/snpanel-php-fpm-<user>-<ver>.service`
  (ví dụ `snpanel-php-fpm-alice-8.4.service`).
- Cấu hình: `/etc/snpanel/php-fpm/<user>/<ver>/php-fpm.conf` và
  `/etc/snpanel/php-fpm/<user>/<ver>/pool.d/<pool>.conf`.
- Master chạy **root** như master của distro, pool vẫn `user = <user>`, worker
  setuid. Lý do: giữ nguyên `/run/php/*.sock`, `listen.owner = www-data`, và
  4 chỗ tính tên socket; chạy master bằng chính user sẽ kéo theo đổi thư mục
  socket, `RuntimeDirectory`, ACL và nhiều chỗ sửa hơn. Có thể đổi sau, không
  ảnh hưởng API.
- `php.ini` và các drop-in `95-snpanel-tune.ini`, `99-snpanel.ini` theo
  phiên bản **vẫn có hiệu lực**, vì binary `php-fpm` tự tìm `php.ini` theo
  đường dẫn biên dịch của SAPI fpm (Debian `/etc/php/8.4/fpm/`, Remi
  `/etc/opt/remi/php84/`). Không sửa code tune ini.
- Master distro (`php8.4-fpm.service`) **vẫn giữ**, chỉ còn pool `www` cho
  phpMyAdmin, tools vhost và socket fallback. Không còn pool `snpanel-*` nào
  trong đó.
- Master rỗng (user đổi phiên bản PHP, xoá site cuối) được dọn: stop, disable,
  xoá unit và thư mục cấu hình. Đồng thời sửa `apply_php_version` để xoá pool
  phiên bản cũ (hiện bị bỏ sót, websites.rs:5077).

Unit sinh ra (hàm `fpm_unit_body`, kiểm thử bằng file directive như
`ops/node-unit-directives.txt`):

```ini
[Unit]
Description=SNPanel PHP-FPM 8.4 for alice
After=network.target
# master của user không được giữ máy khởi động lại nếu lỗi cấu hình
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=notify
ExecStart=/usr/sbin/php-fpm8.4 --nodaemonize --fpm-config /etc/snpanel/php-fpm/alice/8.4/php-fpm.conf
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure
RestartSec=2
Slice=user-1001.slice
# một worker bị OOM-kill thì chỉ worker đó chết, master vẫn sống
OOMPolicy=continue
OOMScoreAdjust=-500
StandardOutput=journal
StandardError=journal
SyslogIdentifier=snpanel-php-fpm-alice-8.4
# CageFS-lite: FPM chỉ thấy home của chính user
PrivateTmp=yes
ProtectSystem=full
ProtectHome=tmpfs
BindPaths=/home/alice
ReadWritePaths=/var/lib/php/sessions/alice /var/lib/php/uploads/alice /run/php
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
```

`php-fpm.conf` của master:

```ini
[global]
error_log = /proc/self/fd/2
process_control_timeout = 10
; EP: tổng số worker của user này, trên mọi pool
process.max = 20
include = /etc/snpanel/php-fpm/alice/8.4/pool.d/*.conf
```

Pool giữ nguyên template hiện tại (`pool_body`), chỉ đổi thư mục ghi.
`OOMScoreAdjust=-500` áp cho master; worker kế thừa nhưng kernel OOM trong
cgroup vẫn chọn tiến trình RSS lớn nhất, tức là một worker. Mục 12 ghi việc
phải đo lại điều này.

### 2.3 Giới hạn ghi bằng `systemctl set-property`, không ghi file cgroup

Helper gọi:

```
systemctl set-property user-1001.slice \
  CPUQuota=100% MemoryHigh=921M MemoryMax=1024M TasksMax=100 \
  IOReadBandwidthMax="/home 20M" IOWriteBandwidthMax="/home 20M"
```

- Có hiệu lực ngay cho slice đang chạy, và được ghi bền vào
  `/etc/systemd/system.control/user-1001.slice.d/`. Không cần `daemon-reload`.
- Bỏ giới hạn: giá trị `infinity`. Xoá user: `systemctl revert user-1001.slice`
  **trước** `userdel` (còn cần uid), tránh uid tái sử dụng kế thừa giới hạn cũ.
- `MemoryHigh` = 90% `MemoryMax` để kernel reclaim và làm chậm trước khi
  kill.
- `IO*BandwidthMax` nhận đường dẫn bất kỳ trong filesystem, systemd tự tìm
  block device; dùng `/home`. Trong nspawn và một số VPS không có io
  controller: helper thử, lỗi thì bỏ qua phần IO và ghi cảnh báo, không fail
  cả thao tác.

### 2.4 Lệnh của helper chạy thay user vào đúng slice

Bọc mọi `runuser -u <user> --` bằng:

```
systemd-run --scope --quiet --slice=user-1001.slice --unit=snpanel-<verb>-<pid> -- runuser -u alice -- <lệnh>
```

- `--scope`: tiến trình vẫn là con của helper, stdin/stdout/exit code đi
  thẳng như cũ; chỉ cgroup được chuyển. Nhẹ hơn mở phiên PAM.
- Áp dụng cho: `terminal-exec`, `wp-site`, `site-archive-extract`. `wp`
  (chạy thay web user, không phải user panel) giữ nguyên.
- Dùng thẳng được dù helper có `ProtectControlGroups=true`, vì PID 1 là bên
  ghi cgroup.

### 2.5 Mô hình dữ liệu: bảng phụ, `NULL` = không giới hạn

Năm trường, cùng tên ở gói và ở user:

| Trường | Ánh xạ | Mặc định gói mới | Khoảng hợp lệ |
|---|---|---|---|
| `cpu_percent` | `CPUQuota` | 100 | 10..6400 hoặc null |
| `memory_mb` | `MemoryMax` (+`MemoryHigh`) | 1024 | 128..1048576 hoặc null |
| `process_limit` | `TasksMax` | 100 | 10..65536 hoặc null |
| `io_mbps` | `IORead/WriteBandwidthMax` | null | 1..10000 hoặc null |
| `entry_processes` | `process.max` của mọi master FPM của user | 20 | 1..1000 hoặc null |

Khác với `storage_limit_mb` (0 là giới hạn thật), ở đây `null` là không giới
hạn; không dùng số 0 làm giá trị đặc biệt.

Thứ tự phân giải cho một user: `user_resource_limits` (tuỳ chỉnh) →
`package_resource_limits` của gói → `DEFAULT_LIMITS` trong Rust. Tài khoản
**admin** không bị giới hạn (giống hạn mức dung lượng hiện nay): helper được
gọi `user-limits-clear`.

Migration `rust_0012_resource_limits` (tuân C12: chỉ `CREATE TABLE IF NOT
EXISTS`, thêm vào danh sách bảng trong test
`the_rust_migrations_leave_every_python_table_as_it_was`):

```sql
CREATE TABLE IF NOT EXISTS package_resource_limits (
  package_id      INTEGER PRIMARY KEY REFERENCES user_packages(id) ON DELETE CASCADE,
  cpu_percent     INTEGER,
  memory_mb       INTEGER,
  process_limit   INTEGER,
  io_mbps         INTEGER,
  entry_processes INTEGER,
  updated_at      DATETIME
);
CREATE TABLE IF NOT EXISTS user_resource_limits (
  user_id         INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  username        VARCHAR(32) NOT NULL,
  cpu_percent     INTEGER,
  memory_mb       INTEGER,
  process_limit   INTEGER,
  io_mbps         INTEGER,
  entry_processes INTEGER,
  updated_at      DATETIME
);
```

`username` lưu kèm vì SQLite tái dùng id đã xoá (cùng lý do với
`sftp_accounts`). Tạo gói luôn tạo kèm một hàng `package_resource_limits`
trong cùng transaction, nên "gói không có hàng" không xảy ra với gói mới.

### 2.6 Khi nào áp giới hạn xuống OS

| Sự kiện | Hành động API |
|---|---|
| Tạo user | sau `panel-user-ensure`: `user-limits-apply <user>` với giới hạn đã phân giải |
| Sửa user (đổi gói, đổi role, bật/tắt tuỳ chỉnh) | phân giải lại, `user-limits-apply` hoặc `user-limits-clear` |
| Sửa gói | với mọi user của gói **không** có hàng tuỳ chỉnh: `user-limits-apply` (vòng lặp ở API, từng user, lỗi ghi log và trả danh sách user chưa áp được) |
| Provisioning `ChangePackage`, `CreateAccount` | như sửa user |
| Xoá user | `panel-user-delete` tự `revert` slice và xoá master FPM |
| Tạo site / đổi PHP / chuyển chủ | `site-runtime-ensure|move` ghi `process.max` từ giới hạn hiện tại (truyền qua stdin JSON) |
| Suspend | tuỳ chọn: stop các master FPM của user để trả RAM. Không bắt buộc ở đợt này |

Giới hạn hiệu lực được áp lại toàn bộ khi `snpanel-api` khởi động? **Không.**
`system.control` là bền qua reboot, không cần. Thêm lệnh CLI
`snpanel limits resync` cho vận hành thủ công.

### 2.7 Đọc mức dùng

API (user `snpanel`) đọc trực tiếp, không qua helper:

```
/sys/fs/cgroup/user.slice/user-<uid>.slice/
  cpu.stat         usage_usec, nr_throttled, throttled_usec
  cpu.max          "quota period" hoặc "max"
  memory.current   memory.peak   memory.max
  memory.events    oom_kill
  pids.current     pids.max
  io.stat          rbytes wbytes (cộng mọi device)
```

- uid lấy bằng `getpwnam_r` (API đã link `libc`).
- Thư mục không tồn tại = user không có tiến trình nào, trả 0.
- CPU % = chênh lệch `usage_usec` giữa hai lần đọc cách 200 ms, cùng cách
  `system::resource_usage` làm với `/proc/stat`. Với danh sách user, đọc tất
  cả một lượt, ngủ 200 ms, đọc lại.

---

## 3. Thay đổi ở installer (`installer/`, `crates/snpanel-installer`)

1. **Preflight cgroup v2** trong `detect_platform` (platform.sh) và
   `snpanel_osabi::detect`: yêu cầu `/sys/fs/cgroup/cgroup.controllers` có
   `cpu memory pids`. Thiếu (OpenVZ, LXC không delegate) thì dừng với thông
   báo rõ; biến `SNPANEL_RESOURCE_LIMITS=off` cho phép cài tiếp ở chế độ
   không giới hạn, ghi `RESOURCE_LIMITS=off` vào `/opt/snpanel/backend/.env`
   để API ẩn tính năng và báo trên dashboard.
2. **Drop-in mặc định cho mọi user slice**, viết bởi
   `snpanel-install systemd-units` (thêm vào `systemd_units.rs`, có fixture
   golden):

   ```ini
   # /etc/systemd/system/user-.slice.d/50-snpanel.conf
   [Slice]
   CPUAccounting=yes
   MemoryAccounting=yes
   TasksAccounting=yes
   IOAccounting=yes
   ```
   Chỉ bật kế toán; giới hạn thật luôn đi theo từng user ở `system.control`.
3. **PAM cho cron trên Debian/Ubuntu**: thêm
   `session optional pam_systemd.so` vào `/etc/pam.d/cron` (idempotent,
   thêm sau dòng `@include common-session-noninteractive`). Trên EL kiểm tra
   `/etc/pam.d/crond` đã kéo `pam_systemd` qua `password-auth`; nếu không thì
   thêm tương tự. Việc này ở phase `setup_panel_user`, dưới dạng
   `snpanel-install pam-cron` để test được bằng golden.
4. **Thư mục**: `/etc/snpanel/php-fpm` (`root:root 0755`), ghi trong
   `setup_backend`. `/run/php` giữ nguyên tmpfiles hiện có.
5. **osabi**: thêm `php_fpm_binary(ver)` (Debian `/usr/sbin/php-fpm8.4`, EL
   `/opt/remi/php84/root/usr/sbin/php-fpm`), thêm cột tương ứng vào
   `platform.sh` và `tests/golden/platform_table.json` (test
   `the_shell_installers_table_agrees_with_this_one` bắt buộc).
6. `install_php` **không đổi**: master distro vẫn cài, enable, và `www.conf`
   vẫn qua `snpanel-install php-fpm-pool`.
7. `php-install` lúc chạy (helper `packages::php_install`): sau khi cài
   phiên bản mới không cần tạo master user nào; master được tạo khi site đầu
   tiên dùng phiên bản đó.
8. **Smoke test CI** (`ci.yml`, job `install-smoke-test`), sau bước tạo site:
   - `systemctl is-active snpanel-php-fpm-<user>-8.4`
   - worker nằm đúng chỗ: `grep -q user-<uid>.slice /proc/<pid worker>/cgroup`
   - `cat /sys/fs/cgroup/user.slice/user-<uid>.slice/cpu.max` khớp gói mặc định
   - `curl` site vẫn trả 200 (socket không đổi).
9. `tools/os-check` (nspawn, đủ systemd, chạy trên cả 3 OS): thêm các kiểm
   tra trên vào `xtask acceptance`, trừ IO (nspawn không có block device).

---

## 4. Thay đổi ở helper và IPC

### 4.1 Verb mới (`crates/snpanel-ipc`)

| Verb | Tham số | stdin | Lock | Việc làm |
|---|---|---|---|---|
| `user-limits-apply` | `<user>` | JSON `{cpu_percent, memory_mb, process_limit, io_mbps, entry_processes}` (null cho phép) | Accounts, Systemd, Php | `id -u`; `systemctl set-property user-<uid>.slice ...`; ghi lại `process.max` trong mọi `/etc/snpanel/php-fpm/<user>/*/php-fpm.conf` rồi `reload` các master |
| `user-limits-clear` | `<user>` | – | Accounts, Systemd, Php | `systemctl revert user-<uid>.slice`; `process.max = 0` |
| `user-fpm-list` | `<user>` | – | – | trả `[{php_version, unit, active}]`, cho trang Services và dọn rác |

Checklist bắt buộc cho mỗi verb (test đang ép): variant + `op_name` trong
`ipc/lib.rs`; arm `from_argv` trong `ipc/argv.rs`; arm `dispatch` trong
`helper/ops/mod.rs`; `locks::placed`; `ANSWERED_VERBS` và help text trong
`helper/main.rs`; nơi gọi trong API (test
`every_verb_the_panel_asks_for_is_one_the_helper_answers`). `PROTOCOL_VERSION`
tăng lên 2 vì `site-runtime-ensure|move` nhận thêm payload (mục 4.3).

### 4.2 Module mới `helper/ops/limits.rs`

- `apply(user, Limits)`: dựng argv `set-property` từ struct, `null` →
  `infinity`; chạy thử IO riêng một lệnh, lỗi thì bỏ qua và trả
  `data.io_applied=false`.
- `clear(user)`.
- Kiểm thử thuần: `set_property_argv(limits)` với bảng giá trị, có golden.

### 4.3 Tách master FPM theo user (`helper/ops/php.rs`, module mới `ops/fpm.rs`)

- `fpm::ensure_master(user, ver, entry_processes)`: tạo thư mục cấu hình,
  ghi `php-fpm.conf`, ghi unit (atomic, so sánh nội dung, chỉ `daemon-reload`
  khi đổi), `enable --now` hoặc `reload`.
- `fpm::remove_master(user, ver)`: stop, disable, xoá unit, xoá thư mục.
- `fpm::units_for_version(ver)`: glob `snpanel-php-fpm-*-<ver>.service`.
- `fpm::unit_body(...)` + file `ops/php-fpm-unit-directives.txt` + test như
  `node_unit_body`.
- `ensure_site_pool`: ghi vào `/etc/snpanel/php-fpm/<user>/<ver>/pool.d/`,
  gọi `ensure_master`, reload master của user thay vì `php<v>-fpm`.
- `delete_site_pools`, `remove_php_pools` (xoá user), `runtime_move`: đọc
  thư mục mới; sau khi xoá pool, master rỗng thì `remove_master`.
- `pools_retune`, `php-pools-retune`: duyệt `/etc/snpanel/php-fpm/*/*/pool.d`
  và reload từng master. `pool_count` đếm ở đó.
- `pool_tuning`: thêm chặn trên theo RAM của user:
  `children ≤ max(2, floor(memory_mb × 0.75 / worker_mb))`. Server-wide
  formula hiện tại vẫn là chặn trên thứ hai.
- `site-runtime-ensure|move` nhận thêm JSON stdin `{entry_processes,
  memory_mb}` để ghi `process.max` và tính `pm.max_children` đúng ngay lần
  đầu. Không có stdin → mặc định (giữ tương thích với CLI).
- Mọi chỗ restart/reload theo phiên bản sau khi đổi cấu hình phải thêm vòng
  lặp qua `units_for_version(ver)`: `php-config-write` (restart),
  `php-ext-install|remove` (restart), `php-opcache-set` (reload),
  `php-tune-write` (reload), `php-pools-retune` (reload).
- Bỏ hardcode `/etc/php/<v>/fpm` ở các hàm trên; lấy từ `Platform`.

### 4.4 `user.rs`

- `delete`: thứ tự mới: `sftp_sub::delete_all` → `fpm::remove_master` cho
  mọi phiên bản → `limits::clear` (còn uid) → `crontab -r` → `pkill` →
  `userdel` → xoá thư mục cũ và `/etc/snpanel/php-fpm/<user>`.
- `ensure`: không đổi (giới hạn do API gọi riêng ngay sau).

### 4.5 `exec.rs`

- `run_in_user_slice(user, argv, ...)`: tiền tố
  `systemd-run --scope --quiet --slice=user-<uid>.slice --`; dùng ở
  `terminal::run_as`, `site::wp_argv` (nhánh `wp-site`), giải nén. Nếu
  `RESOURCE_LIMITS=off` thì chạy như cũ.

### 4.6 `siteapp.rs`

- `node_unit_body`: thêm `Slice=user-<uid>.slice` (thêm vào file directive).
- Docker: thêm `--cgroup-parent=user-<uid>.slice` khi daemon dùng cgroup
  driver `systemd` (đọc `docker info --format '{{.CgroupDriver}}'`); ngược
  lại giữ `--memory/--cpus` như hiện tại và ghi chú trong UI.

---

## 5. Thay đổi ở DB (`crates/snpanel-db`)

- `schema.rs`: `rust_0012_resource_limits` + cập nhật danh sách bảng trong
  test.
- Module mới `resource_limits.rs`: struct `ResourceLimits { cpu_percent:
  Option<i64>, memory_mb, process_limit, io_mbps, entry_processes }`,
  `ResourceLimitsRepo` với `package_get/set`, `user_get/set/clear`,
  `users_without_override(package_id)`.
- `packages.rs::create` nhận `ResourceLimits` và ghi hàng phụ cùng transaction;
  `update` không cascade (API tự áp, vì cần gọi helper).
- Expose qua `Database::resource_limits()` (`lib.rs`).

---

## 6. Thay đổi ở API (`crates/snpanel-api`)

### 6.1 Module mới

- `resource_limits.rs`: `DEFAULT_LIMITS`, `resolve(user, package) ->
  Effective { limits, source: Custom|Package|Default|Unlimited }`,
  `validate(json) -> Result<ResourceLimits>` (bảng khoảng hợp lệ ở 2.5),
  `apply_for_user(state, user)` (gọi helper), `apply_for_package(state, pkg)`.
- `cgroup_usage.rs`: `read(uid) -> Usage`, `sample_many(uids) ->
  Vec<Usage>`; JSON:

  ```json
  {"cpu":{"percent":12.5,"limit_percent":100,"throttled_percent":0.0},
   "memory":{"bytes":187000000,"peak_bytes":401000000,"limit_bytes":1073741824,"percent":17.4,"oom_kills":0},
   "processes":{"current":7,"limit":100},
   "io":{"read_bytes":0,"write_bytes":0}}
  ```

### 6.2 Routes

| Route | Thay đổi |
|---|---|
| `GET/POST/PATCH /packages` | thêm 5 trường phẳng; `INTS` không dùng được vì cần null, thêm bảng `NULLABLE_INTS` cùng kiểu; PATCH xong gọi `apply_for_package` và trả `limits_applied: {ok: n, failed: [username]}` |
| `POST/PATCH /users` | thêm `limits: {...} \| null` (null = theo gói); áp sau khi ghi DB |
| `user_out` | thêm `limits`, `limits_source`, `resources` (usage, chỉ khi `?usage=1`) |
| `GET /users/{id}/usage` | thêm `resources` |
| `GET /users/resources` (admin) | usage của mọi user một lượt, cho bảng Users và dashboard |
| `GET /auth/session` | thêm `limits` và `resources` của chính user |
| `provisioning` `change_package`, `create_account` | gọi `apply_for_user`; `/plans` **không** thêm trường (hợp đồng ngoài, giống node_*) |
| `GET /dashboard/summary` | admin: `resources: {users_over_80: [...], oom_last_24h: n}`; customer: `resources` của mình |
| `GET /services/...` | `stopped_services()` thêm các unit `snpanel-php-fpm-*` không active |

### 6.3 Notify

- Kind mới `resource_limit` (group `accounts`, `default_on: true`).
- Watcher mỗi 5 phút: với mỗi user có giới hạn, so `oom_kill` với lần trước
  trong `Memo` (`oom_seen: HashMap<user_id, u64>`), và CPU throttled ≥ 50%
  thời gian trong cửa sổ. Báo một lần, xoá cờ khi về dưới ngưỡng (hysteresis
  như `storage_told`).
- Nội dung song ngữ `Text::new(en, vi)`, trang đích `/users`.

### 6.4 MCP

- `whoami`, `list_users`: thêm `limits` và `resources`.
- Tool mới chỉ đọc `user_resources` (admin: user bất kỳ; end user: chính
  mình). Cập nhật `vi-mcp.js` qua `scripts/mcp-texts.mjs`.

### 6.5 Dev fallback

`command_dry_run` và `SNPANEL_USE_HELPER` chưa bật: `apply_for_user` ghi log
và trả ok, để `testenv::panel` chạy được.

---

## 7. Frontend (`frontend/src`)

- `pages/Users.jsx`, tab Packages: thêm nhóm "Resource limits" với 5 ô, ô
  trống = không giới hạn, gợi ý đơn vị (`% of one core`, `MB`, `processes`,
  `MB/s`, `PHP workers`).
- Form user: khi chọn gói, hiện giới hạn của gói ở dạng chỉ đọc; checkbox
  "Custom resource limits" mở 5 ô.
- Bảng Users: cột CPU, RAM, Procs với thanh `ResourceCard`-style
  (warn ≥ 75 %, bad ≥ 90 %), dữ liệu từ `GET /users/resources`, poll 5 s
  khi đang ở trang.
- `pages/Dashboard.jsx`: customer "Package usage" thêm 3 ô CPU, RAM, Processes;
  admin thêm card "Resources" (tone bad khi có user bị OOM 24 h qua, warn khi
  có user ≥ 80 %), attention list dẫn tới `/users`.
- `pages/Notifications.jsx`: nhãn cho `resource_limit`.
- Banner khi `RESOURCE_LIMITS=off` (đọc từ `/auth/session` hoặc
  `/dashboard/summary`): "Máy chủ này không hỗ trợ giới hạn tài nguyên".
- i18n: `vi.js` cho UI, `vi-server.js` tự thu từ Rust bằng
  `scripts/server-messages.mjs`; `npm run i18n:check` phải xanh.

---

## 8. CLI (`crates/snpanel-cli`)

- `snpanel limits show <user>`: in giới hạn hiệu lực và mức dùng (đọc cgroup).
- `snpanel limits resync`: áp lại cho mọi user từ DB (sau khi khôi phục máy
  từ backup hoặc đổi tay).
- `snpanel doctor`: kiểm tra cgroup v2, `pam_systemd` trong cron, số master
  FPM của user đang `failed`.

---

## 9. Kiểm thử

**Rust (unit, trong file):**
- `ipc`: `from_argv` cho 3 verb mới; `op_name`; đếm `ANSWERED_VERBS`.
- `helper/ops/limits.rs`: `set_property_argv` (null → infinity, MemoryHigh
  90 %, IO tách riêng).
- `helper/ops/fpm.rs`: `unit_body` khớp file directive; `php-fpm.conf` có
  `process.max`; tên unit hợp lệ với mọi username hợp lệ
  (`^[a-z_][a-z0-9_-]{2,31}$`) và mọi `PhpVersion`.
- `helper/ops/php.rs`: `pool_tuning` với chặn trên RAM user; đường dẫn pool
  mới; `pool_count` đếm thư mục mới.
- `helper/locks.rs`: `every_operation_is_placed`.
- `db`: migration chỉ thêm; repo get/set/clear; cascade `ON DELETE`.
- `api/resource_limits.rs`: `resolve` theo 4 nguồn; `validate` biên và null;
  admin → Unlimited.
- `api/cgroup_usage.rs`: parse `cpu.stat`, `memory.events`, `io.stat`,
  `cpu.max` ("max" và "100000 100000") từ fixture thư mục tạm.
- `routes/packages.rs`: serialise có đủ 5 khoá; PATCH null xoá giới hạn.
- `routes/users.rs`: tạo user với `limits` gọi đúng verb (dry-run ghi lại
  argv); đổi gói áp lại.
- `notify/watcher.rs`: `oom_seen` hysteresis.
- `installer/systemd_units.rs`: golden cho `user-.slice.d/50-snpanel.conf`;
  `pam-cron` idempotent trên fixture Debian và EL.

**Tích hợp:**
- `ci.yml` smoke test: các bước ở mục 3.8.
- `tools/os-check` trên `ub24t`, `deb13t`, `alma10t`: tạo user với gói
  `memory_mb=256`, chạy một script PHP cấp phát 400 MB qua curl → nhận 502,
  `memory.events oom_kill` tăng 1, master FPM vẫn active, user khác không
  ảnh hưởng; đổi gói `cpu_percent=50` → `cpu.max` đổi ngay không reload;
  xoá user → `system.control/user-<uid>.slice.d` biến mất.
- `tools/ui-audit/users.mjs`, `dashboard.mjs`, `dashboard-enduser.mjs`: cột
  và ô mới hiển thị, tone đúng.

---

## 10. Trình tự thực hiện

| Phase | Nội dung | Kết quả nghiệm thu | Ước lượng |
|---|---|---|---|
| 0. Xác minh | Trên `alma10t` và `ub24t` (nspawn) kiểm tra 6 giả định ở mục 12 bằng tay, ghi kết quả vào cuối tài liệu này | Bảng giả định có cột "đã xác minh" | 0.5 ngày |
| 1. Nền | osabi `php_fpm_binary`; installer preflight, `user-.slice.d`, `pam-cron`, thư mục; `.env RESOURCE_LIMITS` | Cài mới xanh trên 3 OS, chưa đổi hành vi | 1 ngày |
| 2. Master FPM theo user | `ops/fpm.rs`, sửa `php.rs`, `site.rs`, `user.rs`, các verb reload/restart theo phiên bản, dọn master rỗng, sửa `apply_php_version` | Tạo site → unit riêng, worker trong `user-<uid>.slice`, site chạy, đổi PHP không để lại pool cũ, xoá user sạch | 3 ngày |
| 3. Giới hạn | DB, IPC verbs, `limits.rs`, API packages/users/provisioning, cascade | Đổi gói → `cpu.max` đổi ngay; OOM test ở mục 9 đạt | 3 ngày |
| 4. Slice cho phần còn lại | `systemd-run --scope` cho terminal/WP-CLI/extract, `Slice=` cho app Node, Docker `--cgroup-parent` | `terminal-exec` của user nằm trong slice user | 1 ngày |
| 5. Hiển thị và cảnh báo | `cgroup_usage.rs`, routes usage, dashboard, bảng Users, notify, MCP, i18n | Dashboard customer có CPU/RAM; admin nhận Telegram khi user bị OOM | 3 ngày |
| 6. CLI, doctor, tài liệu | `snpanel limits`, `doctor`, README en/vi, mục "Tài khoản" | `npm run i18n:check`, `cargo test`, smoke test xanh | 1 ngày |

Phase 2 và 3 độc lập về code nhưng phase 3 chỉ có ý nghĩa khi phase 2 xong;
làm tuần tự. Mỗi phase một PR.

---

## 11. Nếu sau này có máy đã cài bản cũ

Không cần cho hiện tại. Ghi lại để `update.sh` không bị quên:

- Verb một lần `php-pools-migrate`: với mỗi `/etc/php/*/fpm/pool.d/snpanel-*.conf`
  đọc `user`, tạo master theo user, chuyển file pool sang thư mục mới, reload
  master distro để bỏ pool cũ. Socket không đổi nên nginx không cần reload.
- Áp giới hạn mặc định cho mọi user hiện có (`snpanel limits resync`).
- `update.sh` chạy hai việc trên sau `update-units`.

---

## 12. Giả định cần xác minh ở phase 0 và rủi ro

Giả định (chưa chạy thử trong repo này, phải kiểm tra trước khi code phase 2):

1. Service trong `/etc/systemd/system` đặt `Slice=user-1001.slice` khởi động
   và nằm đúng chỗ, và logind không stop slice đó khi phiên SSH cuối đóng
   (slice còn unit active thì phải còn sống).
2. `systemctl set-property user-1001.slice ...` chạy được khi slice **chưa
   từng** được khởi động (user mới tạo, chưa có tiến trình). Nếu không: ghi
   drop-in vào `/etc/systemd/system/user-1001.slice.d/` + `daemon-reload`
   thay thế.
3. `systemd-run --scope --slice=user-1001.slice` từ bên trong
   `snpanel-helper.service` (có `ProtectControlGroups=true`) thành công.
4. `OOMPolicy=continue` giữ master sống khi một worker bị OOM-kill trong
   cgroup của slice (không phải của service).
5. `pam_systemd` trong `/etc/pam.d/cron` (Debian) đưa job cron vào
   `user-<uid>.slice` mà không gây lỗi "Failed to create session" khi logind
   bận; trên EL `crond` đã làm việc này sẵn.
6. Trong nspawn (`tools/os-check`), `cpu`, `memory`, `pids` controller được
   delegate đủ để test; `io` thì không, bỏ qua.

Rủi ro và cách xử lý:

- **RAM mỗi master**: thêm khoảng 20–30 MB RSS cho mỗi cặp (user, phiên bản),
  cộng opcache dùng thực tế của user đó (shared memory được tính vào cgroup
  chạm trang đầu tiên, tức là của user, đúng ý). Dọn master rỗng và cân nhắc
  `opcache.memory_consumption` nhỏ hơn cho master user (64 MB) nếu đo thấy
  cần. Ghi rõ trong README phần yêu cầu RAM.
- **`MemoryMax` quá thấp → 502 liên tục**: `MemoryHigh` 90 % để reclaim
  trước; cảnh báo notify; mặc định gói 1024 MB.
- **uid tái sử dụng**: `revert` trước `userdel`; `doctor` phát hiện thư mục
  `system.control/user-*.slice.d` mồ côi.
- **VPS không có cgroup v2** (OpenVZ 7, một số LXC): preflight từ chối, hoặc
  `SNPANEL_RESOURCE_LIMITS=off` cài không giới hạn, UI báo rõ.
- **IO limit trên LVM/dm hoặc network disk**: áp thử, lỗi thì bỏ qua và báo
  `io_applied=false` trong response để UI hiện ghi chú.
- **systemd khác phiên bản**: Debian 12 (252), Ubuntu 24.04 (255), AlmaLinux
  10 (257). Mọi directive dùng đều có từ 247 trở về trước, trừ `memory.peak`
  cần kernel 6.5 (Debian 12 kernel 6.1 → trả null, UI ẩn).
- **Admin host site**: không giới hạn, nhưng vẫn có master FPM riêng và
  sandbox như mọi user, nên vẫn hưởng cách ly.
