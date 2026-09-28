# SNPanel — Kế hoạch nâng cấp lên CloudLinux và LiteSpeed Enterprise

**Ngày:** 2026-09-28 · **Áp dụng cho:** SNPanel ≥ 1.1.0 · **Tài liệu tham khảo chi tiết:** `CLOUDLINUX_APACHE_LSPHP_UPGRADE_PLAN_v3_SNPANEL.md`

> **Đã cập nhật sau thử nghiệm tay CL-0 (2026-09-28).** Cả hai bậc đã chạy trọn trên một VPS thật. Các chỗ có đánh dấu **[F…]** được sửa theo kết quả thử, chi tiết trong `docs/hosting/CL-0-REPORT.md`.

---

## 1. Nguyên tắc

1. **Bản cài SNPanel giữ nguyên như hiện tại.** `install.sh` vẫn cài Nginx + PHP-FPM trên Ubuntu 24.04, Debian 12/13 và AlmaLinux 10. Không thêm menu hay cờ chọn edition lúc cài.
2. **Nâng cấp là một lệnh riêng, chạy sau khi đã cài.** Lệnh chia hai bậc, bậc sau cần bậc trước:

```
 Mức 0 — Standard (mặc định sau khi cài)
   AlmaLinux 10 · Nginx · PHP-FPM (Remi) · open_basedir · quota mềm
        │
        │  snpanel upgrade cloudlinux --key=<CL_KEY>          ← bậc 1, một chiều
        ▼
 Mức 1 — CloudLinux
   CloudLinux 10 · Apache + mod_lsapi · LSPHP (alt-php)
   PHP Selector (+ MultiPHP theo domain) · CageFS · LVE · MySQL Governor
        │
        │  snpanel upgrade litespeed --key=<LSWS_KEY>         ← bậc 2, đảo ngược được
        ▼
 Mức 2 — CloudLinux + LiteSpeed Enterprise
   LSWS giữ :80/:443, dùng LSPHP (cùng bộ alt-php, cùng PHP Selector)
   Apache dự phòng qua port offset → tự nhận lại :80/:443 khi LSWS chết hoặc hết license
```

3. **Chỉ AlmaLinux 10 mới lên được CloudLinux.** Máy Ubuntu/Debian muốn lên thì dùng backup/restore của SNPanel để chuyển sang một máy AlmaLinux 10 mới, rồi chạy lệnh nâng cấp trên máy đó.
4. **Bậc 1 là một chiều**, vì `cldeploy` convert cả OS. Lệnh phải nói rõ điều này và bắt gõ xác nhận. **Bậc 2 đảo ngược được**: `snpanel upgrade litespeed --remove` đưa máy về Mức 1.

---

## 2. Đối chiếu với cPanel / DirectAdmin

Làm giống cách hai panel này đã làm, để admin quen tay:

| Việc | DirectAdmin (CustomBuild) | cPanel | SNPanel |
|---|---|---|---|
| Lên CloudLinux | `cldeploy -k KEY` + reboot | `cldeploy -k KEY` + reboot | `snpanel upgrade cloudlinux --key=KEY` (tự lo reboot và chạy tiếp) |
| Web server | `./build set webserver apache` | EasyApache 4 | tự động trong bậc 1 |
| PHP mode | `php1_mode lsphp` | `mod_lsapi` qua EA4 | tự động: alt-php + mod_lsapi |
| PHP Selector | có sẵn sau CL | CloudLinux Manager | trang *Select PHP Version* |
| PHP theo domain | `.htaccess` handler | MultiPHP Manager | trang *MultiPHP Manager* (khối `.htaccess` do SNPanel quản lý) |
| CageFS, LVE | `cagefsctl`, `lvectl` | CloudLinux Manager | tự bật trong bậc 1; giới hạn lấy từ *Packages* |
| MySQL Governor | `./build set mysql_gov yes` | có sẵn | trong bậc 1, chế độ **quan sát** mặc định |
| LiteSpeed | `./build set webserver litespeed` | cài LSWS cPanel plugin | `snpanel upgrade litespeed --key=KEY` |
| Dự phòng khi LSWS lỗi | (thủ công: đổi về apache) | (thủ công) | **tự động**: port offset + watchdog |

---

## 3. Lệnh 1 — `snpanel upgrade cloudlinux`

### 3.1 Cú pháp

```bash
snpanel doctor --enterprise-readiness          # chỉ kiểm tra, không cài gì, không cần key
snpanel upgrade cloudlinux --key=<KEY> [--confirm] [--unattended] [--cagefs-batch-size=10] [--no-governor]
snpanel upgrade status                         # đang ở bước nào, lỗi gì
snpanel upgrade resume                         # chạy tiếp (tự gọi sau reboot)
```

### 3.2 Điều kiện chặn cứng (preflight)

| Kiểm tra | Cách | Exit |
|---|---|---|
| OS là AlmaLinux 10. Nếu đã có `/etc/cloudlinux-release` thì bỏ qua bước convert **[F1]** | `/etc/os-release`, `/etc/cloudlinux-release` | 10 |
| x86_64 | `uname -m` | 11 |
| CPU đạt x86-64-v3 | `snpanel_osabi::cpu_baseline()` (đã có sẵn) | 12 |
| Không chạy trong container (LVE cần kernel thật) | `systemd-detect-virt`: từ chối lxc, openvz, docker, podman, systemd-nspawn, wsl | 13 |
| RAM ≥ 2 GB, đĩa trống ≥ 25 GB, `/boot` ≥ 500 MB | meminfo, statvfs | 14 |
| License CloudLinux hợp lệ | gọi API kích hoạt | 15 |
| Không có panel khác | cPanel, DA, Plesk | 16 |
| Máy convert được | `cldeploy --precheck` **[F2]** | 17 |

Mã 20 nghĩa là lỗi giữa chừng và **đã rollback**. Mã 21 nghĩa là lỗi giữa chừng và **cần can thiệp tay**.

### 3.3 Các bước

Ba việc rủi ro nhất (convert kernel, đổi web server, đưa user vào cage) **không bao giờ nằm chung một bước**. Hỏng ở đâu thì biết ngay ở đó.

| # | Việc | Site có bị gián đoạn? | Rollback |
|---|---|---|---|
| S1 | Preflight (có `cldeploy --precheck`). Backup `/etc/nginx`, `snpanel.db`, `.env`, firewall rules, danh sách site | không | không cần |
| S2 | `CLDEPLOY_ACTIVATION_KEY=… cldeploy -y --conversion-only` → **reboot** (resume tự chạy sau boot). Đo được 5 phút 13 giây, **0 gián đoạn** lúc convert | chỉ lúc reboot | snapshot VPS |
| S3 | Xác nhận `/etc/cloudlinux-release`, module `kmodlve` đã nạp, `lvectl list` chạy được. **Không** dựa vào `ID` trong `os-release` hay tên kernel, vì CloudLinux 10 giữ nguyên cả hai **[F1]** | không | dừng sạch, exit 17 |
| S4 | LVE: đồng bộ gói SNPanel → LVE package **ngay**. LVE mặc định (1 GB, EP 20) đã áp cho mọi user từ lúc boot **[F3]** | không | `lvectl destroy` |
| S5 | `systemctl mask httpd` **[F4]**, rồi cài `httpd mod_ssl mod_security cagefs liblsapi mod_lsapi alt-php81…85` cùng extension | không | gỡ gói |
| S5b | Chuẩn bị Apache: dọn `conf.d` **[F5]**, drop-in `ProtectHome=no` **[F6]**. `/usr/local/bin/lsphp` và `/usr/bin/php` là **file thật** của alt-php mặc định **[F8][F9]** | không | khôi phục file |
| S6 | `cagefsctl --init` rồi `--disable-all`. Bật `nd_mysqli,nd_pdo_mysql,opcache` cho mọi phiên bản trong Selector **[F10]**. Cài CPAPI: `integration.ini`, snapshot, mount chỉ đọc vào cage **[F11]** | không | gỡ |
| S7 | Từng user: CageFS + phiên bản Selector = phiên bản đa số trong các site của họ. Site lệch phiên bản → **Isolates + Selector theo domain** **[F7][F12]**. An toàn khi Nginx + FPM vẫn đang phục vụ **[F13]** | không | `cagefsctl --disable` |
| S8 | Sinh vhost Apache (**cổng cố định**, `SetHandler application/x-httpd-lsphp`) **[F20]**. `httpd -t`. Chạy Apache **bóng** trên :8088, so sánh từng site Nginx:80 và Apache:8088 | không | không cần |
| S9 | **Cutover:** dừng Nginx (không gỡ), Apache nhận :80. Đo được ~1,1 giây | ~1 giây | bật lại Nginx |
| S10 | Dừng PHP-FPM (Remi). Sau 2 tuần ổn định thì gỡ `nginx nginx-core phpXX-php-fpm` **[F29]**. phpMyAdmin phải chuyển sang tarball upstream trước, vì RPM của EPEL kéo theo `nginx-filesystem` và `php8.4-fpm` | không | bật lại / cài lại |
| S11 | MySQL Governor, rồi ghi `/etc/container/dbuser-map` và chạy `dbctl --lve-mode off`. Mặc định sau khi cài là `abusers`, tức **có hạn chế** **[F17]**. Có `--no-governor` để bỏ qua | DB lỗi **~95 giây** | dump + snapshot datadir |
| S12 | Ghi `edition=cloudlinux`, chạy `snpanel doctor`, in báo cáo | không | — |

Ghi chú:
- **S9 là điểm lui quan trọng nhất.** Nginx được giữ nguyên cấu hình ít nhất 2 tuần, bật lại là xong. Lệnh `snpanel upgrade cloudlinux --rollback-webserver` làm việc này.
- **Resume qua reboot:**
  - Trạng thái lưu ở `/var/lib/snpanel/upgrade-state.json`, theo cùng mẫu với `update/state.rs` đang có.
  - Unit `snpanel-upgrade-resume.service` là oneshot, tự chạy sau boot và tự tắt khi xong.
  - Mỗi bước chạy lại được an toàn.
- **License key** lưu ở `/etc/snpanel/cloudlinux.key` (0600 root). File trạng thái chỉ giữ đường dẫn tới đó.
- **SSL:** cert Let's Encrypt sẵn có được đọc từ `/etc/letsencrypt/live/<domain>` và ghi thẳng vào vhost Apache. Không phải xin lại cert.

### 3.4 Kết quả với từng thành phần

| Thành phần | Trước (Standard) | Sau bậc 1 |
|---|---|---|
| Web server | Nginx | Apache (Nginx dừng, còn cài) |
| PHP | Remi PHP-FPM, 1 pool mỗi site | alt-php qua mod_lsapi, chạy đúng UID của user (suexec). Mỗi site giữ đúng phiên bản PHP lúc chuyển (đã kiểm chứng) |
| Chọn PHP | theo site, trong form website | theo **user** (Selector), override theo **domain** = Selector `--domain` + CloudLinux Isolates **[F7]** |
| Cô lập | open_basedir + SFTP chroot | **CageFS** (vẫn giữ open_basedir làm lớp hai) |
| Giới hạn tài nguyên | không có | **LVE**: CPU, RAM, IO, IOPS, EP, NPROC theo gói |
| Quota đĩa | quota mềm (chỉ đếm site + app) | quota kernel (XFS project quota; nếu ext4 thì quota theo UID) |
| MySQL | MariaDB thường | MariaDB + **MySQL Governor** |
| Cache trang | fastcgi_cache | không có (có lại khi lên LiteSpeed) |
| WAF | Alma: không có | **mod_security2 + CRS** (được thêm) |
| Chống flood | nginx `limit_req` | tạm không có (có lại khi lên LiteSpeed) |
| Suspend | vhost thành trang tĩnh, khoá mật khẩu | cộng thêm: LVE về mức tối thiểu, dừng cron, khoá CageFS |

---

## 4. Lệnh 2 — `snpanel upgrade litespeed`

### 4.1 Cú pháp

```bash
snpanel upgrade litespeed --key=<LSWS_KEY> [--port-offset=1000] [--confirm]
snpanel upgrade litespeed --remove             # về lại Mức 1 (Apache)

snpanel web status      # ai đang giữ :80/:443, license LSWS còn bao lâu, standby có sẵn sàng không
snpanel web switch lsws|apache
snpanel web verify      # so sánh mọi site giữa bên live và bên standby
snpanel web history     # lịch sử failover
```

Chỉ chạy được khi máy đã ở Mức 1.

### 4.2 Các bước

| # | Việc | Rollback |
|---|---|---|
| L1 | Preflight: đã ở Mức 1, Apache đang live, key LSWS kích hoạt được | — |
| L2 | Cài LSWS vào `/usr/local/lsws`, chế độ đọc cấu hình Apache: `loadApacheConf=1`, `apacheConfFile=/etc/httpd/conf/httpd.conf`, `phpSuExec=2`, `enableLVE=2`. Với key `TRIAL`, lấy file `trial.key` (hiệu lực 14 ngày) **[F19]** | gỡ LSWS |
| L3 | Bật tích hợp CloudLinux trong LSWS (CageFS, LVE, PHP Selector). LSWS dùng **cùng bộ alt-php/lsphp** qua LSAPI riêng của nó, không cần khai báo external app | — |
| L4 | Chuyển Apache sang `Listen 8080/8443` và vhost `*:8080` (dự phòng nóng). Một luật nft giữ công khai 80/443 → Apache. LSWS đọc cấu hình Apache với **offset +1000** → 9080/9443 **[F21]** | nft về Apache |
| L5 | Kiểm tra **mọi site** qua 9080: status code, phiên bản PHP, UID chạy PHP. Chỉ đi tiếp khi mọi khác biệt nằm trong danh sách đã biết **[F24]** | dừng LSWS |
| L6 | **Hoán đổi**: thay bảng nft trong một giao dịch, 80/443 → 9080/9443. **0 gián đoạn** (đã đo) | `snpanel web switch apache` |
| L7 | Bật LSCache cho site WordPress (cài plugin LiteSpeed Cache qua WP-CLI). Chống flood chuyển sang cơ chế per-IP của LSWS | tắt plugin |
| L8 | Bật watchdog `snpanel-webwatch.service`. Ghi `webserver=lsws` | tắt watchdog |

**Không bao giờ gỡ Apache.** Apache ở lại vĩnh viễn để dự phòng.

### 4.3 Cơ chế dự phòng (port offset) — đã kiểm chứng **[F20][F21]**

```
Apache     Listen 8080/8443, vhost *:8080            luôn chạy (dự phòng nóng)
LiteSpeed  đọc cấu hình Apache, offset +1000     →   9080/9443, luôn chạy
nftables   table inet snpanel_webfailover
             LSWS live:    80 → 9080   443 → 9443
             Apache live:  80 → 8080   443 → 8443
panel SNPanel ở :2222, không bị ảnh hưởng trong mọi trường hợp
```

- **Cả hai web server luôn chạy, cùng đọc một bộ vhost.** Chuyển đổi chỉ là **thay nguyên bảng nft trong một giao dịch**: mất khoảng 0,06 giây, không restart, không sinh lại cấu hình, IP của khách truy cập được giữ nguyên.
  - Diễn tập: LSWS chết → Apache phục vụ sau **~3,4 giây** (kiểm tra mỗi 1 giây × 3 lần).
  - Chuyển ngược về LSWS: **0 request lỗi**.
- **Bất biến C47:** mọi vhost phải chạy được trên **cả Apache lẫn LSWS thật**. Chỉ `httpd -t` là chưa đủ, vì LSWS:
  - **không** mở rộng `Define`/`${VAR}`;
  - coi `<VirtualHost *>` là vhost mặc định;
  - không nhận port offset âm.
  - → vhost và `Listen` luôn dùng **cổng cố định**. Job CI phải chạy LSWS thật.
- **Firewall:** `snpanel_input` so khớp cổng **sau NAT**, nên chặn luồng đã chuyển cổng.
  - → Bộ sinh firewall phải thêm luật `ct status dnat ct original proto-dst { 80, 443 } return`.
  - Cổng 8080/9080 vẫn đóng từ bên ngoài.
- **Khôi phục sau boot và sau khi firewall được sinh lại:** một oneshot kèm timer áp lại bảng nft theo `/var/lib/snpanel/webserver`.
- **mod_lsapi khi LSWS live:** giữ mod_lsapi nạp sẵn trong Apache (đường A). Hai bên không xung đột vì đã tách cổng. Đã kiểm chứng: sau failover, PHP chạy đúng phiên bản của từng site.
- **Chênh lệch 403/404/301 giữa LSWS và Apache đã khắc phục** bằng các luật chặn viết thêm dạng `RewriteRule … [F]` **[F27]**.
- **PHP theo domain dưới LSWS: giới hạn của nhà cung cấp [F30]**. CloudLinux chỉ hỗ trợ Isolates + LiteSpeed trên cPanel (CLOS-4167). Đã thử 9 cách, không cách nào vừa giữ suEXEC vừa đổi được phiên bản.
  - Phiên bản theo **user** chạy đúng trên cả hai server.
  - Phiên bản theo **domain** chỉ có tác dụng khi Apache live. UI phải ghi rõ điều này.
  - Cần site khác phiên bản thì chuyển site đó sang một user riêng.

### 4.4 Watchdog `snpanel-webwatch.service`

Là unit systemd riêng. Không nằm trong `snpanel-api`, để restart panel không làm mất khả năng dự phòng.

| Tình huống | Phát hiện | Hành động |
|---|---|---|
| **LSWS chết / treo** | Mỗi **1 giây**: HTTP GET một **file tĩnh** (`/.well-known/acme-challenge/snpanel-health`) thẳng vào 9080. Lỗi 3 lần liên tiếp. Chỉ bắt đầu đếm sau lần thành công đầu tiên, tối đa 120 giây sau khi khởi động, để không failover nhầm lúc boot **[F22]** | Đổi bảng nft sang Apache, ghi `/var/lib/snpanel/webserver` và audit, báo admin (email/Telegram, dùng addon Notifications sẵn có) |
| **License LSWS sắp hết** | Kiểm tra mỗi ngày | Cảnh báo trước 30, 7 và 1 ngày trên dashboard và qua Notifications |
| **License LSWS đã hết / bị thu hồi** | Kiểm tra license mỗi giờ, cộng thêm health check | **Chủ động** chuyển sang Apache *trước* khi LSWS ngừng phục vụ, rồi báo admin |
| LSWS chạy lại ổn / đã gia hạn license | — | **Không tự chuyển về.** Admin chạy `snpanel web switch lsws` để tránh bật tắt liên tục (flapping) |

**Cảnh báo vận hành:** khi chạy Apache dự phòng thì **không có LSCache**. Toàn bộ traffic đi thẳng vào PHP và MySQL.
- Số tiến trình PHP của Apache (`lsapi_backend_children`) phải tính theo tải **không cache**.
- LVE và MySQL Governor chính là lớp giữ cho máy không sập trong lúc này.
- `snpanel web status` và dashboard hiện rõ dòng "đang chạy dự phòng Apache, không có LSCache".

---

## 5. Việc phải làm trong mã SNPanel

Nhóm theo thứ tự phụ thuộc. Các file dẫn chiếu là code hiện tại (1.1.0).

### A. Nền (làm trước, có lợi cho cả bản Standard)

| # | Việc | Chỗ trong code |
|---|---|---|
| A1 | Nhận diện CloudLinux 10 qua `/etc/cloudlinux-release`. `os-release` vẫn ghi `almalinux` **[F1]** | `snpanel-osabi/src/detect.rs:105`, `installer/platform.sh:50` |
| A2 | Sửa file tuning MariaDB trên EL: hiện ghi vào `/etc/mysql/mariadb.conf.d`, nơi MariaDB trên EL không đọc | `snpanel-helper/src/ops/mariadb.rs:28` → `Platform::mariadb_conf_dir()` |
| A3 | Đường dẫn PHP-FPM theo distro (đang hardcode `/etc/php/{v}/fpm`) | `helper/ops/php.rs`, `snpanel-api/src/php_tune.rs:644,759` |
| A4 | Nối SELinux vào luồng tạo site (verb đã có nhưng chưa ai gọi). Chỉ cho Standard: CloudLinux boot với `selinux=0` **[F2]** | `helper/ops/selinux.rs` |
| A5 | Preflight dùng chung: virt, RAM, đĩa, `/boot`, FS `/home` | mới trong `snpanel-osabi`, dùng cho cả `doctor` và `upgrade` |

### B. Tách lớp web server / PHP (hiện Nginx hardcode khắp nơi)

| # | Việc | Chỗ trong code |
|---|---|---|
| B1 | Trait `WebServer` (Nginx, Apache, LiteSpeed) và `PhpRuntime` (PhpFpm, ModLsapi, LswsLsapi) | mới: `snpanel-osabi/src/hosting/` |
| B2 | Vhost đi qua trait. Chỉ helper được ghi vhost (hiện API tự ghi) | `routes/websites.rs:583,1015`; `snpanel-nginx` → `snpanel-web` |
| B3 | Verb helper `web-test`, `web-reload`, `vhost-write` (giữ tên `nginx-*` cũ làm alias) | `snpanel-ipc/src/lib.rs:487`, `argv.rs`, `helper/ops/mod.rs`, `locks.rs` |
| B4 | Cho phép service `httpd`, `lsws`, `snpanel-webwatch` | `snpanel-ipc/src/lib.rs:218` (`ALLOWED_SERVICES`) |
| B5 | File `/var/lib/snpanel/webserver` là nguồn chân lý duy nhất cho "ai đang live". API, doctor và watchdog cùng đọc | mới |
| B6 | Firewall cho phép luồng đã chuyển cổng: `ct original proto-dst { 80, 443 }` **[F21]** | bộ sinh ruleset nft trong helper |
| B7 | `cleanup_failed_site` xoá cả thư mục site (lỗi có sẵn) **[F16]** | `routes/websites.rs:4191` |
| B8 | Renderer vhost ghi nguyên bộ vào thư mục tạm rồi `rename` một lần; nguồn dữ liệu lỗi thì từ chối ghi **[F28]** | `snpanel-web` |

**Tiêu chí xong B:** bản Standard chạy y hệt 1.1.0 (golden test nginx không đổi byte nào, acceptance 30/30 trên các distro).

### C. Apache + LSPHP (cho lệnh 1)

- Template Apache viết bằng Rust, tương ứng 4 template nginx hiện có (`snpanel-nginx/src/templates.rs`: wordpress, php, static, proxy). Giữ đủ các tính năng:
  - rewrite modes (laravel, codeigniter, …)
  - alias và redirect
  - chặn bot
  - SSL thủ công
  - ACME
  - header bảo mật
- Validator khối custom cho Apache. Chặn: `Include`, `LoadModule`, `SuexecUserGroup`, `SetHandler` PHP, `ProxyPass`, `*Log`, `SSL*`, … (tương ứng `snpanel-nginx/src/custom.rs`).
- PHP qua mod_lsapi:
  - `SuexecUserGroup` mỗi vhost
  - **chỉ một handler: `SetHandler application/x-httpd-lsphp`**. Handler theo phiên bản kiểu cPanel **không** chạy khi không có panel, và Apache sẽ trả mã nguồn PHP **[F7]**
  - vhost `<VirtualHost *:PORT>` với **cổng cố định**, `Listen` là số cố định trong một file riêng **[F20]**
  - drop-in `httpd.service.d/snpanel.conf`: `ProtectHome=no` **[F6]**
  - tune `lsapi_backend_*` thay cho tune FPM pool
- SSL: giữ `certbot certonly --webroot` như hiện tại. SNPanel tự ghi cert vào vhost (không dùng `certbot --apache`), nên cùng một đường dùng được cho cả LSWS.
- WAF: `mod_security2`, dùng lại rule CRS và giao diện WAF đang có.
- phpMyAdmin chạy qua lsphp bằng user hệ thống riêng `snpanel-pma`, ngoài CageFS. Giữ SSO.
- Proxy cho app (Node): `ProxyPass` + `mod_proxy_wstunnel`.

### D. CloudLinux (cho lệnh 1)

- **CageFS:**
  - Skeleton sinh từ danh sách lệnh terminal được phép hiện có (`TERMINAL_ALLOWLIST`, 53 lệnh). Chỉ một danh sách duy nhất.
  - User `snpanel` và `snpanel-pma` luôn ở ngoài cage.
  - **`runuser` không vào cage** (đã kiểm chứng). Terminal và WP-CLI phải bọc bằng `cagefs_enter.proxied` hoặc `cagefs_enter_user`. Cron thì tự vào cage, nên cách ghi crontab hiện tại vẫn đúng **[F14]**.
  - `/opt` được mount vào mọi cage, nên phải rà quyền của `/opt/snpanel` **[F15]**.
- **LVE:** gói SNPanel là nguồn chân lý, tự đồng bộ xuống LVE package. Thêm bảng phụ `package_hosting_limits`: cpu, pmem, io, iops, ep, nproc, inode, mức governor, phiên bản PHP cho phép, quyền MultiPHP.
- **PHP Selector:** bọc `cloudlinux-selector --json`.
  - Theo user: gọi dưới quyền root.
  - Theo domain: gọi **dưới quyền user**.
  - Thứ tự bắt buộc: bật extension mặc định **trước**, rồi mới đặt phiên bản cho user. User đã có thì `--reset-extensions` **[F10]**.
  - Đặt `date.timezone` mặc định.
- **MultiPHP theo domain [F7][F12]:**
  - Cách làm: `cagefsctl --isolates-allow <user>`, rồi `--isolates-enable <domain>`, rồi `cloudlinux-selector set --domain <domain> --current-version X` (chạy dưới quyền user).
  - SNPanel tạo sẵn `~/.cagefs/websites` (chủ `<u>:<u>`, quyền 0771), vì home thuộc root theo C33.
  - **Bỏ hẳn khối handler trong `.htaccess`**, cùng các hợp đồng C49/C51 và cái bẫy "override trùng phiên bản mặc định".
  - Sau khi đổi, vẫn xác minh bằng HTTP thật (C50).
- **MySQL Governor [F17]:**
  - Ghi `/etc/container/dbuser-map` (mỗi dòng `db_user linux_user uid`) mỗi khi tạo hoặc xoá database. Không cần đổi quy ước tên `u_<db>`.
  - Đặt chế độ quan sát tường minh bằng `dbctl --lve-mode off`, vì mặc định sau khi cài là `abusers`.
- **CPAPI [F11]:**
  - Đăng ký bằng `/opt/cpvendor/etc/integration.ini`, gồm 8 script theo schema `vendors_api/schemas/*.yaml`.
  - Binary `snpanel-cpapi` **không mở SQLite**. Nó đọc snapshot không chứa bí mật `/var/lib/snpanel-cpapi/data.json`, do panel ghi lại mỗi khi user, site, alias hoặc package thay đổi.
  - Snapshot được mount chỉ đọc vào cage bằng dòng `!/var/lib/snpanel-cpapi` trong `cagefs.mp`.
  - `domains` khi người gọi không phải root chỉ trả domain của chính họ. `users`/`packages` chỉ root gọi được.
- **Quota thật:** XFS project quota theo `/home/<user>`. Giữ thông báo lỗi thân thiện (HTTP 413) như hiện nay.
- **Giao diện:** 6 trang mới, chỉ hiện khi đã lên CloudLinux: Resource Usage, Select PHP Version, MultiPHP Manager, LVE Manager, CageFS, MySQL Governor. Nhúng trang của CloudLinux thì nới CSP **riêng cho các trang này**, không nới toàn cục.
- **WHMCS:** `GET /accounts/{eid}/usage` thêm các field CPU, RAM, EP (vẫn là bare object).

### E. LiteSpeed (cho lệnh 2)

- impl `LiteSpeed` cho `WebServer`, cộng `PageCache` (LSCache purge). Nút "Clear cache" hiện có dùng cho cả ba web server.
- Watchdog, `snpanel web …`, trang **Web Server** trong Settings (trạng thái, license, nút chuyển, lịch sử failover).
- Kiểm tra license LSWS và cảnh báo qua addon Notifications.

### F. Hai lệnh nâng cấp

- Logic: module `snpanel-installer/src/upgrade/`, theo mẫu `update/` (`state.rs`, `steps.rs`, `snapshot.rs`).
- CLI: thêm `Upgrade { cloudlinux | litespeed | status | resume }` và `Web { status | switch | verify | history }` vào `snpanel-cli/src/cli.rs:25`, rẽ nhánh ở `main.rs:80`.
- Unit `snpanel-upgrade-resume.service` và `snpanel-webwatch.service` sinh trong `systemd_units.rs`, có golden test như các unit khác.
- **`install.sh` không đổi.**

---

## 6. Lộ trình (2 dev)

| Giai đoạn | Tuần | Kết quả |
|---|---:|---|
| **0. Thử nghiệm tay** trên 1 VPS KVM | ✔ **xong 2026-09-28 — GO** | Xem `docs/hosting/CL-0-REPORT.md`. Còn mở: F23 (license hết hạn), F24.3 (Isolates dưới LSWS), F25 (SSL) |
| A. Nền | 2 | Phát hành 1.2 Standard (sửa tuning MariaDB trên EL, SELinux, preflight) |
| B. Tách lớp web/PHP | 3 | Phát hành 1.3 Standard, không đổi hành vi |
| C + D. Apache + CloudLinux | 11 | Lệnh `upgrade cloudlinux` chạy được. **Có thể bán từ đây** |
| E. LiteSpeed + dự phòng | 3 | Lệnh `upgrade litespeed`, watchdog, diễn tập failover |
| F. Hoàn thiện lệnh, test resume/rollback | 2 | Kill tiến trình ở từng bước rồi chạy lại phải sạch. Rollback S7 trên máy ≥ 20 site thật |
| Dự phòng | 2 | |
| **Tổng còn lại** | **≈ 23** | ≈ 5,5 tháng |

Nếu phải cắt: hoãn **MySQL Governor** trước (rủi ro cao nhất, giá trị thấp nhất), rồi đến **LiteSpeed**. Giữ **CageFS + LVE + PHP Selector**, vì đây là phần tạo khác biệt thật.

---

## 7. Quyết định đã chốt (2026-09-28)

| # | Câu hỏi | Quyết định |
|---|---|---|
| 1 | Tên gọi trong CLI/UI | Theo thành phần: `cloudlinux` / `litespeed`, như trong lệnh |
| 2 | Danh sách alt-php cài mặc định | 8.1–8.4 (+ 8.5 nếu có). 7.4 chỉ cài khi khách yêu cầu |
| 3 | MultiPHP cho end user | Theo gói (cờ `multiphp_allowed`) |
| 4 | Shell thật trong CageFS | Có, bật theo gói |
| 5 | MySQL Governor | Trong lệnh 1, chế độ quan sát, có `--no-governor` |
| 6 | App Docker trên máy CloudLinux | Chỉ admin dùng |
| 7 | WAF | mod_security2 (dùng lại UI WAF sẵn có). Imunify360 làm tuỳ chọn sau |
