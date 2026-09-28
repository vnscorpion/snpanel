# CL-0 — Báo cáo thử nghiệm tay: CloudLinux + Apache/LSPHP + LiteSpeed

**Ngày:** 2026-09-28 · **Máy thử:** VPS KVM, AlmaLinux 10.2, 4 vCPU (x86-64-v4), 5 GB RAM, XFS 54 GB
**Đầu vào:** SNPanel 1.1.0 Standard, 4 user, 20 site (6 WordPress, 9 PHP, 5 static, 1 alias, 1 laravel)
**Kế hoạch đối chiếu:** `docs/hosting/UPGRADE-PLAN.md`
**Prototype dùng trong buổi thử:** `docs/hosting/cl0-prototype/`

---

## 1. Kết luận

**GO.** Cả hai bậc nâng cấp đã chạy tay trọn vẹn trên máy thật, không mất dữ liệu:

- **Bậc 1:** AlmaLinux 10 → CloudLinux 10 → Apache + mod_lsapi + alt-php 8.1–8.5 → CageFS + PHP Selector (theo user và theo domain) → MySQL Governor.
- **Bậc 2:** LiteSpeed Enterprise (TRIAL), có dự phòng Apache dùng port offset và watchdog tự chuyển.

Có một thiết kế bị bác bỏ và thay thế: **khối handler PHP trong `.htaccess` không dùng được**. PHP theo domain làm bằng cơ chế có sẵn của CloudLinux, gọn hơn, xem F7.

Cách đo: mỗi mốc chạy `probe.py`, gửi cùng 147 request tới 21 host. Kết quả so với baseline lấy khi còn chạy Nginx + PHP-FPM, gồm: status code, phiên bản PHP (major.minor) và UID của tiến trình PHP.

| Mốc | Khác biệt so với baseline | Gián đoạn cổng 80 |
|---|---:|---|
| Sau `cldeploy` + reboot (vẫn Nginx) | 0 | 0 trong lúc convert (162/162 request OK); chỉ mất lúc reboot |
| Apache chạy bóng :8088 | 0 | — |
| Cutover Nginx → Apache | 0 | **~1,1 s** |
| Dừng PHP-FPM | 0 | 0 |
| Cài MySQL Governor | 0 | site dùng DB lỗi 500 **~95 s** |
| LiteSpeed live (80 → LSWS) | 30 (3 nhóm đã biết, F24) | 0 |
| Failover LSWS chết → Apache | 0 | **~3,4 s** |
| Chuyển ngược về LSWS | — | 0 |
| Reboot (lần 2, sau khi sửa watchdog) | LSWS vẫn live | chỉ thời gian boot |

---

## 2. Phát hiện — và thay đổi phải đưa vào plan

### Bậc 1: CloudLinux

**F1 — CloudLinux 10 không đổi kernel và không đổi `os-release`.**
- Sau convert, `/etc/os-release` vẫn ghi `ID=almalinux`, kernel vẫn là của AlmaLinux (`6.12.0-211.56.1.el10_2`). LVE chạy bằng module `kmod-lve`.
- CloudLinux chỉ thêm `/etc/cloudlinux-release` ("CloudLinux release 10") và gói `cloudlinux-release`.
- → Plan P2/S3 sai. Nhận diện CloudLinux qua `/etc/cloudlinux-release`. Xác minh bằng `lsmod | grep kmodlve` và `lvectl list`, không dựa vào `ID` hay tên kernel.

**F2 — `cldeploy` chạy 5 phút 13 giây, không làm gián đoạn site.**
- Lệnh đầy đủ: `CLDEPLOY_ACTIVATION_KEY=… cldeploy -y --conversion-only`. Có sẵn `--precheck`, và biến môi trường giúp key không hiện trong danh sách tiến trình.
- Kernel được thêm các tham số `selinux=0 cgroup.memory=nokmem ibt=off cgroup_no_v1=all`.
- → **CloudLinux tự tắt SELinux.** Việc bật SELinux cho EL (plan P3) không áp dụng cho Hosting Edition.
- → Preflight nên dùng `cldeploy --precheck` thay vì tự viết các kiểm tra kernel.

**F3 — LVE có hiệu lực ngay sau reboot**, với mức mặc định 1 GB RAM và 20 Entry Process cho **mọi user**, trước khi SNPanel đồng bộ gói.
- → Lệnh nâng cấp phải đồng bộ gói → LVE ngay tại S4, hoặc nâng LVE mặc định lên trước.

**F4 — Scriptlet của gói tự khởi động `httpd`** ngay khi cài. Apache chết vì cổng 80 đang do Nginx giữ.
- → `systemctl mask httpd` **trước** khi cài gói ở S5.

**F5 — Các file trong `conf.d` phải vô hiệu hoá:**
- `php.conf`, `php83-php.conf`, `php84-php.conf` (Remi, trỏ PHP sang FPM);
- `phpMyAdmin.conf`, `welcome.conf`, `userdir.conf`, `autoindex.conf`;
- `ssl.conf`: bỏ vhost `_default_:443`. SNPanel tự quản vhost SSL.

**F6 — `httpd.service` của hệ thống đặt `ProtectHome=read-only`.**
- mod_lsapi chạy PHP trong namespace của httpd, nên PHP **không ghi được vào `/home`**: WordPress không upload được, lỗi "Read-only file system".
- → Thêm drop-in `/etc/systemd/system/httpd.service.d/snpanel.conf` chứa `ProtectHome=no`.

**F7 — Ở máy không có panel, mod_lsapi chỉ nhận đúng một handler là `application/x-httpd-lsphp`.**
- Handler dạng cPanel như `application/x-httpd-alt-php83___lsphp` **không được nhận**: Apache trả **mã nguồn PHP dạng text**. Đã thử thêm 5 biến thể tên khác, đều thất bại.
- Phiên bản PHP được chọn qua PHP Selector:
  - theo **user**: `cloudlinux-selector set --user … --current-version`;
  - theo **domain**: `cloudlinux-selector set --domain … --current-version`, chạy **dưới quyền user**, cần domain đó bật **CloudLinux Isolates** (`cagefsctl --isolates-allow <user>` rồi `--isolates-enable <domain>`) và cần CPAPI (F11).
- → **Bỏ toàn bộ thiết kế khối `# SNPANEL PHP HANDLER` trong `.htaccess`**: C49, C51, việc đối chiếu khối, và cái bẫy "override trùng phiên bản mặc định".
- → MultiPHP = Selector `--domain` + Isolates. Mỗi vhost chỉ cần `SetHandler application/x-httpd-lsphp`.

**F8 — `/usr/local/bin/lsphp` là lsphp "native"** (dùng cho user nằm ngoài cage).
- `mod_lsapi --setup` mặc định chép bản alt-php **thấp nhất đang cài** (8.1) vào đây.
- File này **phải là file thật**. Nếu là symlink, `cagefsctl --force-update` sẽ chép nguyên symlink vào skeleton, và Selector trong cage bị vô hiệu: mọi user chạy cùng một phiên bản.
- → Chép bản alt-php mặc định (8.4) vào đây bằng `install`, không dùng `ln`.

**F9 — Shim PHP của SNPanel xung đột với Selector.**
- Trên EL, `php_shim` biến `/usr/bin/php` thành symlink sang Remi.
- Selector báo: "…/opt/remi/php84/root/usr/bin/php is mounted to CageFS. CloudLinux Selector will not be available". Hậu quả: CLI trong cage (WP-CLI, composer, cron) chạy PHP của Remi.
- → Lệnh nâng cấp phải thay `/usr/bin/php` bằng file thật của alt-php mặc định.
- → Các lệnh `php8.4`/`php8.3` mà helper đang dùng phải đổi sang `php` bên trong cage.

**F10 — Bộ extension mặc định của Selector thiếu `nd_mysqli`, `nd_pdo_mysql` và `opcache`**, nên WordPress báo "Requirements Not Met".
- Mỗi user có file `~/.cl.selector/defaults.cfg`, là **bản chụp** bộ mặc định tại thời điểm user được thiết lập. Bật extension chung sau đó không có tác dụng ngược với user cũ.
- → Bật extension cho mọi phiên bản bằng `selectorctl --enable-extensions=… --version=X` **trước** khi đặt phiên bản cho user. User đã có thì chạy `cloudlinux-selector set --reset-extensions`.
- → Đặt thêm `date.timezone`: alt-php đang cảnh báo giá trị này trống.

**F11 — CPAPI cho panel tự viết được đặc tả ngay trên máy**, rủi ro R17 gần như không còn.
- Tích hợp qua file `/opt/cpvendor/etc/integration.ini`, mục `[integration_scripts]`, gồm 8 script: `panel_info`, `db_info`, `packages`, `users`, `domains`, `resellers`, `admins`, `php`.
- Mỗi script trả JSON `{data, metadata:{result}}`. JSON schema nằm ở `/opt/cloudlinux/venv/lib64/python3.11/site-packages/vendors_api/schemas/`.
- Prototype `snpanel-cpapi` chạy được: `getCPName()` trả `SNPanel`, `userdomains()` đúng, Selector theo domain chạy.
- **Ràng buộc mới:** script `domains` bị **mọi user gọi, kể cả trong CageFS**, nên không được đọc `snpanel.db`.
- → SNPanel xuất snapshot không chứa bí mật ra `/var/lib/snpanel-cpapi/data.json` (0644), mount chỉ đọc vào cage qua dòng `!/var/lib/snpanel-cpapi` trong `cagefs.mp`. Khi người gọi không phải root, script chỉ trả domain của chính họ.
- → Hợp đồng C45 đổi thành: "CPAPI không bao giờ mở SQLite; đọc snapshot".

**F12 — Selector theo domain cần thư mục `~/.cagefs/websites`.**
- Quy tắc C33 (home thuộc `root:<u>` 0751) khiến Selector không tự tạo được thư mục này.
- → SNPanel tạo sẵn `~/.cagefs/websites` với chủ `<u>:<u>`, quyền 0771.

**F13 — CageFS chạy song song với PHP-FPM được.**
- Bật CageFS cho cả 4 user trong khi Nginx + FPM vẫn phục vụ: 0 khác biệt.
- → **Đổi thứ tự:** CageFS + Selector (S9/S10) chạy **trước** cutover (S7). Nhờ vậy lúc chuyển sang Apache, mỗi site giữ đúng phiên bản PHP.

**F14 — `runuser -u <user>` không vào cage** (rủi ro R30 đã được xác nhận).
- Terminal và WP-CLI của helper hiện chạy bên ngoài CageFS. `cagefs_enter.proxied` và `cagefs_enter_user` thì vào được.
- Cron thì vào cage: crond của CloudLinux tự lo, nên ghi crontab bằng `runuser` vẫn đúng.
- → Helper phải bọc terminal và WP-CLI bằng `cagefs_enter`.

**F15 — `/opt` được mount vào mọi cage**, nên user trong cage nhìn thấy `/opt/snpanel`.
- Hiện đã có quyền 0711/0750 bảo vệ, nhưng phải đưa vào checklist bảo mật.

**F16 — SNPanel 1.1.0 không vận hành được sau khi cutover**, đúng như dự đoán, và là bằng chứng cho phase CL-R.
- Tạo site thất bại với lỗi "Failed to reload php8.4-fpm.service".
- Lỗi phụ có sẵn: `cleanup_failed_site` để lại thư mục site.

**F17 — MySQL Governor** (`--mysql-version=mariadb1011 --install --yes`, mất 3 phút 57 giây).
- MariaDB 10.11.18 được thay bằng `10.11.19-MariaDB-cll-lve`. Dữ liệu còn nguyên. Site dùng DB lỗi 500 khoảng 95 giây.
- Mặc định là `lve use="abusers"`, tức **hạn chế ngay** user bị coi là lạm dụng.
- → Đặt chế độ tường minh bằng `dbctl --lve-mode off` (chỉ quan sát).
- Tên DB user `u_<db>` bị gom hết thành **một** tài khoản `u`.
- → SNPanel ghi `/etc/container/dbuser-map` (mỗi dòng `db_user linux_user uid`) mỗi khi tạo hoặc xoá database. Không cần đổi quy ước đặt tên, và không cần đi qua CPAPI.

**F18 — phpMyAdmin** chạy qua lsphp dưới user hệ thống `snpanel-pma`, nằm ngoài cage.
- SSO lấy token qua API loopback 2222, không dùng `/tmp`, nên `PrivateTmp` của httpd không ảnh hưởng.
- Thư mục `/var/www/snpanel-acme` không tồn tại trên bản cài mới. Cần xem lại installer.

### Bậc 2: LiteSpeed

**F19 — Cài đặt:**
- Nhánh không có panel của `get.litespeed.sh` chạy `install.sh` ở chế độ hỏi đáp. Lệnh `more ./LICENSE` đọc mất stdin, nên muốn tự động hoá phải thay `more` bằng `cat`.
- Chọn panel "2" (DirectAdmin) để LSWS dùng chế độ đọc cấu hình Apache: `loadApacheConf=1`, `apacheConfFile=/etc/httpd/conf/httpd.conf`, `apachePortOffset`, `phpSuExec=2`, `enableLVE=2`.
- Trial key lấy từ `license.litespeedtech.com/reseller/trial.key`, hiệu lực **14 ngày**. Phiên bản cài: LSWS 6.3.7.

**F20 — LSWS không đọc được một số cú pháp Apache hợp lệ.** Đây đúng là thứ ràng buộc C47 nhằm bắt.
- `Define` / `${VAR}` **không được mở rộng**: cổng thành 0, cộng offset thành 1000, và mọi vhost báo "Listener … not available".
- `<VirtualHost *>` (không kèm cổng) bị LSWS coi là vhost mặc định: **mọi request đi vào vhost nạp sau cùng**.
- Port offset âm không được chấp nhận.
- → Vhost phải có **cổng cố định**, và `Listen` phải là số cố định. Job CI kiểm tra C47 phải chạy LSWS thật, không chỉ `httpd -t`.

**F21 — Thiết kế dự phòng đã kiểm chứng**, thay cho thiết kế "đổi cổng rồi restart" của plan:

```
Apache     Listen 8080/8443, vhost *:8080         luôn chạy (dự phòng nóng)
LiteSpeed  đọc cấu hình Apache, offset +1000   →   9080/9443, luôn chạy
nftables   table inet snpanel_webfailover:  80 → 9080, 443 → 9443   (LSWS live)
                                             80 → 8080, 443 → 8443   (Apache live)
```

- Chuyển đổi = thay nguyên bảng nft trong **một giao dịch**, mất khoảng 0,06 giây, không restart gì.
- Chuyển ngược về LSWS: **0 request lỗi**.
- Cổng 8080 và 9080 vẫn đóng từ bên ngoài.
- Firewall của SNPanel so khớp cổng **sau NAT**, nên chặn luồng đã chuyển cổng. → Thêm luật `ct status dnat ct original proto-dst { 80, 443 } return` vào `snpanel_input`. Bộ sinh firewall phải tự tạo luật này, nếu không mỗi lần sinh lại firewall sẽ làm mọi site mất kết nối.
- `/var/lib/snpanel/webserver` là nguồn chân lý duy nhất cho câu hỏi "ai đang live" (C56).

**F22 — Watchdog (diễn tập có bấm giờ):**
- Dừng LSWS → sau khoảng 3,4 giây cổng 80 được Apache phục vụ (kiểm tra mỗi 1 giây, 3 lần lỗi). Sau đó 0 khác biệt, kể cả PHP theo domain.
- Lần reboot đầu **failover nhầm**: LSWS báo "started" nhưng chưa trả lời ngay.
- → Watchdog chỉ đếm lỗi sau lần kiểm tra thành công đầu tiên, và tối đa sau 120 giây kể từ khi khởi động.
- → Điểm kiểm tra phải là **file tĩnh** (`/.well-known/acme-challenge/snpanel-health`), không phụ thuộc PHP.
- → Nhịp kiểm tra nên là 1 giây × 3 lần. Con số 5 giây × 3 trong plan cho gián đoạn khoảng 15 giây.
- Việc áp lại luật sau boot và sau mỗi lần firewall được sinh lại do một oneshot kèm timer 60 giây đảm nhận (`units.sh`).

**F23 — License hết hạn:** chưa thử được, vì trial còn 14 ngày.
- Watchdog kiểm tra `lshttpd -V`, và vẫn failover được nếu LSWS không lên sau 120 giây. **Cần thử lại khi trial hết hạn**, vào khoảng 2026-10-12.

**F24 — LSWS khác Apache ở 3 điểm** (30/147 request):
1. File bị chặn nhưng không tồn tại (`.php` trên site static, `wp-config.php`/`xmlrpc.php` trên site không phải WordPress…): LSWS trả **404**, Apache trả **403**. PHP không chạy, nên về bảo mật là tương đương.
2. `/wp-content/uploads/x.php` không tồn tại: LSWS trả **301** sang địa chỉ có `/` ở cuối, thay vì 403. PHP cũng không chạy.
3. **PHP theo domain (Isolates) không có tác dụng trên LSWS**: domain override chạy phiên bản của user. **Đây là vấn đề mở quan trọng**, phải hỏi LiteSpeed/CloudLinux, có thể cần phiên bản LSWS hoặc tuỳ chọn tích hợp khác. Trong lúc chờ: khi LSWS live, MultiPHP theo domain bị giới hạn, và UI phải cảnh báo.

**F25 — Chưa thử:**
- SSL trên Apache/LSWS (máy thử không có domain thật);
- terminal của panel chạy trong cage (mới kiểm chứng ở mức lệnh);
- cập nhật alt-php kèm `cagefsctl --force-update` trên máy đông user;
- chế độ restrict của Governor dưới tải thật.

**F26 — Dung lượng:** toàn bộ stack dùng 5,8 GB trên `/`; riêng skeleton CageFS là 3,5 GB. Mức cảnh báo ≥ 25 GB đĩa trống trong preflight hơi cao, nhưng vẫn giữ để dư chỗ cho nhiều bản alt-php.

---

## 3. Thứ tự các bước của lệnh 1, viết lại theo kết quả thử

| # | Việc | Ghi chú mới |
|---|---|---|
| S1 | Preflight + backup | Có `cldeploy --precheck` |
| S2 | `cldeploy -y --conversion-only` → reboot | F1, F2 |
| S3 | Xác minh `/etc/cloudlinux-release` + `kmodlve` + `lvectl list` | F1 |
| S4 | LVE: đồng bộ gói **ngay** | F3 |
| S5 | `mask httpd` → cài httpd, mod_ssl, mod_security, cagefs, mod_lsapi, alt-php 8.1–8.5 | F4 |
| S5b | Dọn `conf.d`, drop-in `ProtectHome=no`, `/usr/local/bin/lsphp` và `/usr/bin/php` là file thật | F5, F6, F8, F9 |
| S6 | `cagefsctl --init` + disable-all, extension mặc định cho Selector, CPAPI + `integration.ini` + mount snapshot | F10, F11 |
| S7 | CageFS cho từng user + Selector theo user, **Isolates + Selector theo domain** cho site lệch phiên bản | F7, F12, F13 |
| S8 | Vhost Apache chạy bóng, so sánh từng site | cổng cố định (F20) |
| S9 | **Cutover** Nginx → Apache (~1 giây) | rollback = bật lại Nginx |
| S10 | Dừng PHP-FPM | |
| S11 | Governor + `dbuser-map` + `--lve-mode off` (cửa sổ DB ~1,5 phút) | F17 |
| S12 | Ghi edition, doctor, báo cáo | |

---

## 4. Việc tiếp theo

1. Cập nhật `UPGRADE-PLAN.md` theo F1–F26. Bản đã cập nhật nằm cạnh file này.
2. Hỏi LiteSpeed/CloudLinux về F24.3: CloudLinux Isolates và PHP Selector theo domain dưới LSWS.
3. Thử lại F23 (license hết hạn) và F25 (SSL) trên chính máy này khi có domain thật.
4. Bắt đầu phase CL-R (tách lớp web/PHP), vì F16 cho thấy đây là điều kiện tiên quyết.

---

## 5. Buổi 2 (cùng ngày): chuyển hẳn sang LiteSpeed, gỡ Nginx và PHP-FPM

**F27 — Lệch 403/404/301 giữa LiteSpeed và Apache: đã khắc phục hẳn.**
- Mọi luật chặn giờ viết thêm bằng `RewriteRule "(?i)<mẫu>" - [F]`, đặt trước front controller. Khối `Require all denied` cũ giữ lại làm lớp phòng thủ thứ hai.
- `RewriteRule [F]` trả **403 như nhau trên cả hai server**, dù file có tồn tại hay không.
- Kết quả trên LiteSpeed: 30 khác biệt → **4**. Cả 4 là F24.3.

**F28 — Bộ sinh vhost phải thay nguyên bộ trong một lần.**
- Bản prototype cũ xoá vhost trước rồi mới sinh lại. Khi token API hết hạn, nó sinh ra **0 vhost**, và reload đó làm mọi site mất phục vụ khoảng 1 phút.
- → Renderer trong Rust phải sinh toàn bộ vào thư mục tạm, rồi `rename` một lần. Nếu nguồn dữ liệu lỗi thì từ chối ghi. `gen_apache.py` đã sửa theo cách này.

**F29 — Gỡ Nginx và PHP-FPM.**
- Đã gỡ `nginx`, `nginx-core`, `php83-php-fpm`, `php84-php-fpm`. Kết quả: 0 khác biệt trên Apache, phpMyAdmin vẫn 200, panel vẫn OK.
- RPM phpMyAdmin của EPEL đòi `nginx-filesystem` (chỉ là thư mục) và `php(httpd)`, mà chỉ `php8.4-fpm` của AppStream cung cấp. Nếu gỡ hai gói này, dnf **gỡ luôn phpMyAdmin**.
- → Tạm thời giữ hai gói đó, và `systemctl mask php8.4-fpm` để nó không bao giờ chạy.
- → Muốn sạch hẳn: Hosting Edition cài phpMyAdmin từ **tarball upstream** thay cho RPM của EPEL. Đây là việc của installer / lệnh nâng cấp.
- Cấu hình cũ đã sao lưu ở `/root/cl0/removed/`.

**F30 — PHP theo domain dưới LiteSpeed: giới hạn của nhà cung cấp, đã xác nhận.**
- Tài liệu CloudLinux ghi: LiteSpeed + Isolates "Supported (cPanel only)". Bài KB *"Per-domain PHP Selector settings are not applied when CloudLinux Isolates is used with LiteSpeed"* nhắc tới task nội bộ **CLOS-4167**.
- Đã thử 9 cách trên LiteSpeed 6.3.7. Kết quả chia làm hai nhóm:
  - **đúng phiên bản nhưng chạy dưới `apache`**, tức mất suEXEC và là lỗ hổng bảo mật: `x-httpd-alt-php83___lsphp`, `x-httpd-alt-php83`, `x-lsphp83`, handler `ea-php83___lsphp` với đường dẫn kiểu cPanel, và khai báo app `alt-php83` riêng với `autoStart=2`;
  - **đúng user nhưng sai phiên bản**: `x-httpd-lsphp83`, `x-httpd-php83` (kể cả khi có `/usr/local/php83/bin/lsphp` kiểu DirectAdmin), `phpSuExec=1`, và cài `mod_hostinglimits`.
- **Không có cách cấu hình nào vừa giữ suEXEC vừa đổi được phiên bản theo domain dưới LiteSpeed.**

**Quyết định đề xuất cho F30:**
1. Phiên bản PHP **theo user** (Selector) chạy đúng trên cả hai web server. Đây là mặc định, và cũng là cách phần lớn nhà cung cấp hosting bán.
2. PHP **theo domain** (Isolates + Selector `--domain`):
   - khi Apache live: có tác dụng;
   - khi LiteSpeed live: chưa có tác dụng; UI hiển thị "đang theo phiên bản của tài khoản (giới hạn của LiteSpeed)".
   - Không dùng handler theo phiên bản vì nó mất suEXEC.
3. Khách thật sự cần một site chạy phiên bản khác: tách site đó sang một user riêng. SNPanel đã có sẵn chức năng chuyển chủ sở hữu site.
4. Mở ticket với LiteSpeed và CloudLinux, dẫn chiếu CLOS-4167, hỏi lộ trình hỗ trợ Isolates dưới LiteSpeed cho panel tự viết. Khi có hỗ trợ, SNPanel không phải sửa gì, vì cơ chế đang dùng đúng là Isolates.

---

## 6. Buổi 3: dùng thật trên panel — lỗi giao diện và dọn sạch stack cũ

**F31 — Dashboard báo "Stopped: snpanel-api, nginx, mariadb, valkey" dù mọi thứ đang chạy.**
- Nguyên nhân: file `cagefs-dbus-hardening.conf` của gói `cagefs` (CLOS-2704/4516) **chặn mọi account không phải root truy vấn systemd qua D-Bus**. Lệnh `systemctl is-active` chạy dưới quyền `snpanel` vì thế không trả lời được gì.
- → Lệnh nâng cấp cài `/etc/dbus-1/system.d/snpanel-systemd-read.conf`. File này chỉ cho `snpanel` các lệnh **đọc** (`Properties.Get/GetAll`, `Manager.GetUnit/LoadUnit/ListUnitsByNames/GetUnitProcesses`), sau đó chạy `busctl … ReloadConfig`.
  - Đã kiểm tra: `stop` vẫn bị từ chối. User khách vẫn bị CageFS chặn như cũ.
  - Không sửa file của CloudLinux, vì bản cập nhật `cagefs` sẽ ghi đè nó.
  - Thêm `snpanel` vào nhóm `clsupergid` **không** giải quyết được việc này.
- → Danh sách service trên máy Hosting không còn nginx/PHP-FPM. Nó gồm `lshttpd`, `httpd`, `db_governor`, `snpanel-webwatch` (PR #24).

**F32 — CloudLinux chặn account không phải root đọc `/proc/modules`** ("Operation not permitted").
- → Nhận diện LVE bằng `/sys/module/kmodlve` (PR #25).

**F33 — Panel không khởi động khi thiếu `/etc/nginx`** (226/NAMESPACE).
- Nguyên nhân: `ReadWritePaths=` của unit liệt kê các thư mục nginx.
- → Các đường dẫn không bắt buộc thêm tiền tố `-` (PR #24).

**F34 — Gỡ hẳn Nginx, PHP-FPM và Remi** (đã làm trên VPS; phải thành bước S10 của lệnh nâng cấp):
- RPM phpMyAdmin (EPEL) kéo theo `nginx-filesystem` và `php8.4-fpm`, còn RPM composer kéo theo `php-cli`.
  - phpMyAdmin được giữ nguyên bản đang chạy, **không còn thuộc RPM**. Cấu hình vẫn ở `/etc/phpMyAdmin`, dữ liệu ở `/var/lib/phpMyAdmin`, nhóm sở hữu là `snpanel-pma`.
  - Composer cài bằng phar chính thức, có kiểm tra chữ ký SHA-384.
- `/usr/bin/php` được ghi là **thuộc** `php8.4-cli`, nên gỡ gói đó là mất luôn file.
  - → Sau khi gỡ, đặt lại file thật của alt-php mặc định. `php8.3`/`php8.4`/`php83`/`php84` trỏ sang alt-php.
- alt-php native (chạy ngoài cage: phpMyAdmin, WP-CLI và composer do root chạy) **chỉ nạp `default.ini`**, không có `mysqli` hay `phar`.
  - → Symlink các file ini cần thiết từ `php.d.all` sang `php.d`, cộng một `snpanel-mysql.ini` duy nhất để `mysqlnd` chỉ nạp một lần. Đặt `date.timezone`.
  - Hệ quả thấy được: phpMyAdmin đi đúng luồng SSO (302 → `snpanel-signon.php`).
- Xoá `/etc/nginx`, log và cache của nginx, `/etc/opt/remi`, `/opt/remi`, các thư mục shim `/etc/php`, rồi chạy `cagefsctl --force-update`.
- Kết quả: Apache 0 khác biệt, LiteSpeed chỉ còn 4 khác biệt (F30), `/` dùng 6,1 GB.

**F35 — Helper chạy thường trực** (`snpanel-helper.service --serve`).
- Thay binary mà chỉ restart socket thì tiến trình cũ vẫn chạy.
- → `update.sh` và lệnh nâng cấp phải restart cả `snpanel-helper.service`.

**F36 — Các việc giao diện vẫn còn (theo plan):**
- *"The WAF engine is not installed"*: phần WAF hiện chỉ hiểu ModSecurity của nginx; `mod_security2` cho Apache/LiteSpeed thuộc phase C.
- *"No backup schedule"*: không phải lỗi. Máy thử chưa có lịch backup.
- Tạo và sửa site qua panel vẫn cần phase B (tách lớp web/PHP).
