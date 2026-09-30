# SNPanel Hosting Edition: nâng cấp từ 1.1.0 lên CloudLinux và LiteSpeed Enterprise

Có ba bước. Bước sau cần bước trước:

```
Bước 0  panel 1.1.0 (Standard)  ->  panel bản Hosting Edition     apply-bundle.sh       không gián đoạn site
Bước 1  AlmaLinux 10 + nginx     ->  CloudLinux 10 + Apache        upgrade-cloudlinux.sh MỘT CHIỀU
Bước 2  Apache                   ->  LiteSpeed Enterprise live     install-litespeed.sh  đảo ngược được (--remove)
                                      (Apache dự phòng nóng)
```

Mọi script đều **chạy lại được**:
- Mỗi bước tự xem máy đã có kết quả chưa. Bước nào xong rồi thì bỏ qua.
- Lỗi ở đâu thì sửa nguyên nhân rồi chạy lại đúng lệnh cũ.
- `--check` chỉ báo bước nào đã xong, bước nào chưa. Nó không đổi gì trên máy.
- Nhật ký nằm ở `/var/log/snpanel-upgrade.log`.

## Điều kiện

- VPS KVM, VMware hoặc máy vật lý. **Không** dùng container (LXC/OpenVZ): LVE cần kernel thật.
- x86_64 có CPU đạt x86-64-v3, **AlmaLinux 10**, RAM ≥ 2 GB, đĩa trống ≥ 25 GB (riêng skeleton CageFS đã khoảng 3,5 GB).
  - Máy Ubuntu/Debian: backup/restore SNPanel sang một máy AlmaLinux 10 mới trước.
- SNPanel 1.1.0 trở lên đã cài và đang chạy.
- **Snapshot VPS trước bước 1.** `cldeploy` đổi cả hệ điều hành và không có đường lui.
- Key CloudLinux cho bước 1, serial LiteSpeed cho bước 2 (hoặc `--trial`, dùng thử 14 ngày).

## Bước 0: đưa bản Hosting Edition lên máy

Trên máy build (có `cargo` và target `x86_64-unknown-linux-musl`), từ nhánh `feat/hosting-waf`:

```bash
bash installer/hosting/make-bundle.sh
# -> dist/snpanel-hosting-<version>-<commit>.tar.gz và .sha256
scp dist/snpanel-hosting-*.tar.gz* root@SERVER:/root/
```

Trên server:

```bash
cd /root && sha256sum -c snpanel-hosting-*.tar.gz.sha256
tar -xzf snpanel-hosting-*.tar.gz            # -> /root/snpanel-hosting
bash /root/snpanel-hosting/installer/hosting/apply-bundle.sh
```

Script tự chọn cách cập nhật theo loại máy:
- **Máy còn nginx:** chạy `installer/update.sh --skip-pull` từ source trong bundle, đúng như cập nhật một release. Nó sinh lại unit, build frontend, restart panel.
- **Máy đã lên Hosting Edition:** chỉ thay binary và build lại frontend. Dùng cách này cho các lần cập nhật sau khi đã nâng cấp, vì `update.sh` vẫn giả định có nginx.

## Bước 1: CloudLinux

```bash
H=/root/snpanel-hosting/installer/hosting
bash $H/upgrade-cloudlinux.sh --check                 # xem trước
bash $H/upgrade-cloudlinux.sh --key <CLOUDLINUX_KEY>  # sao lưu, convert (~5 phút, site vẫn chạy)
systemctl reboot
SNPANEL_ADMIN_PASSWORD='<mật khẩu admin panel>' bash $H/upgrade-cloudlinux.sh   # phần còn lại
```

Nếu không đặt `SNPANEL_ADMIN_PASSWORD`, script sẽ hỏi mật khẩu. Để trống thì bước "PHP riêng cho từng website" bị bỏ qua; chạy lại sau để làm bước đó. Tài khoản bật 2FA thì không đăng nhập được: đặt PHP cho từng site trong trang Websites.

| # | Bước | Site có gián đoạn? |
|---|---|---|
| 1 | Sao lưu `snpanel.db`, `.env`, `/etc/nginx`, pool FPM, ruleset nft, danh sách gói vào `/root/snpanel-upgrade-backup/<thời điểm>/` | không |
| 2 | `cldeploy --conversion-only` (key đi qua biến môi trường, không lộ trên dòng lệnh), sau đó **khởi động lại** | chỉ lúc reboot |
| 3 | Xác nhận kernel LVE đã nạp | không |
| 4 | Cài Apache, mod_ssl, mod_security, mod_lsapi, CageFS, lvemanager và alt-php. Mặc định 8.1–8.5, cộng mọi bản website đang dùng (`--php` để đổi) | không |
| 5 | CageFS skeleton, PHP Selector (mặc định `--default-php 8.4`), PHP native thành **file thật** (`/usr/bin/php`, `php-cgi`, `/etc/php.ini`, `/usr/local/bin/lsphp`), bật `nd_mysqli`/`nd_pdo_mysql`/`opcache` cho mọi bản | không |
| 6 | Apache trên 8080/8443, chạy song song với nginx. Có drop-in `ProtectHome=no`, log dùng chung với LiteSpeed, vhost tools, file health | không |
| 7 | CPAPI (`integration.ini`, snapshot mount vào cage), D-Bus policy cho user `snpanel`, CloudLinux Manager trong panel (`snpanel-cloudlinux-ui`, sudoers) | không |
| 8 | Mọi tài khoản panel vào CageFS. Phiên bản PHP của mỗi tài khoản = bản mà đa số site của tài khoản đó dùng | không |
| 9 | Script `snpanel-webswitch` và timer giữ bảng nft 80/443 | không |
| 10 | **Cutover:** tắt và gỡ nginx, panel ghi lại vhost Apache cho mọi site (`--refresh-sites`), nft chuyển 80/443 sang 8080/8443, tắt PHP-FPM. In mã HTTP của từng site trước và sau | **có**, trong lúc gỡ nginx và ghi vhost (thường dưới 1 phút) |
| 11 | PHP riêng cho từng website: site cùng bản với tài khoản thì theo tài khoản, site khác bản thì dùng bản riêng qua MultiPHP | vài giây mỗi site |
| 12 | MySQL Governor: dump toàn bộ database trước, rồi `mysqlgovernor.py`. Để ở chế độ quan sát (`dbctl --lve-mode off`) và bật timer `snpanel-dbuser-map`. Bỏ bước này bằng `--no-governor` | database lỗi khoảng 1,5 phút (đo được 95 giây) |

Số đo từ buổi thử CL-0 (20 site):
- Convert: 5 phút 13 giây, không làm gián đoạn site.
- Chuyển nginx sang Apache: khoảng 1,1 giây. Lần đó dùng cổng 80 trực tiếp; qua nft thì thêm thời gian ghi vhost.
- Governor: site dùng database lỗi 95 giây.

## Bước 2: LiteSpeed Enterprise

```bash
bash $H/install-litespeed.sh --check
bash $H/install-litespeed.sh --serial XXXX-XXXX-XXXX-XXXX     # hoặc --trial
```

1. Cài LiteSpeed bằng `install.sh` gốc, không cần hỏi đáp.
   - Chọn chế độ "đọc cấu hình Apache" (lựa chọn DirectAdmin), port offset 1000, PHP suEXEC.
   - Mật khẩu WebAdmin được sinh ngẫu nhiên và **chỉ in ra một lần**. Đổi lại trong panel: Services > Web server.
2. Cấu hình: `enableLVE`, mount `/usr/local/lsws` vào CageFS, log. LiteSpeed nghe 9080/9443.
3. So mã HTTP của từng site giữa Apache (8080) và LiteSpeed (9080).
   - Có site lệch thì **dừng lại, chưa chuyển**. LiteSpeed vẫn chạy trên 9080 để kiểm tra; dùng `--force` nếu chấp nhận.
   - Không lệch thì nft chuyển 80/443 sang LiteSpeed (không gián đoạn) và bật `snpanel-webwatch`.
4. Watchdog: LiteSpeed không trả lời 3 lần liền (mỗi giây một lần) hoặc hết license thì Apache nhận lại 80/443 sau khoảng 3,4 giây. Watchdog **không tự chuyển về**; bấm "Switch back to LiteSpeed" trong trang Services.

Quay lại chỉ Apache (bước 1): `bash $H/install-litespeed.sh --remove`.

## Quay lui

- **Bước 2:** dùng `--remove`, không gián đoạn.
- **Bước 1:** không quay lui được, vì `cldeploy` là một chiều. Chỉ có cách khôi phục snapshot VPS.
  - Cấu hình nginx và pool FPM cũ nằm trong `/root/snpanel-upgrade-backup/<thời điểm>/`.
  - Dump database trước khi cài Governor là `pre-governor.sql` trong cùng thư mục.

## File cài lên máy

| Trong `files/` | Đích | Dùng cho |
|---|---|---|
| `00-snpanel.conf`, `00-snpanel-listen.inc` | `/etc/httpd/conf.d/` | Apache: cổng cố định 8080/8443, nạp vhost của panel |
| `httpd-snpanel.conf` | `/etc/systemd/system/httpd.service.d/snpanel.conf` | `ProtectHome=no` (khách ghi được file của mình) |
| `snpanel-weblogs.conf` | `httpd.service.d/`, `lshttpd.service.d/` | quyền `/var/log/httpd` cho log của LiteSpeed |
| `snpanel-mysql.ini` | `/opt/alt/phpXX/etc/php.d/` | MySQL cho PHP native (phpMyAdmin, WP-CLI) |
| `snpanel-cpapi`, `snpanel.cagefs.cfg` | `/usr/local/lib/snpanel/`, `/etc/cagefs/conf.d/snpanel.cfg` | tích hợp CloudLinux (CPAPI) |
| `snpanel-ui-user-info`, `cloudlinux-ui-router.php`, `snpanel-cloudlinux-ui.service`, `snpanel-lvemanager.sudoers` | `/usr/local/lib/snpanel/`, `/etc/systemd/system/`, `/etc/sudoers.d/` | CloudLinux Manager trong panel |
| `snpanel-systemd-read.conf` | `/etc/dbus-1/system.d/` | panel đọc trạng thái dịch vụ khi có CageFS |
| `snpanel-webswitch`, `snpanel-webswitch-restore`(`.service`, `.timer`) | `/usr/local/sbin/`, `/etc/systemd/system/` | bảng nft 80/443, áp lại sau boot và mỗi phút |
| `snpanel-webwatch`(`.service`) | như trên | watchdog LiteSpeed |
| `snpanel-dbuser-map`(`.service`, `.timer`) | như trên | map database user sang tài khoản cho MySQL Governor |

## Còn mở

- **Chưa chạy trọn trên một máy AlmaLinux 10 mới.**
  - Các script được viết từ đúng những lệnh đã chạy tay trên máy thử.
  - Trên máy thử đã kiểm chứng `--check` và việc chạy lại (các bước đã xong được bỏ qua).
  - Lần chạy đầu trên máy mới nên có người theo dõi.
- **License LiteSpeed hết hạn** (F23) chưa thử được. Trial trên máy thử hết hạn khoảng 12/10.
- **phpMyAdmin vẫn là RPM của EPEL.** Gói này kéo theo `nginx-filesystem` và `php8.4-fpm` (đã mask). Nên chuyển sang tarball upstream.
- **Giới hạn số kết nối** (connection limit) của chống flood chưa có tương đương trên ModSecurity. Giới hạn theo số request thì có.
