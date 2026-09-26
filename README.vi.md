# SNPanel

[English](README.md) | **Tiếng Việt**

SNPanel là control panel quản lý hosting gọn nhẹ cho Ubuntu, Debian và
AlmaLinux. Bạn chạy website WordPress và PHP từ một giao diện web gọn gàng -
có sẵn tài khoản và gói dịch vụ, hạn mức, sao lưu, SSL, tường lửa và WAF.
SNPanel viết bằng Rust: một file chạy duy nhất phục vụ panel, và một helper
nhỏ chạy quyền root làm các việc cần đặc quyền phía sau.

## Tính năng

**Website**

- Cài WordPress một chạm, kèm WP-CLI; PHP 8.4 mặc định, có sẵn 8.3, cài thêm
  phiên bản khác ngay trong panel
- Website WordPress và PHP, mỗi site sửa được vhost nginx riêng
- SSL Let's Encrypt qua certbot
- Trình quản lý tệp: tải lên, sửa, nén và giải nén
- Cơ sở dữ liệu MariaDB, đăng nhập phpMyAdmin một chạm (token 60 giây); mỗi
  cơ sở dữ liệu thuộc về một người dùng panel và đi cùng họ trong bản sao lưu
- Quản lý cron, với các lệnh WP-CLI cho phép sẵn
- Terminal cho từng website, chạy các lệnh được phép dưới user Linux của
  chính website đó

**Tài khoản**

- Hai vai trò: quản trị viên và người dùng cuối (khách hàng)
- Mỗi người dùng panel là một user Linux, có tài khoản SFTP bị giới hạn
  (chroot) trong thư mục home của mình; website nằm ở
  `/home/<user>/<tên miền>/public_html`
- Giới hạn số website, dung lượng và các gói dùng lại được cho từng người dùng
- Quản trị viên đăng nhập thay khách hàng để tạo website cho họ, và chuyển
  website sang chủ khác
- Đăng nhập 2 bước bằng passkey, mã từ ứng dụng xác thực (TOTP), hoặc cả hai

**Sao lưu**

- File website cùng cơ sở dữ liệu; lịch sao lưu toàn bộ tài khoản; khôi
  phục, tải lên và tải về
- Bản sao ra ngoài máy chủ: máy chủ SFTP và bucket S3 - AWS S3, Cloudflare
  R2, Backblaze B2, Wasabi, MinIO hoặc bất kỳ dịch vụ tương thích S3 nào
- Đặt tên bản sao lưu theo ngày giờ, theo tên người dùng, theo thứ trong tuần
  hoặc theo ngày, mỗi cách giữ số bản theo lịch đã đặt

**Bảo mật**

- Tường lửa nftables: cổng panel, web và mail luôn mở, luật cho phép và chặn
  theo địa chỉ, danh sách chặn từ URL nạp thẳng vào set của nftables
- WAF ModSecurity cho nginx với bộ luật WordPress, Laravel, PHP của panel và
  OWASP Core Rule Set, bật tắt theo từng website; giới hạn HTTP flood và chặn
  bot
- Quét mã độc: ClamAV kiểm tra tệp ngay khi tải lên, Linux Malware Detect
  quét một website, mọi website hoặc toàn máy - khi cần hoặc theo lịch - và
  chuyển những gì tìm thấy vào khu cô lập

**Máy chủ**

- Trang tổng quan: CPU, RAM, ổ đĩa và mạng; mỗi mảng một thẻ xanh, vàng hoặc
  đỏ; và những việc cần xử lý, việc nặng nhất trước, kèm cách khắc phục
- Cấu hình PHP theo từng phiên bản, cài hoặc gỡ PHP extension ngay trên trang -
  redis, imagick, memcached, mongodb, apcu, xdebug và nhiều hơn
- PHP-FPM và MariaDB tự điều chỉnh theo RAM và CPU của máy
- Xem trạng thái và khởi động lại dịch vụ; cập nhật hệ điều hành qua apt hoặc
  dnf, ngay hoặc tự động; cập nhật SNPanel từ các bản phát hành
- Tiếng Anh và tiếng Việt, đổi ngay trên thanh tiêu đề - cả giao diện lẫn
  thông báo từ máy chủ

**Addon**, cài ở Cài đặt > Addon

- **Applications**: ứng dụng Node.js, container Docker và dự án Compose, mỗi
  cái một cổng và một giới hạn bộ nhớ riêng, chạy trên tên miền qua nginx
- **Fail2ban**: chặn trong nftables các địa chỉ dò mật khẩu SSH, đăng nhập
  panel, đăng nhập WordPress, thư mục có mật khẩu, và các địa chỉ tái phạm;
  không bao giờ chặn địa chỉ của Cloudflare từ log của website
- **Trợ lý AI (MCP)**: 32 công cụ cho Claude Code, Cursor, VS Code và mọi
  client MCP khác tại `/api/mcp`, trên website, tệp, log, sao lưu, tường lửa và
  WAF. Mỗi trợ lý dùng một token của tài khoản mà nó thay mặt, chỉ đọc trừ khi
  được cho phép thao tác, và mọi thao tác đều ghi vào nhật ký
- **Thông báo**, dành cho quản trị viên: e-mail qua máy chủ SMTP của bạn và
  Telegram qua bot của bạn - sao lưu lỗi, mã độc, chứng chỉ sắp hết hạn, ổ đĩa
  sắp đầy, dịch vụ dừng, phiên bản mới, đăng nhập và thay đổi ở tài khoản quản
  trị

## Yêu cầu

- Máy chủ mới cài Ubuntu 24.04 LTS, Debian 13 hoặc AlmaLinux 10, có quyền
  root
  - Debian 13 có nhiều phiên bản PHP nhất: từ 7.4 đến 8.5, lấy từ
    packages.sury.org
  - Trên AlmaLinux, trình cài đặt bật EPEL và Remi, PHP lấy từ Remi. Ở đó
    không có gói ModSecurity cho nginx, nên trang WAF chỉ có giới hạn HTTP
    flood và chặn bot. Trình cài đặt không cấu hình SELinux.
  - Chưa hỗ trợ Ubuntu 26.04: kho PHP cho Ubuntu chưa phát hành cho bản này,
    nên chỉ có PHP 8.5 của bản phân phối
  - Debian 12 cài được, nhưng chưa được kiểm thử kỹ như ba bản trên
- Tối thiểu 1 vCPU và 1 GB RAM; khuyến nghị 2 vCPU và 2 GB RAM
- Không bắt buộc: một tên miền trỏ về máy chủ, để panel có SSL riêng

## Cài đặt

Chạy bằng root trên máy chủ mới:

```bash
curl -fsSL https://raw.githubusercontent.com/vnscorpion/snpanel/refs/heads/main/install.sh | bash
```

Script cài bản phát hành mới nhất và sẽ hỏi:

- tên miền của panel - không bắt buộc; bỏ trống thì panel dùng IP của máy chủ
- cổng của panel - mặc định `2222`; tường lửa chỉ mở cổng này cho panel
- có cấp SSL Let's Encrypt cho tên miền panel không, và e-mail dùng cho SSL

Sau đó script cài nginx, MariaDB, Redis, OpenSSH/SFTP, PHP 8.4 và 8.3,
Node.js, certbot, phpMyAdmin, WP-CLI và nftables; tạo tài khoản dịch vụ
`snpanel`, tài khoản `admin` và dịch vụ `snpanel-api`; điều chỉnh PHP-FPM và
MariaDB theo cấu hình máy; rồi in ra địa chỉ panel, tên đăng nhập và mật
khẩu, đồng thời lưu vào `/root/login.txt`. Hãy cất mật khẩu vào trình quản
lý mật khẩu.

Panel mở được trên mọi tên miền đang host trên máy chủ: panel giữ chứng chỉ
của từng tên miền và chọn đúng chứng chỉ cho mỗi kết nối, nên
`https://<tên miền bất kỳ trên máy>:<cổng panel>` đều mở được với chứng chỉ
hợp lệ. `snpanel login` liệt kê các địa chỉ này.

Để kiểm tra một bản cài, chạy `xtask acceptance` bằng root trên máy chủ: lệnh
này tạo một website tạm, kiểm tra PHP chạy qua nginx và WAF báo đúng trạng
thái, rồi xoá website tạm đi.

## Cập nhật

Từ trang **Cập nhật** trong panel, hoặc qua SSH:

```bash
snpanel-update --release      # bản phát hành mới nhất
snpanel-update --tag v1.0.0   # một bản phát hành cụ thể
```

Nếu sau khi cập nhật trình duyệt vẫn hiện giao diện cũ, tải lại bằng
Ctrl + Shift + R.

## Cứu hộ qua SSH

Chạy `snpanel` bằng root để mở menu dùng khi không vào được panel web: xem
thông tin đăng nhập đã lưu, xem log gần đây, khởi động lại panel, mở lại các
cổng của tường lửa, đặt lại địa chỉ và cổng panel, sửa SSL của panel, sửa
quyền tệp, đổi mật khẩu admin và cập nhật.

```bash
snpanel change-ip OLD_IP NEW_IP      # máy chủ đổi địa chỉ IP
snpanel change-admin-password
snpanel sync-admin-root-password     # mật khẩu admin trùng mật khẩu root
snpanel reset-admin-2fa              # mất ứng dụng xác thực hoặc passkey
snpanel-rescue-firewall              # bị khoá ngoài: sao lưu luật, dựng lại tường lửa chỉ với các cổng bảo vệ
```

## Các thứ nằm ở đâu

| | |
|---|---|
| Chương trình | `/opt/snpanel` |
| Cấu hình | `/opt/snpanel/backend/.env`, `/etc/snpanel` |
| Dữ liệu trạng thái | `/var/lib/snpanel` |
| Bản sao lưu | `/var/backups/snpanel` |
| Website | `/home/<user>/<tên miền>/public_html` |
| User hệ thống | `snpanel` |
| Dịch vụ | `snpanel-api`, `snpanel-helper` |
| Log | `journalctl -u snpanel-api` |

```bash
systemctl restart snpanel-api
systemctl status snpanel-api nginx mariadb redis-server php8.3-fpm php8.4-fpm
nginx -t && systemctl reload nginx
```

## Tường lửa

Việc lọc gói tin chạy trên nftables, trong một bảng riêng của panel
(`inet snpanel`). Các luật nằm trong `/var/lib/snpanel/firewall/rules.tsv`;
mỗi lần thay đổi, panel dựng lại cả bảng, kiểm tra bằng `nft --check` rồi nạp
một lần, và `snpanel-firewall.service` nạp lại bảng khi khởi động máy, trước
mạng và nginx.

- Cổng SSH, cổng panel và 80, 443, 465, 587 luôn mở, không đóng được từ panel.
- Luật cho phép và chặn, có hoặc không kèm cổng, là phần tử của set nftables;
  luật cho phép được xét trước.
- Danh sách chặn từ URL được tải mỗi ngày vào set riêng, cả IPv4 và IPv6: một
  danh sách một triệu địa chỉ chỉ tốn một lần tra cứu cho mỗi gói tin.
- Lưu lượng được cho phép rời bảng bằng `return` chứ không phải `accept`, nên
  fail2ban và các luật khác trên máy vẫn thấy nó.
- Tắt tường lửa chỉ gỡ bảng của panel, không đụng gì khác.

Bản cài cũ lọc bằng UFW, iptables hoặc blocklist `geo` của nginx sẽ được
chuyển luật sang khi cập nhật. Nếu trước đó không có tường lửa nào đang chạy,
các luật được chuẩn bị sẵn nhưng chưa áp dụng cho tới khi bật ở trang Tường
lửa.

## Tài khoản, quyền sở hữu và hạn mức

| Vai trò | Được làm |
|------|-----|
| `admin` | Mọi thứ: website, người dùng và gói của họ, quyền sở hữu, dịch vụ, tường lửa, PHP, sao lưu và cài đặt panel |
| `end_user` | Website của mình cùng tệp, cơ sở dữ liệu, SSL, công cụ WordPress và cron của chúng, và bản sao lưu của mình |

- User Linux của người dùng panel cùng tên với họ, và chính là tài khoản SFTP,
  bị giới hạn trong thư mục home - `admin` là `/home/admin`. Mật khẩu SFTP đi
  theo mật khẩu panel, trừ khi quản trị viên tắt SFTP của người dùng đó hoặc
  đặt cho nó mật khẩu riêng; người dùng xem thông tin SFTP và đổi mật khẩu
  SFTP ở trang Bảo mật tài khoản.
- Các tài khoản này thuộc nhóm `snpanel-sftp`: chỉ SFTP - không shell, không
  terminal, không chuyển tiếp cổng.
- Mỗi cơ sở dữ liệu có một chủ sở hữu. Quản trị viên tạo được cơ sở dữ liệu
  cho bất kỳ người dùng nào, và đổi chủ cũng như website của nó; chuyển một
  website sang người dùng khác thì cơ sở dữ liệu, tệp, cấu hình PHP-FPM và
  nginx của nó đi theo.
- Xoá một người dùng là xoá mọi thứ của họ: website, tệp, cơ sở dữ liệu, cron,
  pool PHP-FPM và user Linux.
- Người dùng cuối có giới hạn số website và dung lượng tính bằng MB, cộng trên
  mọi website của họ và được kiểm tra trước mọi thao tác ghi - tạo website,
  tải lên, sửa, nén, giải nén, nhận website. Đây là hạn mức của panel, không
  phải quota ổ đĩa; quản trị viên không bị giới hạn.

## Cấu hình

Trình cài đặt ghi file `/opt/snpanel/backend/.env`:

```ini
APP_ENV=production
SECRET_KEY=<ngẫu nhiên, từ 32 byte>
COMMAND_DRY_RUN=false
DATABASE_URL=sqlite:////opt/snpanel/backend/snpanel.db
REDIS_URL=redis://localhost:6379/0
RATE_LIMIT_BACKEND=redis
ALLOWED_ORIGINS=https://panel.example.com
BACKUP_ROOT=/var/backups/snpanel
SSL_EMAIL=admin@example.com
PANEL_URL=http://SERVER_IP:2222
PANEL_DOMAIN=
PANEL_PORT=2222
PANEL_SSL_CERT=                   # chứng chỉ cho tên miền chưa có chứng chỉ riêng
PANEL_SSL_KEY=
PANEL_SNI_DIR=/etc/snpanel/sni    # mỗi tên miền một chứng chỉ
FRONTEND_DIST=/opt/snpanel/frontend/dist
```

Ở môi trường production, panel không khởi động nếu `COMMAND_DRY_RUN=true`,
`ALLOWED_ORIGINS=*` hoặc `SECRET_KEY` ngắn hơn 32 ký tự.

**Điều chỉnh PHP-FPM và MariaDB.** Mỗi website PHP có một pool PHP-FPM riêng
(`ondemand`), kích thước tính theo RAM, số CPU và số pool của máy; MariaDB có
file `/etc/mysql/mariadb.conf.d/90-snpanel-tuning.cnf`, tính theo RAM và CPU,
chừa chỗ cho nginx, PHP-FPM, Redis và panel. Muốn tự đặt, thêm các biến sau
vào `.env` rồi điều chỉnh lại:

```ini
SNPANEL_PHP_FPM_WORKER_MB=128
SNPANEL_PHP_FPM_MAX_CHILDREN=
SNPANEL_PHP_FPM_IDLE_TIMEOUT=
SNPANEL_PHP_FPM_MAX_REQUESTS=
SNPANEL_PHP_FPM_REQUEST_TERMINATE_TIMEOUT=300
SNPANEL_MARIADB_BUFFER_POOL_SIZE=
SNPANEL_MARIADB_MAX_CONNECTIONS=
SNPANEL_MARIADB_THREAD_CACHE_SIZE=
SNPANEL_MARIADB_TABLE_OPEN_CACHE=
SNPANEL_MARIADB_TMP_TABLE_SIZE=
SNPANEL_MARIADB_MAX_ALLOWED_PACKET=
SNPANEL_MARIADB_LOG_FILE_SIZE=
SNPANEL_MARIADB_IO_CAPACITY=
SNPANEL_MARIADB_OPEN_FILES_LIMIT=
```

```bash
sudo -u snpanel env HOME=/opt/snpanel sudo -n /usr/local/sbin/snpanel-helper php-fpm-retune
sudo -u snpanel env HOME=/opt/snpanel sudo -n /usr/local/sbin/snpanel-helper mariadb-retune
```

## Mô hình bảo mật

Panel không chạy bằng root. `snpanel-api` chạy dưới user hệ thống `snpanel`
trong một unit systemd đã siết chặt, và nhờ một helper chạy root làm mọi việc
cần đặc quyền:

```
snpanel-api      (user snpanel, unit systemd đã siết chặt)
   |  /run/snpanel/helper.sock - yêu cầu có kiểu; kiểm tra bên gọi bằng SO_PEERCRED
   v
snpanel-helper   (root; chỉ trả lời danh sách thao tác của nó, ngoài ra không gì cả)
```

Helper kiểm tra mọi tên miền, cổng, địa chỉ và đường dẫn trước khi chạy bất
cứ thứ gì: dịch vụ trong danh sách cho phép, `nginx -t` và reload, certbot cho
một tên miền đã kiểm tra, người dùng panel và pool PHP-FPM của họ, luật tường
lửa, quyền sở hữu thư mục website dưới `/home`, WP-CLI và cron dưới user của
website, và các lệnh được phép của terminal. Kể cả khi chính API bị chiếm
quyền, kẻ tấn công chỉ ghi được vào `conf.d` của nginx, thư mục website được
quản lý và thư mục sao lưu, và chỉ gọi được các thao tác trên của helper -
không có đường nào từ đó lên root.

Terminal chạy lệnh không qua shell - `;`, `|`, dấu backtick và ký tự đại diện
chỉ là tham số bình thường - kiểm tra mọi đường dẫn nằm trong home của người
dùng, chạy các công cụ PHP bằng đúng phiên bản PHP của website, và dừng lệnh
sau 60 giây, hoặc 900 giây với các trình cài đặt như `composer`, `npm`, `wp`
và `git`. Danh sách lệnh cho phép là hàng rào chứ không phải ranh giới: các
website tách biệt nhau nhờ user Linux riêng, home bị chroot, `open_basedir`
của PHP-FPM và việc kiểm tra đường dẫn của helper.

- Đăng nhập bị giới hạn tần suất trong Redis - 8 lần mỗi phút, khoá sau 20
  lần sai - và mất cùng một khoảng thời gian dù người dùng có tồn tại hay
  không.
- Phiên đăng nhập là cookie HttpOnly (`snpanel_session`) kèm token CSRF
  (`snpanel_csrf`) gửi lại trong header `X-CSRF-Token`; JavaScript không bao
  giờ đọc được token. Đổi mật khẩu, vai trò hay xác minh 2 bước, vô hiệu hoá
  tài khoản hoặc đăng xuất đều thu hồi các phiên đã cấp trước đó.
- Content-Security-Policy chặt chẽ (`script-src 'self'`,
  `frame-ancestors 'none'`).
- Mật khẩu cơ sở dữ liệu và WordPress được truyền cho lệnh qua stdin, không
  bao giờ nằm trên dòng lệnh; mật khẩu cơ sở dữ liệu được mã hoá khi lưu.
- Khối nginx tuỳ chỉnh được kiểm tra: ngoặc phải cân, tối đa 16 KB, và không
  có các chỉ thị `server`, `http`, `include`, `load_module`, `proxy_pass`,
  `alias`, log hay `ssl_*`.
- Trình quản lý tệp từ chối symlink ở bất kỳ đâu trong đường dẫn, và đường dẫn
  ra ngoài website.
- Trong website, tệp có quyền `644` và thư mục `755`; `wp-config.php`, `.env`
  và `.my.cnf` được giữ ở `640`.

## API cấp tài khoản (WHMCS)

Module máy chủ WHMCS trong `modules/servers/snpanel/` tạo và quản lý tài
khoản panel qua API cấp tài khoản, dùng Bearer token tạo ở tab API token của
Cài đặt panel và dán vào ô Access Hash của máy chủ. Module dùng chung với
OPanel, nên SNPanel trả lời đúng cách module mong đợi.

| WHMCS | Endpoint |
|---|---|
| `TestConnection`, `PackageLoader` | `GET /plans` |
| `CreateAccount` | `POST /accounts` |
| `SuspendAccount` | `POST /accounts/{external_id}/suspend` |
| `UnsuspendAccount` | `POST /accounts/{external_id}/unsuspend` |
| `TerminateAccount` | `DELETE /accounts/{external_id}` |
| `ChangePassword` | `PATCH /accounts/{external_id}/password` |
| `ChangePackage` | `PATCH /accounts/{external_id}/package` |
| `UsageUpdate` | `GET /accounts/{external_id}/usage` |
| `LoginLink`, `ClientArea` | `POST /accounts/{external_id}/login` |

- `external_id` có dạng `whmcs:<serviceid>`, nên mỗi dịch vụ là đúng một tài
  khoản panel dù có đổi tên.
- SNPanel trả về object trần - không bao giờ có cùng lúc `success` và `data`,
  thứ mà module sẽ bóc ra.
- Đăng nhập một chạm trả về `login_url`, địa chỉ đầy đủ trên tên miền mà lời
  gọi API đến (hoặc `PANEL_URL`), dùng được một lần trong 5 phút. Tài khoản bị
  tạm ngưng sẽ được đưa tới `/?error=account_suspended`.
- Tạm ngưng sẽ khoá đăng nhập panel, kết thúc các phiên của tài khoản, hiện
  trang "tạm ngưng" cho từng website của nó và khoá các user Linux; mở lại thì
  trả mọi thứ như cũ.
- Huỷ tài khoản không sao lưu trừ khi yêu cầu bằng `?backup=true` - khi đó bản
  sao lưu đầy đủ được ghi vào `/var/backups/snpanel` trước; sao lưu lỗi cũng
  không chặn việc huỷ. Dòng dữ liệu tính cước vẫn được giữ, để trống, để khu
  vực khách hàng vẫn hiển thị được dịch vụ.

## Phát triển

- **Panel**: Rust - axum, rustls, sqlx (SQLite), tokio; một file chạy tĩnh
  phục vụ cả API lẫn giao diện qua TLS trên cổng panel
- **Helper**: Rust, chạy root, sau một Unix socket có kiểm tra bên gọi
- **Giao diện**: React 18, Vite, lucide-react
- **Máy chủ**: nginx, OpenSSH/SFTP, ModSecurity, nftables, systemd, MariaDB,
  Redis (Valkey trên AlmaLinux), PHP-FPM, certbot

```
snpanel/
|-- crates/
|   |-- snpanel-api/         API HTTP và các tác vụ của panel
|   |-- snpanel-helper/      các thao tác cần đặc quyền
|   |-- snpanel-ipc/         giao thức giữa hai phần trên
|   |-- snpanel-core/        cấu hình, mã hoá, vai trò
|   |-- snpanel-db/          schema và truy vấn cơ sở dữ liệu
|   |-- snpanel-nginx/       mẫu vhost
|   |-- snpanel-osabi/       khác biệt giữa các bản phân phối
|   |-- snpanel-installer/   phần script cài đặt và cập nhật gọi tới
|   `-- snpanel-cli/         lệnh `snpanel`
|-- frontend/                giao diện React
|-- installer/               script cài đặt, cập nhật và cứu hộ tường lửa
|-- modules/servers/snpanel/ module WHMCS
|-- xtask/                   tác vụ build và kiểm tra
`-- backend/                 trên máy chủ: `.env` và cơ sở dữ liệu SQLite
```

## Phiên bản

SNPanel đánh số phiên bản theo semantic versioning (`major.minor.patch`).
Bản phát hành hiện tại là `1.0.0`.

## Giấy phép

MIT.
