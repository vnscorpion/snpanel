//! Notifications - the addon that tells the panel's administrators, by
//! e-mail and on Telegram, what they would otherwise only find by opening
//! the panel.
//!
//! Not in the Python. It is the administrators' alone: no customer is sent
//! anything, or sees its page. What it keeps is in `notifications.json` in
//! the data directory, mode 0600, the SMTP password and the bot token
//! Fernet-encrypted with the panel's key - see [`Channels`]:
//!
//! - **E-mail**: an SMTP server, and the addresses it sends to - by default
//!   every active administrator's own.
//! - **Telegram**: a bot, and the chat it writes in - a person's, or a group
//!   or channel the administrators share.
//! - **What is told**, and in which language.
//!
//! What can be told - see [`KINDS`] - is of every account's websites and
//! backups (a backup that failed, malware, a certificate about to expire, an
//! account nearly out of storage), of the machine (the disk filling, a
//! service stopping, a new release), and of the administrator accounts
//! themselves (a sign-in from an address new to one, a change to how one
//! signs in, a new administrator). A customer's own sign-ins and passwords
//! are the customer's, and are not told.
//!
//! Each event is written in English and Vietnamese here. Nothing is sent
//! while the addon is not installed, or while there is nowhere to send it;
//! what was sent, and what failed, is in `notification_log`.

pub mod smtp;
pub mod telegram;
pub mod watcher;

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use snpanel_core::crypto::fernet;
use snpanel_db::notifications::NewLogEntry;
use snpanel_db::User;

use crate::state::AppState;

// ---------------------------------------------------------------- channels

/// How mail goes out, and to whom.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    /// `starttls`, `tls` or `none` - [`smtp::Security`].
    pub security: String,
    #[serde(default)]
    pub username: String,
    /// Fernet-encrypted; empty when the server takes no password.
    #[serde(default)]
    pub password: String,
    pub from_address: String,
    #[serde(default)]
    pub from_name: String,
    /// Where messages go; none is every active administrator's own address.
    #[serde(default)]
    pub to: Vec<String>,
}

/// The Telegram bot messages come from, and the chat they go to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelegramConfig {
    /// Fernet-encrypted.
    pub token: String,
    /// The bot's `@username`, as `getMe` said when the token was saved.
    pub username: String,
    /// The chat, as Telegram numbers it: a person's, a group's (negative) or
    /// a channel's. Empty in a file saved before there was one - nothing
    /// goes to Telegram then.
    #[serde(default)]
    pub chat_id: String,
    /// What Telegram calls that chat, for the page and the log.
    #[serde(default)]
    pub chat_name: String,
}

/// Everything the addon keeps.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Channels {
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,
    #[serde(default)]
    pub telegram: Option<TelegramConfig>,
    /// `en` or `vi`; Vietnamese when none was chosen.
    #[serde(default)]
    pub language: Option<String>,
    /// `{event: bool}`: an event not in it takes its default.
    #[serde(default)]
    pub events: BTreeMap<String, bool>,
}

impl Channels {
    /// The bot and the chat it writes in, when both are set.
    pub fn telegram_chat(&self) -> Option<(&TelegramConfig, &str)> {
        self.telegram
            .as_ref()
            .filter(|bot| !bot.chat_id.is_empty())
            .map(|bot| (bot, bot.chat_id.as_str()))
    }

    /// Whether a message has anywhere to go.
    pub fn ready(&self) -> bool {
        self.smtp.is_some() || self.telegram_chat().is_some()
    }

    /// Whether `key` is told.
    pub fn wants(&self, key: &str) -> bool {
        self.events
            .get(key)
            .copied()
            .unwrap_or_else(|| kind(key).is_some_and(|k| k.default_on))
    }

    /// The language messages are written in.
    pub fn lang(&self) -> Lang {
        Lang::parse(self.language.as_deref()).unwrap_or(Lang::Vi)
    }
}

fn data_dir() -> PathBuf {
    PathBuf::from(std::env::var("SNPANEL_DATA_DIR").unwrap_or_else(|_| "/var/lib/snpanel".into()))
}

fn channels_file() -> PathBuf {
    data_dir().join("notifications.json")
}

/// The channels as saved; none when nothing is, or the file cannot be read.
pub fn load_channels() -> Channels {
    std::fs::read_to_string(channels_file())
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// Write them 0600 through a rename, so a reader never sees half a file
/// and nobody but the panel reads even the encrypted secrets.
pub fn save_channels(channels: &Channels) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = channels_file();
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(channels).map_err(std::io::Error::other)?;
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(&body)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, &path)
}

/// A stored secret back in the clear, or `None` when it cannot be.
pub fn reveal(state: &AppState, stored: &str) -> Option<String> {
    if stored.is_empty() {
        return Some(String::new());
    }
    fernet::decrypt(
        &state.settings.secret_key,
        Some(stored),
        state.settings.strict_decrypt,
    )
    .ok()
}

pub fn conceal(state: &AppState, plain: &str) -> String {
    if plain.is_empty() {
        return String::new();
    }
    fernet::encrypt(&state.settings.secret_key, plain)
}

/// Whether the addon is on.
pub fn installed() -> bool {
    crate::routes::addons::notifications_installed()
}

// ---------------------------------------------------------------- the kinds

/// One kind of event, told or not as the administrators chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kind {
    pub key: &'static str,
    /// Where the page lists it: `accounts` - the websites and backups of
    /// every account - `server`, or `admins`, the administrator accounts.
    pub group: &'static str,
    /// Whether it is told before anyone chose.
    pub default_on: bool,
}

/// Every kind, in the order the page lists them.
pub const KINDS: &[Kind] = &[
    Kind {
        key: "backup_failed",
        group: "accounts",
        default_on: true,
    },
    Kind {
        key: "backup_done",
        group: "accounts",
        default_on: false,
    },
    Kind {
        key: "malware",
        group: "accounts",
        default_on: true,
    },
    Kind {
        key: "ssl_expiring",
        group: "accounts",
        default_on: true,
    },
    Kind {
        key: "storage_full",
        group: "accounts",
        default_on: true,
    },
    Kind {
        key: "disk_low",
        group: "server",
        default_on: true,
    },
    Kind {
        key: "service_down",
        group: "server",
        default_on: true,
    },
    Kind {
        key: "panel_update",
        group: "server",
        default_on: true,
    },
    Kind {
        key: "sign_in",
        group: "admins",
        default_on: true,
    },
    Kind {
        key: "security",
        group: "admins",
        default_on: true,
    },
];

pub fn kind(key: &str) -> Option<&'static Kind> {
    KINDS.iter().find(|k| k.key == key)
}

// ---------------------------------------------------------------- the words

/// A message's language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Vi,
}

impl Lang {
    pub fn parse(text: Option<&str>) -> Option<Self> {
        match text {
            Some("en") => Some(Self::En),
            Some("vi") => Some(Self::Vi),
            _ => None,
        }
    }
}

/// A piece of a message in both languages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Text {
    pub en: String,
    pub vi: String,
}

impl Text {
    pub fn new(en: impl Into<String>, vi: impl Into<String>) -> Self {
        Self {
            en: en.into(),
            vi: vi.into(),
        }
    }

    /// The same words in both: a path, a name, a server's own error.
    pub fn same(text: impl Into<String>) -> Self {
        let text = text.into();
        Self {
            en: text.clone(),
            vi: text,
        }
    }

    pub fn get(&self, lang: Lang) -> &str {
        match lang {
            Lang::En => &self.en,
            Lang::Vi => &self.vi,
        }
    }
}

/// What a message says: a subject, lines under it, and the panel page it
/// points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    pub subject: Text,
    pub lines: Vec<Text>,
    /// A path in the panel, such as `/backups`.
    pub page: &'static str,
}

/// One message an event makes: under which kind, saying what.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub key: &'static str,
    pub content: Content,
}

// ---------------------------------------------------------------- the events

/// One account's part in a scheduled backup's run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserBackup {
    pub username: String,
    /// Where the archive went, or why there is none.
    pub outcome: Result<String, String>,
}

/// A malware finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Threat {
    pub path: String,
    pub signature: String,
    pub domain: String,
    /// Whether it was moved to quarantine.
    pub quarantined: bool,
}

/// A certificate close to its end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expiring {
    pub domain: String,
    /// Whole days left; zero or less is expired.
    pub days: i64,
}

/// A change to how an administrator account signs in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Password,
    TwoFactorOn,
    TwoFactorOff,
    TwoFactorReset,
    PasskeyAdded(String),
    PasskeyRemoved(String),
    McpToken {
        name: String,
        can_write: bool,
    },
    SftpPassword(String),
    /// The account is an administrator now: made as one, or made one.
    Administrator,
}

/// Something that happened, as a hook reports it.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// A backup schedule ran, for these accounts; `problem` when it could
    /// not run for anyone.
    ScheduleRun {
        schedule: String,
        users: Vec<UserBackup>,
        problem: Option<String>,
    },
    /// A backup someone started by hand failed. One that finished is told
    /// by the page that started it.
    BackupFailed {
        /// The account that started it.
        by: String,
        /// The website or account it was of.
        what: String,
        why: String,
    },
    /// A scan found something.
    Malware { threats: Vec<Threat> },
    /// Certificates close to their end.
    SslExpiring { certificates: Vec<Expiring> },
    /// The disk holding `mount` is filling.
    DiskLow {
        mount: String,
        percent: f64,
        free: u64,
    },
    /// Services stopped, or running again.
    Services {
        stopped: Vec<String>,
        running_again: Vec<String>,
    },
    /// A newer release is out.
    PanelUpdate { current: String, latest: String },
    /// A customer's storage is nearly full.
    StorageFull {
        username: String,
        percent: f64,
        used: u64,
        limit: u64,
    },
    /// A sign-in to an administrator account from an address it has not
    /// signed in from.
    SignIn {
        username: String,
        address: String,
        agent: String,
        how: &'static str,
    },
    /// A change to how an administrator account signs in.
    Security {
        username: String,
        change: Change,
        address: String,
        /// The administrator who made it, when it was not the account's own.
        by: Option<String>,
    },
}

/// Bytes as people read them.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn percent(value: f64) -> String {
    format!("{value:.0}%")
}

/// At most `n` items, and how many more there were.
fn first<T>(items: &[T], n: usize) -> (&[T], usize) {
    let shown = items.len().min(n);
    (&items[..shown], items.len() - shown)
}

fn more(count: usize) -> Option<Text> {
    (count > 0).then(|| {
        Text::new(
            format!("... and {count} more"),
            format!("... và {count} mục khác"),
        )
    })
}

fn threat_lines(threats: &[Threat]) -> Vec<Text> {
    let (shown, rest) = first(threats, 10);
    let mut lines: Vec<Text> = shown
        .iter()
        .map(|t| Text::same(format!("{} - {}", t.path, t.signature)))
        .collect();
    lines.extend(more(rest));
    lines
}

fn malware_content(threats: &[Threat]) -> Content {
    let mut domains: Vec<&str> = threats
        .iter()
        .map(|t| t.domain.as_str())
        .filter(|d| !d.is_empty())
        .collect();
    domains.sort_unstable();
    domains.dedup();
    let quarantined = threats.iter().filter(|t| t.quarantined).count();
    let subject = match domains.as_slice() {
        [one] => Text::new(
            format!("Malware found on {one}"),
            format!("Phát hiện mã độc trên {one}"),
        ),
        [] => Text::new(
            "Malware found on the server",
            "Phát hiện mã độc trên máy chủ",
        ),
        many => Text::new(
            format!("Malware found on {} websites", many.len()),
            format!("Phát hiện mã độc trên {} website", many.len()),
        ),
    };
    let mut lines = vec![Text::new(
        format!(
            "{} infected file(s); {quarantined} moved to quarantine, where nothing serves or runs them. Put a file back from the Malware page if it is safe.",
            threats.len()
        ),
        format!(
            "{} tệp nhiễm mã độc; đã chuyển {quarantined} tệp vào khu cô lập, nơi không ai truy cập hay chạy được. Nếu tệp nào an toàn, hãy khôi phục ở trang Quét mã độc.",
            threats.len()
        ),
    )];
    lines.extend(threat_lines(threats));
    Content {
        subject,
        lines,
        page: "/malware",
    }
}

fn ssl_content(certificates: &[Expiring]) -> Content {
    let subject = match certificates {
        [one] if one.days <= 0 => Text::new(
            format!("The SSL certificate of {} has expired", one.domain),
            format!("Chứng chỉ SSL của {} đã hết hạn", one.domain),
        ),
        [one] => Text::new(
            format!(
                "The SSL certificate of {} expires in {} day(s)",
                one.domain, one.days
            ),
            format!(
                "Chứng chỉ SSL của {} hết hạn sau {} ngày",
                one.domain, one.days
            ),
        ),
        many => Text::new(
            format!("{} SSL certificates expire soon", many.len()),
            format!("{} chứng chỉ SSL sắp hết hạn", many.len()),
        ),
    };
    let mut lines = vec![Text::new(
        "Automatic renewal has not renewed it. Check that the domain still points at this server, then issue the certificate again on the SSL page.",
        "Tự động gia hạn chưa gia hạn được. Hãy kiểm tra tên miền vẫn trỏ về máy chủ này, rồi cấp lại chứng chỉ ở trang SSL.",
    )];
    let (shown, rest) = first(certificates, 15);
    lines.extend(shown.iter().map(|c| {
        if c.days <= 0 {
            Text::new(
                format!("{}: expired", c.domain),
                format!("{}: đã hết hạn", c.domain),
            )
        } else {
            Text::new(
                format!("{}: {} day(s) left", c.domain, c.days),
                format!("{}: còn {} ngày", c.domain, c.days),
            )
        }
    }));
    lines.extend(more(rest));
    Content {
        subject,
        lines,
        page: "/ssl",
    }
}

/// What to do when an administrator account did something nobody meant it
/// to: `who` is the account that did it.
fn if_not_them(who: &str) -> Text {
    Text::new(
        format!("If it was not {who}, change {who}'s password at once on the Users page, or deactivate the account."),
        format!("Nếu không phải {who}, hãy đổi mật khẩu của {who} ngay ở trang Người dùng, hoặc vô hiệu hoá tài khoản đó."),
    )
}

impl Event {
    /// The messages this event makes, each under its kind.
    pub fn messages(&self) -> Vec<Message> {
        match self {
            Event::ScheduleRun {
                schedule,
                users,
                problem,
            } => {
                let failed: Vec<&UserBackup> = users.iter().filter(|u| u.outcome.is_err()).collect();
                if failed.is_empty() && problem.is_none() {
                    let mut lines = vec![Text::new(
                        format!("{} account(s) backed up.", users.len()),
                        format!("Đã sao lưu {} tài khoản.", users.len()),
                    )];
                    let (shown, rest) = first(users, 15);
                    lines.extend(shown.iter().map(|u| {
                        Text::same(format!(
                            "{}: {}",
                            u.username,
                            u.outcome.as_ref().map(String::as_str).unwrap_or("")
                        ))
                    }));
                    lines.extend(more(rest));
                    return vec![Message {
                        key: "backup_done",
                        content: Content {
                            subject: Text::new(
                                format!("Scheduled backup finished: {schedule}"),
                                format!("Đã sao lưu xong theo lịch: {schedule}"),
                            ),
                            lines,
                            page: "/backups",
                        },
                    }];
                }
                let mut lines = Vec::new();
                if let Some(problem) = problem {
                    lines.push(Text::same(problem.clone()));
                }
                if !failed.is_empty() {
                    lines.push(Text::new(
                        format!("{} of {} account(s) were not backed up:", failed.len(), users.len()),
                        format!("{}/{} tài khoản chưa được sao lưu:", failed.len(), users.len()),
                    ));
                }
                let (shown, rest) = first(&failed, 15);
                lines.extend(shown.iter().map(|u| {
                    Text::same(format!(
                        "{}: {}",
                        u.username,
                        u.outcome.as_ref().err().map(String::as_str).unwrap_or("")
                    ))
                }));
                lines.extend(more(rest));
                vec![Message {
                    key: "backup_failed",
                    content: Content {
                        subject: Text::new(
                            format!("Scheduled backup failed: {schedule}"),
                            format!("Lịch sao lưu bị lỗi: {schedule}"),
                        ),
                        lines,
                        page: "/backups",
                    },
                }]
            }
            Event::BackupFailed { by, what, why } => vec![Message {
                key: "backup_failed",
                content: Content {
                    subject: Text::new(format!("Backup failed: {what}"), format!("Sao lưu bị lỗi: {what}")),
                    lines: vec![
                        Text::new(format!("Started by {by}."), format!("Do {by} khởi chạy.")),
                        Text::new(format!("Reason: {why}"), format!("Lý do: {why}")),
                    ],
                    page: "/backups",
                },
            }],
            Event::Malware { threats } => vec![Message {
                key: "malware",
                content: malware_content(threats),
            }],
            Event::SslExpiring { certificates } => vec![Message {
                key: "ssl_expiring",
                content: ssl_content(certificates),
            }],
            Event::DiskLow { mount, percent: used, free } => vec![Message {
                key: "disk_low",
                content: Content {
                    subject: Text::new(
                        format!("The disk is {} full ({mount})", percent(*used)),
                        format!("Ổ đĩa đã dùng {} ({mount})", percent(*used)),
                    ),
                    lines: vec![
                        Text::new(
                            format!("{} free. When it is full, websites, databases and backups stop writing.", human_size(*free)),
                            format!("Còn trống {}. Khi ổ đĩa đầy, website, cơ sở dữ liệu và sao lưu sẽ không ghi được nữa.", human_size(*free)),
                        ),
                        Text::new(
                            "Old backups and logs are where space usually goes.",
                            "Bản sao lưu và nhật ký cũ thường là nơi chiếm dung lượng.",
                        ),
                    ],
                    page: "/",
                },
            }],
            Event::Services {
                stopped,
                running_again,
            } => {
                let mut out = Vec::new();
                if !stopped.is_empty() {
                    let names = stopped.join(", ");
                    out.push(Message {
                        key: "service_down",
                        content: Content {
                            subject: Text::new(format!("Service stopped: {names}"), format!("Dịch vụ đã dừng: {names}")),
                            lines: vec![Text::new(
                                "Seen stopped in two checks five minutes apart. Start it again on the Services page; its log there says why it stopped.",
                                "Hai lần kiểm tra cách nhau năm phút đều thấy dịch vụ dừng. Hãy khởi động lại ở trang Dịch vụ; nhật ký ở đó cho biết vì sao nó dừng.",
                            )],
                            page: "/services",
                        },
                    });
                }
                if !running_again.is_empty() {
                    let names = running_again.join(", ");
                    out.push(Message {
                        key: "service_down",
                        content: Content {
                            subject: Text::new(format!("Service running again: {names}"), format!("Dịch vụ đã chạy lại: {names}")),
                            lines: vec![],
                            page: "/services",
                        },
                    });
                }
                out
            }
            Event::PanelUpdate { current, latest } => vec![Message {
                key: "panel_update",
                content: Content {
                    subject: Text::new(format!("SNPanel {latest} is out"), format!("Đã có SNPanel {latest}")),
                    lines: vec![Text::new(
                        format!("This server runs {current}. Update it from the Updates page."),
                        format!("Máy chủ này đang chạy {current}. Cập nhật ở trang Cập nhật."),
                    )],
                    page: "/updates",
                },
            }],
            Event::StorageFull {
                username,
                percent: used_percent,
                used,
                limit,
            } => vec![Message {
                key: "storage_full",
                content: Content {
                    subject: Text::new(
                        format!("{username} has used {} of their storage", percent(*used_percent)),
                        format!("{username} đã dùng {} dung lượng", percent(*used_percent)),
                    ),
                    lines: vec![
                        Text::same(format!("{} / {}", human_size(*used), human_size(*limit))),
                        Text::new(
                            "When it is full, the account's uploads, new websites and backups stop. Raise its limit on the Users page, or ask its owner to delete what they no longer need.",
                            "Khi đầy, tài khoản này sẽ không tải tệp lên, tạo website mới hay sao lưu được nữa. Hãy tăng giới hạn ở trang Người dùng, hoặc đề nghị chủ tài khoản xoá bớt những gì không cần.",
                        ),
                    ],
                    page: "/users",
                },
            }],
            Event::SignIn {
                username,
                address,
                agent,
                how,
            } => {
                let how_vi = match *how {
                    "passkey" => "passkey",
                    "code" => "mật khẩu và mã xác thực",
                    _ => "mật khẩu",
                };
                let how_en = match *how {
                    "passkey" => "a passkey",
                    "code" => "the password and a code",
                    _ => "the password",
                };
                let mut lines = vec![Text::new(
                    format!("From {address}, which this account has not signed in from before, with {how_en}."),
                    format!("Từ địa chỉ {address} - tài khoản này chưa từng đăng nhập từ đây - bằng {how_vi}."),
                )];
                if !agent.is_empty() {
                    lines.push(Text::new(format!("Browser: {agent}"), format!("Trình duyệt: {agent}")));
                }
                lines.push(if_not_them(username));
                vec![Message {
                    key: "sign_in",
                    content: Content {
                        subject: Text::new(
                            format!("New sign-in to the administrator account {username}"),
                            format!("Có đăng nhập mới vào tài khoản quản trị {username}"),
                        ),
                        lines,
                        page: "/users",
                    },
                }]
            }
            Event::Security {
                username,
                change,
                address,
                by,
            } => {
                let subject = match change {
                    Change::Password => Text::new(
                        format!("Password changed: {username}"),
                        format!("Đã đổi mật khẩu: {username}"),
                    ),
                    Change::TwoFactorOn => Text::new(
                        format!("Two-step verification turned on: {username}"),
                        format!("Đã bật xác minh 2 bước: {username}"),
                    ),
                    Change::TwoFactorOff => Text::new(
                        format!("Authenticator app turned off: {username}"),
                        format!("Đã tắt ứng dụng xác thực: {username}"),
                    ),
                    Change::TwoFactorReset => Text::new(
                        format!("Two-step verification reset: {username}"),
                        format!("Đã đặt lại xác minh 2 bước: {username}"),
                    ),
                    Change::PasskeyAdded(name) => Text::new(
                        format!("Passkey added to {username}: {name}"),
                        format!("Đã thêm passkey cho {username}: {name}"),
                    ),
                    Change::PasskeyRemoved(name) => Text::new(
                        format!("Passkey removed from {username}: {name}"),
                        format!("Đã gỡ passkey của {username}: {name}"),
                    ),
                    Change::McpToken { name, .. } => Text::new(
                        format!("AI assistant token made for {username}: {name}"),
                        format!("Đã tạo token trợ lý AI cho {username}: {name}"),
                    ),
                    Change::SftpPassword(account) => Text::new(
                        format!("SFTP password changed: {account} ({username})"),
                        format!("Đã đổi mật khẩu SFTP: {account} ({username})"),
                    ),
                    Change::Administrator => Text::new(
                        format!("{username} is now an administrator"),
                        format!("{username} đã trở thành quản trị viên"),
                    ),
                };
                let mut lines = Vec::new();
                if let Change::McpToken { can_write, .. } = change {
                    lines.push(if *can_write {
                        Text::new(
                            format!("It can read and act as {username}: write files, issue certificates and more."),
                            format!("Token này đọc và thao tác được như {username}: ghi tệp, cấp chứng chỉ và nhiều việc khác."),
                        )
                    } else {
                        Text::new(
                            format!("It can read as {username}."),
                            format!("Token này đọc được như {username}."),
                        )
                    });
                }
                match (by, address.is_empty()) {
                    (Some(admin), false) => lines.push(Text::new(
                        format!("By the administrator {admin}, from {address}."),
                        format!("Do quản trị viên {admin} thực hiện, từ địa chỉ {address}."),
                    )),
                    (Some(admin), true) => lines.push(Text::new(
                        format!("By the administrator {admin}."),
                        format!("Do quản trị viên {admin} thực hiện."),
                    )),
                    (None, false) => lines.push(Text::new(
                        format!("From {address}."),
                        format!("Từ địa chỉ {address}."),
                    )),
                    (None, true) => {}
                }
                lines.push(if_not_them(by.as_deref().unwrap_or(username)));
                let page = match change {
                    Change::McpToken { .. } => "/ai-assistants",
                    _ => "/users",
                };
                vec![Message {
                    key: "security",
                    content: Content {
                        subject,
                        lines,
                        page,
                    },
                }]
            }
        }
    }
}

// ---------------------------------------------------------------- writing it out

/// A message in one language, ready for a channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub subject: String,
    pub text: String,
    pub html: String,
    pub telegram: String,
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn render(content: &Content, lang: Lang, app: &str, base_url: &str) -> Rendered {
    let subject = content.subject.get(lang).to_string();
    let lines: Vec<&str> = content.lines.iter().map(|l| l.get(lang)).collect();
    let link = (!base_url.is_empty()).then(|| format!("{base_url}{}", content.page));
    let settings = (!base_url.is_empty()).then(|| format!("{base_url}/notifications"));
    let (open, why, choose) = match lang {
        Lang::En => (
            "Open the panel",
            format!("Sent to the administrators of {app}."),
            "Choose what is sent",
        ),
        Lang::Vi => (
            "Mở panel",
            format!("Gửi tới quản trị viên của {app}."),
            "Chọn những gì được gửi",
        ),
    };

    let mut text = format!("{subject}\n\n");
    for line in &lines {
        text.push_str(line);
        text.push('\n');
    }
    if let Some(link) = &link {
        text.push_str(&format!("\n{open}: {link}\n"));
    }
    text.push_str(&format!("\n--\n{why}\n"));
    if let Some(settings) = &settings {
        text.push_str(&format!("{choose}: {settings}\n"));
    }

    let mut html = String::from(
        "<!doctype html><html><body style=\"margin:0;padding:24px;background:#f3f6fa;font-family:Arial,Helvetica,sans-serif;color:#111827\">\
         <div style=\"max-width:600px;margin:0 auto;background:#ffffff;border:1px solid #dbe3ee;border-radius:10px;padding:24px\">",
    );
    html.push_str(&format!(
        "<p style=\"margin:0 0 4px;font-size:12px;color:#6b7280\">{}</p>\
         <h1 style=\"margin:0 0 16px;font-size:20px;line-height:1.35;color:#0b3d91\">{}</h1>",
        html_escape(app),
        html_escape(&subject)
    ));
    for line in &lines {
        html.push_str(&format!(
            "<p style=\"margin:0 0 10px;font-size:14px;line-height:1.55\">{}</p>",
            html_escape(line)
        ));
    }
    if let Some(link) = &link {
        html.push_str(&format!(
            "<p style=\"margin:20px 0 0\"><a href=\"{}\" style=\"display:inline-block;background:#0b5cd5;color:#ffffff;text-decoration:none;padding:10px 16px;border-radius:6px;font-size:14px;font-weight:bold\">{}</a></p>",
            html_escape(link),
            html_escape(open)
        ));
    }
    html.push_str(&format!(
        "</div><p style=\"max-width:600px;margin:12px auto 0;font-size:12px;color:#6b7280\">{}",
        html_escape(&why)
    ));
    if let Some(settings) = &settings {
        html.push_str(&format!(
            " <a href=\"{}\" style=\"color:#0b5cd5\">{}</a>",
            html_escape(settings),
            html_escape(choose)
        ));
    }
    html.push_str("</p></body></html>");

    let mut telegram = format!("<b>{}</b>\n", telegram::escape(&subject));
    for line in &lines {
        telegram.push('\n');
        telegram.push_str(&telegram::escape(line));
    }
    if let Some(link) = &link {
        telegram.push_str(&format!(
            "\n\n<a href=\"{}\">{}</a>",
            telegram::escape(link).replace('"', "&quot;"),
            telegram::escape(open)
        ));
    }
    telegram.push_str(&format!("\n<i>{}</i>", telegram::escape(app)));

    Rendered {
        subject,
        text,
        html,
        telegram,
    }
}

// ---------------------------------------------------------------- sending it

/// The panel's name, as its settings say.
pub fn app_name(state: &AppState) -> String {
    let raw = crate::routes::panel_settings::raw_settings();
    let stored = raw
        .get("app_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if stored.is_empty() {
        let name = state.settings.app_name.trim();
        if name.is_empty() {
            "SNPanel".to_string()
        } else {
            name.to_string()
        }
    } else {
        stored
    }
}

/// The panel's address, for links; empty when it has none.
pub fn base_url(state: &AppState) -> String {
    crate::panel_urls::configured_panel_url(&state.settings)
        .trim_end_matches('/')
        .to_string()
}

/// The chat as the page and the log name it.
pub fn chat_label(bot: &TelegramConfig) -> String {
    if bot.chat_name.is_empty() || bot.chat_name == bot.chat_id {
        bot.chat_id.clone()
    } else {
        format!("{} ({})", bot.chat_name, bot.chat_id)
    }
}

/// Every active administrator's own address, each once: where e-mail goes
/// when no address is set.
pub async fn admin_addresses(state: &AppState) -> Vec<String> {
    let users = match state.db.users().active_ordered_by_id().await {
        Ok(users) => users,
        Err(e) => {
            tracing::error!("notifications: cannot list the accounts: {e}");
            return Vec::new();
        }
    };
    let mut out: Vec<String> = Vec::new();
    for user in users.iter().filter(|u| u.is_admin()) {
        let address = user.email.trim();
        if smtp::valid_address(address) && !out.iter().any(|a| a.eq_ignore_ascii_case(address)) {
            out.push(address.to_string());
        }
    }
    out
}

/// Where e-mail goes: the addresses set, or the administrators' own.
pub async fn recipients(state: &AppState, config: &SmtpConfig) -> Vec<String> {
    if config.to.is_empty() {
        admin_addresses(state).await
    } else {
        config.to.clone()
    }
}

/// The date header's value, now.
fn mail_date() -> String {
    chrono::Local::now().to_rfc2822()
}

/// The SMTP server, with its password in the clear, from the saved channels.
pub fn smtp_server(state: &AppState, config: &SmtpConfig) -> Result<smtp::Server, String> {
    let security = smtp::Security::parse(&config.security)
        .ok_or_else(|| "The SMTP security setting is not one the panel knows".to_string())?;
    let password = reveal(state, &config.password)
        .ok_or_else(|| "The saved SMTP password cannot be read: save it again".to_string())?;
    Ok(smtp::Server {
        host: config.host.clone(),
        port: config.port,
        security,
        username: config.username.clone(),
        password,
    })
}

/// One e-mail.
pub async fn send_mail(
    state: &AppState,
    config: &SmtpConfig,
    to: &str,
    rendered: &Rendered,
) -> Result<(), String> {
    let server = smtp_server(state, config)?;
    let from_name = if config.from_name.trim().is_empty() {
        app_name(state)
    } else {
        config.from_name.clone()
    };
    smtp::send(
        &server,
        &smtp::Mail {
            from_address: &config.from_address,
            from_name: &from_name,
            to,
            subject: &rendered.subject,
            text: &rendered.text,
            html: &rendered.html,
        },
        &mail_date(),
    )
    .await
    .map_err(|e| e.0)
}

/// The bot token in the clear.
pub fn bot_token(state: &AppState, config: &TelegramConfig) -> Result<String, String> {
    reveal(state, &config.token)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| "The saved bot token cannot be read: save it again".to_string())
}

/// One Telegram message.
pub async fn send_telegram(
    state: &AppState,
    config: &TelegramConfig,
    chat: &str,
    rendered: &Rendered,
) -> Result<(), String> {
    let token = bot_token(state, config)?;
    telegram::send(&token, chat, &rendered.telegram)
        .await
        .map_err(|e| e.0)
}

/// What was sent, or why not, for the page's "Recently sent".
pub async fn log(
    state: &AppState,
    key: &str,
    channel: &str,
    target: &str,
    subject: &str,
    outcome: &Result<(), String>,
) {
    let now = snpanel_db::sqlalchemy_now();
    let (status, detail) = match outcome {
        Ok(()) => ("sent", String::new()),
        Err(why) => ("failed", why.chars().take(400).collect()),
    };
    if let Err(e) = state
        .db
        .notifications()
        .log(&NewLogEntry {
            created_at: &now,
            event: key,
            user_id: None,
            username: None,
            channel,
            target,
            subject,
            status,
            detail: &detail,
        })
        .await
    {
        tracing::warn!("cannot record a notification: {e}");
    }
    if let Err(why) = outcome {
        tracing::warn!(
            channel,
            target,
            event = key,
            "a notification was not sent: {why}"
        );
    }
}

/// Everything an event makes that the administrators chose to hear of, by
/// e-mail to each address and to the Telegram chat. Waits for the sending:
/// a one-shot process calls this before it exits; a request hands it to
/// [`spawn`] instead.
pub async fn deliver(state: &AppState, event: Event) {
    if !installed() {
        return;
    }
    let channels = load_channels();
    if !channels.ready() {
        return;
    }
    let messages: Vec<Message> = event
        .messages()
        .into_iter()
        .filter(|m| channels.wants(m.key))
        .collect();
    if messages.is_empty() {
        return;
    }
    let lang = channels.lang();
    let app = app_name(state);
    let base = base_url(state);
    let addresses = match &channels.smtp {
        Some(config) => recipients(state, config).await,
        None => Vec::new(),
    };
    for message in &messages {
        let rendered = render(&message.content, lang, &app, &base);
        if let Some(config) = &channels.smtp {
            if addresses.is_empty() {
                let nowhere = Err(
                    "No administrator has an e-mail address, and no address is set to send to"
                        .to_string(),
                );
                log(
                    state,
                    message.key,
                    "email",
                    "-",
                    &rendered.subject,
                    &nowhere,
                )
                .await;
            }
            for to in &addresses {
                let outcome = send_mail(state, config, to, &rendered).await;
                log(state, message.key, "email", to, &rendered.subject, &outcome).await;
            }
        }
        if let Some((bot, chat)) = channels.telegram_chat() {
            let outcome = send_telegram(state, bot, chat, &rendered).await;
            log(
                state,
                message.key,
                "telegram",
                &chat_label(bot),
                &rendered.subject,
                &outcome,
            )
            .await;
        }
    }
}

/// [`deliver`] in the background, for a request that should not wait.
pub fn spawn(state: &AppState, event: Event) {
    if !installed() {
        return;
    }
    let state = state.clone();
    tokio::spawn(async move {
        deliver(&state, event).await;
    });
}

/// The words of a test message.
pub fn test_content() -> Content {
    Content {
        subject: Text::new("A test message from the panel", "Tin nhắn thử từ panel"),
        lines: vec![Text::new(
            "If you can read this, the panel's notifications reach you here.",
            "Nếu bạn đọc được tin này, thông báo của panel sẽ đến được đây.",
        )],
        page: "/notifications",
    }
}

/// The panel's state, for the hooks that have none of their own to hand -
/// the malware scans, which run on a job id. Set once, at start-up, by the
/// server and by the one-shot processes alike.
static STATE: std::sync::OnceLock<AppState> = std::sync::OnceLock::new();

pub fn attach(state: &AppState) {
    let _ = STATE.set(state.clone());
}

/// A malware scan that found something, told once what it found has been
/// set aside - so the message can say what was quarantined. A file left in
/// place because it is whitelisted, or gone before it could be moved, is
/// not news. Awaited by the scan's own task, so a one-shot scheduler that
/// waits for its scans waits for this too.
pub async fn scan_finished(job_id: &str) {
    let Some(state) = STATE.get() else {
        return;
    };
    if !installed() {
        return;
    }
    let Some(job) = crate::malware_jobs::get(job_id) else {
        return;
    };
    let Some(found) = job["threats"].as_array().filter(|t| !t.is_empty()) else {
        return;
    };
    let threats: Vec<Threat> = found
        .iter()
        .filter(|t| !matches!(t["state"].as_str(), Some("whitelisted" | "missing")))
        .map(|t| {
            let path = t["path"].as_str().unwrap_or_default().to_string();
            let domain = t["domain"]
                .as_str()
                .filter(|d| !d.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| crate::malware_jobs::domain_from_path(&path));
            Threat {
                signature: t["signature"].as_str().unwrap_or_default().to_string(),
                quarantined: t["state"].as_str() == Some("quarantined"),
                path,
                domain,
            }
        })
        .collect();
    if !threats.is_empty() {
        deliver(state, Event::Malware { threats }).await;
    }
}

/// A sign-in to an administrator account: recorded, and told when the
/// address is new to it. `how` is `password`, `code` or `passkey`. A
/// customer's sign-ins are not looked at.
pub fn signed_in(state: &AppState, user: &User, address: &str, agent: &str, how: &'static str) {
    if !installed() || address.is_empty() || !user.is_admin() {
        return;
    }
    let state = state.clone();
    let (id, username) = (user.id, user.username.clone());
    let address = address.to_string();
    let agent: String = agent
        .chars()
        .filter(|c| !c.is_control())
        .take(160)
        .collect();
    tokio::spawn(async move {
        let now = snpanel_db::sqlalchemy_now();
        match state
            .db
            .notifications()
            .note_address(id, &username, &address, &now)
            .await
        {
            Ok(true) => {
                deliver(
                    &state,
                    Event::SignIn {
                        username,
                        address,
                        agent,
                        how,
                    },
                )
                .await
            }
            Ok(false) => {}
            Err(e) => tracing::warn!("cannot record a sign-in address: {e}"),
        }
    });
}

/// A change to how an administrator account signs in; `by` is who made it.
/// A customer's own are not told.
pub fn security_change(
    state: &AppState,
    owner: &User,
    change: Change,
    address: &str,
    by: Option<&User>,
) {
    if !owner.is_admin() {
        return;
    }
    let by = by.filter(|b| b.id != owner.id).map(|b| b.username.clone());
    spawn(
        state,
        Event::Security {
            username: owner.username.clone(),
            change,
            address: address.to_string(),
            by,
        },
    );
}

/// An account made an administrator - created as one, or its role changed -
/// by the administrator `by`, from `address`.
pub fn new_administrator(state: &AppState, username: &str, by: &User, address: &str) {
    spawn(
        state,
        Event::Security {
            username: username.to_string(),
            change: Change::Administrator,
            address: address.to_string(),
            by: Some(by.username.clone()),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_event_nobody_chose_for_takes_its_default() {
        let mut channels = Channels::default();
        assert!(channels.wants("backup_failed"));
        assert!(!channels.wants("backup_done"));
        assert!(channels.wants("security"));
        assert!(!channels.wants("no_such_event"));
        channels.events.insert("backup_done".into(), true);
        channels.events.insert("sign_in".into(), false);
        assert!(channels.wants("backup_done"));
        assert!(!channels.wants("sign_in"));
        // Every kind has a key of its own, and a group the page knows.
        let mut keys: Vec<&str> = KINDS.iter().map(|k| k.key).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), KINDS.len());
        assert!(KINDS
            .iter()
            .all(|k| matches!(k.group, "accounts" | "server" | "admins")));
    }

    #[test]
    fn a_file_saved_before_the_chat_id_sends_nothing_to_telegram() {
        let old: Channels = serde_json::from_str(
            r#"{"smtp":null,"telegram":{"token":"gAAAA","username":"snpanel_bot"},"language":"vi"}"#,
        )
        .unwrap();
        assert!(old.telegram_chat().is_none());
        assert!(!old.ready(), "a bot with no chat is nowhere to send");
        assert_eq!(old.lang(), Lang::Vi);
        let mut set = old.clone();
        set.telegram.as_mut().unwrap().chat_id = "-1001234567890".into();
        set.telegram.as_mut().unwrap().chat_name = "Ops".into();
        assert!(set.ready());
        assert_eq!(
            chat_label(set.telegram.as_ref().unwrap()),
            "Ops (-1001234567890)"
        );
    }

    #[test]
    fn a_failed_schedule_names_each_account_that_was_not_backed_up() {
        let run = |bob: Result<String, String>| Event::ScheduleRun {
            schedule: "Nightly".into(),
            users: vec![
                UserBackup {
                    username: "alice".into(),
                    outcome: Ok("alice.tar.gz".into()),
                },
                UserBackup {
                    username: "bob".into(),
                    outcome: bob,
                },
            ],
            problem: None,
        };
        let failed = run(Err("disk full".into())).messages();
        assert_eq!(failed.len(), 1, "one message, for the administrators");
        assert_eq!(failed[0].key, "backup_failed");
        assert_eq!(
            failed[0].content.subject.en,
            "Scheduled backup failed: Nightly"
        );
        assert_eq!(failed[0].content.subject.vi, "Lịch sao lưu bị lỗi: Nightly");
        assert!(failed[0]
            .content
            .lines
            .iter()
            .any(|l| l.en == "bob: disk full"));
        let done = run(Ok("bob.tar.gz".into())).messages();
        assert_eq!(done[0].key, "backup_done");
        assert!(done[0]
            .content
            .lines
            .iter()
            .any(|l| l.en == "bob: bob.tar.gz"));
    }

    #[test]
    fn malware_names_every_website_it_was_found_on() {
        let threat = |path: &str, domain: &str| Threat {
            path: path.into(),
            signature: "Eicar-Signature".into(),
            domain: domain.into(),
            quarantined: true,
        };
        let messages = Event::Malware {
            threats: vec![
                threat("/home/a/a.com/x.php", "a.com"),
                threat("/home/b/b.com/y.php", "b.com"),
                threat("/home/b/b.com/z.php", "b.com"),
            ],
        }
        .messages();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].key, "malware");
        assert_eq!(
            messages[0].content.subject.en,
            "Malware found on 2 websites"
        );
        assert!(messages[0].content.lines[0]
            .en
            .starts_with("3 infected file(s); 3 moved to quarantine"));
    }

    #[test]
    fn a_change_names_the_account_and_who_made_it() {
        let reset = Event::Security {
            username: "bob".into(),
            change: Change::TwoFactorReset,
            address: "203.0.113.5".into(),
            by: Some("alice".into()),
        }
        .messages();
        let content = &reset[0].content;
        assert_eq!(content.subject.vi, "Đã đặt lại xác minh 2 bước: bob");
        assert_eq!(
            content.lines[0].en,
            "By the administrator alice, from 203.0.113.5."
        );
        // What to do names who did it.
        assert!(content.lines[1].en.starts_with("If it was not alice,"));
        let made = Event::Security {
            username: "carol".into(),
            change: Change::Administrator,
            address: String::new(),
            by: Some("alice".into()),
        }
        .messages();
        assert_eq!(made[0].key, "security");
        assert_eq!(made[0].content.subject.en, "carol is now an administrator");
        let sign_in = Event::SignIn {
            username: "alice".into(),
            address: "198.51.100.7".into(),
            agent: String::new(),
            how: "passkey",
        }
        .messages();
        assert_eq!(
            sign_in[0].content.subject.en,
            "New sign-in to the administrator account alice"
        );
        assert!(sign_in[0].content.lines[0].en.ends_with("with a passkey."));
    }

    #[test]
    fn a_message_is_written_out_escaped_for_each_channel() {
        let content = Content {
            subject: Text::new("Malware found on <a.com>", "Phát hiện mã độc trên <a.com>"),
            lines: vec![Text::same("x.php - <script>&")],
            page: "/malware",
        };
        let out = render(
            &content,
            Lang::Vi,
            "SNPanel",
            "https://panel.example.com:2222",
        );
        assert_eq!(out.subject, "Phát hiện mã độc trên <a.com>");
        assert!(out
            .text
            .contains("Mở panel: https://panel.example.com:2222/malware"));
        assert!(out.text.contains("Gửi tới quản trị viên của SNPanel."));
        assert!(out.html.contains("Phát hiện mã độc trên &lt;a.com&gt;"));
        assert!(out.html.contains("x.php - &lt;script&gt;&amp;"));
        assert!(!out.html.contains("<script>"));
        assert!(out
            .telegram
            .starts_with("<b>Phát hiện mã độc trên &lt;a.com&gt;</b>"));
        assert!(out
            .telegram
            .contains("<a href=\"https://panel.example.com:2222/malware\">Mở panel</a>"));
        // No address to link to, no link.
        let bare = render(&content, Lang::En, "SNPanel", "");
        assert!(!bare.text.contains("Open the panel"));
        assert!(bare.text.contains("Sent to the administrators of SNPanel."));
    }

    #[test]
    fn sizes_read_as_people_read_them() {
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(512), "512 B");
    }
}
