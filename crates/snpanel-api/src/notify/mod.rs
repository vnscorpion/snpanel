//! Notifications - the addon that tells people, by e-mail and on Telegram,
//! what they would otherwise only find by opening the panel.
//!
//! Not in the Python. Two halves:
//!
//! - **How messages go out** is the administrator's: an SMTP server, a
//!   Telegram bot, and the language a message is written in when its reader
//!   chose none. `notifications.json` in the data directory, mode 0600, the
//!   SMTP password and the bot token Fernet-encrypted with the panel's key -
//!   see [`Channels`].
//! - **Who hears of what** is every account's own: whether to be told by
//!   e-mail, and at which address; a Telegram chat linked through the bot;
//!   and which events. `notification_settings` in the database, one row per
//!   account that chose anything.
//!
//! An administrator hears of the server - a scheduled backup that failed,
//! malware on any website, a certificate about to expire, the disk filling,
//! a service stopping, a new release, an account running out of room. Every
//! account, administrators' too, hears of its own - its backups, malware on
//! its websites, its certificates and storage, a sign-in from an address it
//! has not used, and changes to how it signs in. See [`KINDS`].
//!
//! Each event is written in English and Vietnamese here, and each reader
//! gets it in theirs. A reader who is both an event's owner and an
//! administrator gets one message, the administrator's, which says more.
//! Nothing is sent while the addon is not installed, or while neither way of
//! sending is set up; what was sent, and what failed, is in
//! `notification_log`.

pub mod smtp;
pub mod telegram;
pub mod watcher;

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use snpanel_core::crypto::fernet;
use snpanel_db::notifications::{NewLogEntry, NotificationSettings};
use snpanel_db::User;

use crate::state::AppState;

// ---------------------------------------------------------------- channels

/// How mail goes out.
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
}

/// The Telegram bot messages come from.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelegramConfig {
    /// Fernet-encrypted.
    pub token: String,
    /// The bot's `@username`, as `getMe` said when the token was saved.
    pub username: String,
}

/// The administrator's half: how messages go out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Channels {
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,
    #[serde(default)]
    pub telegram: Option<TelegramConfig>,
    /// `en` or `vi`: a message's language when its reader chose none.
    #[serde(default)]
    pub language: Option<String>,
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

/// One kind of event a reader can ask to hear of or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kind {
    pub key: &'static str,
    /// Only administrators are offered it: it is about the server.
    pub admin: bool,
    /// Whether it is heard of by someone who never chose.
    pub default_on: bool,
}

/// Every kind, in the order the page lists them: the account's own first,
/// then the server's.
pub const KINDS: &[Kind] = &[
    Kind {
        key: "backup_failed",
        admin: false,
        default_on: true,
    },
    Kind {
        key: "backup_done",
        admin: false,
        default_on: false,
    },
    Kind {
        key: "malware",
        admin: false,
        default_on: true,
    },
    Kind {
        key: "ssl_expiring",
        admin: false,
        default_on: true,
    },
    Kind {
        key: "storage_full",
        admin: false,
        default_on: true,
    },
    Kind {
        key: "sign_in",
        admin: false,
        default_on: true,
    },
    Kind {
        key: "security",
        admin: false,
        default_on: true,
    },
    Kind {
        key: "server_backup_failed",
        admin: true,
        default_on: true,
    },
    Kind {
        key: "server_backup_done",
        admin: true,
        default_on: false,
    },
    Kind {
        key: "server_malware",
        admin: true,
        default_on: true,
    },
    Kind {
        key: "server_ssl_expiring",
        admin: true,
        default_on: true,
    },
    Kind {
        key: "disk_low",
        admin: true,
        default_on: true,
    },
    Kind {
        key: "service_down",
        admin: true,
        default_on: true,
    },
    Kind {
        key: "panel_update",
        admin: true,
        default_on: true,
    },
    Kind {
        key: "server_storage_full",
        admin: true,
        default_on: false,
    },
];

pub fn kind(key: &str) -> Option<&'static Kind> {
    KINDS.iter().find(|k| k.key == key)
}

/// Whether a reader with these choices hears of `key`.
pub fn wants(settings: &NotificationSettings, key: &str) -> bool {
    let chosen = serde_json::from_str::<Value>(&settings.events)
        .ok()
        .and_then(|v| v.get(key).and_then(Value::as_bool));
    chosen.unwrap_or_else(|| kind(key).is_some_and(|k| k.default_on))
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

/// Who a message is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience {
    /// One account: the owner of what it is about.
    Owner(i64),
    /// Every active administrator.
    Admins,
}

/// One message an event makes: for whom, under which kind, saying what.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub audience: Audience,
    pub key: &'static str,
    pub content: Content,
}

// ---------------------------------------------------------------- the events

/// One user's part in a scheduled backup's run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserBackup {
    pub user_id: i64,
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
    /// The website's owner, when the path is in a website.
    pub owner: Option<i64>,
    /// Whether it was moved to quarantine.
    pub quarantined: bool,
}

/// A certificate close to its end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expiring {
    pub owner: i64,
    pub domain: String,
    /// Whole days left; zero or less is expired.
    pub days: i64,
}

/// A change to how an account signs in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Password,
    TwoFactorOn,
    TwoFactorOff,
    TwoFactorReset,
    PasskeyAdded(String),
    PasskeyRemoved(String),
    McpToken { name: String, can_write: bool },
    SftpPassword(String),
}

/// Something that happened, as a hook reports it.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// A backup schedule ran, for these users; `problem` when it could not
    /// run for anyone.
    ScheduleRun {
        schedule: String,
        users: Vec<UserBackup>,
        problem: Option<String>,
    },
    /// A backup someone started finished, one way or the other.
    Backup {
        owner: i64,
        what: String,
        outcome: Result<String, String>,
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
    /// An account's storage is nearly full.
    StorageFull {
        owner: i64,
        username: String,
        percent: f64,
        used: u64,
        limit: u64,
    },
    /// A sign-in from an address the account has not signed in from.
    SignIn {
        owner: i64,
        address: String,
        agent: String,
        how: &'static str,
    },
    /// A change to how the account signs in.
    Security {
        owner: i64,
        change: Change,
        address: String,
        /// The administrator who made it, when it was not the owner.
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

fn if_not_you() -> Text {
    Text::new(
        "If it was not you, sign in and change your password at once, and turn on two-step verification.",
        "Nếu không phải bạn, hãy đăng nhập và đổi mật khẩu ngay, rồi bật xác minh 2 bước.",
    )
}

impl Event {
    /// The messages this event makes, each for its audience and kind.
    pub fn messages(&self) -> Vec<Message> {
        match self {
            Event::ScheduleRun {
                schedule,
                users,
                problem,
            } => {
                let failed: Vec<&UserBackup> = users.iter().filter(|u| u.outcome.is_err()).collect();
                let mut out = Vec::new();
                if failed.is_empty() && problem.is_none() {
                    out.push(Message {
                        audience: Audience::Admins,
                        key: "server_backup_done",
                        content: Content {
                            subject: Text::new(
                                format!("Scheduled backup finished: {schedule}"),
                                format!("Đã sao lưu xong theo lịch: {schedule}"),
                            ),
                            lines: vec![Text::new(
                                format!("{} account(s) backed up.", users.len()),
                                format!("Đã sao lưu {} tài khoản.", users.len()),
                            )],
                            page: "/backups",
                        },
                    });
                } else {
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
                    out.push(Message {
                        audience: Audience::Admins,
                        key: "server_backup_failed",
                        content: Content {
                            subject: Text::new(
                                format!("Scheduled backup failed: {schedule}"),
                                format!("Lịch sao lưu bị lỗi: {schedule}"),
                            ),
                            lines,
                            page: "/backups",
                        },
                    });
                }
                for user in users {
                    let (key, content) = match &user.outcome {
                        Ok(went) => (
                            "backup_done",
                            Content {
                                subject: Text::new("Your account was backed up", "Tài khoản của bạn đã được sao lưu"),
                                lines: vec![
                                    Text::new(
                                        format!("By the schedule \"{schedule}\"."),
                                        format!("Theo lịch \"{schedule}\"."),
                                    ),
                                    Text::same(went.clone()),
                                ],
                                page: "/backups",
                            },
                        ),
                        Err(why) => (
                            "backup_failed",
                            Content {
                                subject: Text::new("Your account's backup failed", "Sao lưu tài khoản của bạn bị lỗi"),
                                lines: vec![
                                    Text::new(
                                        format!("The schedule \"{schedule}\" could not back up your account."),
                                        format!("Lịch \"{schedule}\" không sao lưu được tài khoản của bạn."),
                                    ),
                                    Text::new(format!("Reason: {why}"), format!("Lý do: {why}")),
                                ],
                                page: "/backups",
                            },
                        ),
                    };
                    out.push(Message {
                        audience: Audience::Owner(user.user_id),
                        key,
                        content,
                    });
                }
                out
            }
            Event::Backup {
                owner,
                what,
                outcome,
            } => {
                let (key, content) = match outcome {
                    Ok(file) => (
                        "backup_done",
                        Content {
                            subject: Text::new(format!("Backup finished: {what}"), format!("Đã sao lưu xong: {what}")),
                            lines: vec![Text::new(format!("File: {file}"), format!("Tệp: {file}"))],
                            page: "/backups",
                        },
                    ),
                    Err(why) => (
                        "backup_failed",
                        Content {
                            subject: Text::new(format!("Backup failed: {what}"), format!("Sao lưu bị lỗi: {what}")),
                            lines: vec![Text::new(format!("Reason: {why}"), format!("Lý do: {why}"))],
                            page: "/backups",
                        },
                    ),
                };
                vec![Message {
                    audience: Audience::Owner(*owner),
                    key,
                    content,
                }]
            }
            Event::Malware { threats } => {
                let mut out = vec![Message {
                    audience: Audience::Admins,
                    key: "server_malware",
                    content: malware_content(threats),
                }];
                let mut owners: Vec<i64> = threats.iter().filter_map(|t| t.owner).collect();
                owners.sort_unstable();
                owners.dedup();
                for owner in owners {
                    let theirs: Vec<Threat> = threats
                        .iter()
                        .filter(|t| t.owner == Some(owner))
                        .cloned()
                        .collect();
                    out.push(Message {
                        audience: Audience::Owner(owner),
                        key: "malware",
                        content: malware_content(&theirs),
                    });
                }
                out
            }
            Event::SslExpiring { certificates } => {
                let mut out = vec![Message {
                    audience: Audience::Admins,
                    key: "server_ssl_expiring",
                    content: ssl_content(certificates),
                }];
                let mut owners: Vec<i64> = certificates.iter().map(|c| c.owner).collect();
                owners.sort_unstable();
                owners.dedup();
                for owner in owners {
                    let theirs: Vec<Expiring> = certificates
                        .iter()
                        .filter(|c| c.owner == owner)
                        .cloned()
                        .collect();
                    out.push(Message {
                        audience: Audience::Owner(owner),
                        key: "ssl_expiring",
                        content: ssl_content(&theirs),
                    });
                }
                out
            }
            Event::DiskLow { mount, percent: used, free } => vec![Message {
                audience: Audience::Admins,
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
                        audience: Audience::Admins,
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
                        audience: Audience::Admins,
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
                audience: Audience::Admins,
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
                owner,
                username,
                percent: used_percent,
                used,
                limit,
            } => {
                let figures = format!("{} / {}", human_size(*used), human_size(*limit));
                vec![
                    Message {
                        audience: Audience::Admins,
                        key: "server_storage_full",
                        content: Content {
                            subject: Text::new(
                                format!("{username} has used {} of their storage", percent(*used_percent)),
                                format!("{username} đã dùng {} dung lượng", percent(*used_percent)),
                            ),
                            lines: vec![Text::same(figures.clone())],
                            page: "/users",
                        },
                    },
                    Message {
                        audience: Audience::Owner(*owner),
                        key: "storage_full",
                        content: Content {
                            subject: Text::new(
                                format!("Your storage is {} full", percent(*used_percent)),
                                format!("Dung lượng của bạn đã dùng {}", percent(*used_percent)),
                            ),
                            lines: vec![
                                Text::same(figures),
                                Text::new(
                                    "When it is full, uploads, new websites and backups stop. Delete what you no longer need, or ask for more room.",
                                    "Khi đầy, việc tải tệp lên, tạo website mới và sao lưu sẽ dừng. Hãy xoá bớt những gì không cần, hoặc xin thêm dung lượng.",
                                ),
                            ],
                            page: "/filemanager",
                        },
                    },
                ]
            }
            Event::SignIn {
                owner,
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
                lines.push(if_not_you());
                vec![Message {
                    audience: Audience::Owner(*owner),
                    key: "sign_in",
                    content: Content {
                        subject: Text::new("A new sign-in to your account", "Có đăng nhập mới vào tài khoản của bạn"),
                        lines,
                        page: "/security",
                    },
                }]
            }
            Event::Security {
                owner,
                change,
                address,
                by,
            } => {
                let subject = match change {
                    Change::Password => Text::new("Your panel password was changed", "Mật khẩu panel của bạn đã được đổi"),
                    Change::TwoFactorOn => Text::new("Two-step verification was turned on", "Đã bật xác minh 2 bước"),
                    Change::TwoFactorOff => Text::new("The authenticator app was turned off", "Đã tắt ứng dụng xác thực"),
                    Change::TwoFactorReset => Text::new(
                        "Your two-step verification was reset",
                        "Xác minh 2 bước của bạn đã được đặt lại",
                    ),
                    Change::PasskeyAdded(name) => Text::new(format!("A passkey was added: {name}"), format!("Đã thêm passkey: {name}")),
                    Change::PasskeyRemoved(name) => Text::new(format!("A passkey was removed: {name}"), format!("Đã gỡ passkey: {name}")),
                    Change::McpToken { name, .. } => Text::new(
                        format!("An AI assistant token was made: {name}"),
                        format!("Đã tạo token trợ lý AI: {name}"),
                    ),
                    Change::SftpPassword(account) => Text::new(
                        format!("The SFTP password of {account} was changed"),
                        format!("Đã đổi mật khẩu SFTP của {account}"),
                    ),
                };
                let mut lines = Vec::new();
                if let Change::McpToken { can_write, .. } = change {
                    lines.push(if *can_write {
                        Text::new(
                            "It can read and act as your account: write files, issue certificates and more.",
                            "Token này đọc và thao tác được như tài khoản của bạn: ghi tệp, cấp chứng chỉ và nhiều việc khác.",
                        )
                    } else {
                        Text::new("It can read as your account.", "Token này đọc được như tài khoản của bạn.")
                    });
                }
                match by {
                    Some(admin) => lines.push(Text::new(
                        format!("By the administrator {admin}."),
                        format!("Do quản trị viên {admin} thực hiện."),
                    )),
                    None if !address.is_empty() => lines.push(Text::new(
                        format!("From {address}."),
                        format!("Từ địa chỉ {address}."),
                    )),
                    None => {}
                }
                lines.push(if_not_you());
                vec![Message {
                    audience: Audience::Owner(*owner),
                    key: "security",
                    content: Content {
                        subject,
                        lines,
                        page: "/security",
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

/// What the footer says, in `lang`.
struct Footer<'a> {
    app: &'a str,
    username: &'a str,
    base_url: &'a str,
}

pub fn render(
    content: &Content,
    lang: Lang,
    footer_app: &str,
    username: &str,
    base_url: &str,
) -> Rendered {
    let footer = Footer {
        app: footer_app,
        username,
        base_url,
    };
    let subject = content.subject.get(lang).to_string();
    let lines: Vec<&str> = content.lines.iter().map(|l| l.get(lang)).collect();
    let link =
        (!footer.base_url.is_empty()).then(|| format!("{}{}", footer.base_url, content.page));
    let prefs = (!footer.base_url.is_empty()).then(|| format!("{}/notifications", footer.base_url));
    let (open, why, choose) = match lang {
        Lang::En => (
            "Open the panel",
            format!("You get this as {} on {}.", footer.username, footer.app),
            "Choose what you are told of",
        ),
        Lang::Vi => (
            "Mở panel",
            format!(
                "Bạn nhận thư này với tư cách {} trên {}.",
                footer.username, footer.app
            ),
            "Chọn những gì muốn được báo",
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
    if let Some(prefs) = &prefs {
        text.push_str(&format!("{choose}: {prefs}\n"));
    }

    let mut html = String::from(
        "<!doctype html><html><body style=\"margin:0;padding:24px;background:#f3f6fa;font-family:Arial,Helvetica,sans-serif;color:#111827\">\
         <div style=\"max-width:600px;margin:0 auto;background:#ffffff;border:1px solid #dbe3ee;border-radius:10px;padding:24px\">",
    );
    html.push_str(&format!(
        "<p style=\"margin:0 0 4px;font-size:12px;color:#6b7280\">{}</p>\
         <h1 style=\"margin:0 0 16px;font-size:20px;line-height:1.35;color:#0b3d91\">{}</h1>",
        html_escape(footer.app),
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
    if let Some(prefs) = &prefs {
        html.push_str(&format!(
            " <a href=\"{}\" style=\"color:#0b5cd5\">{}</a>",
            html_escape(prefs),
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
    telegram.push_str(&format!(
        "\n<i>{} · {}</i>",
        telegram::escape(footer.app),
        telegram::escape(footer.username)
    ));

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

/// An address as the log shows it: enough to tell which, not the whole.
pub fn masked_address(address: &str) -> String {
    match address.split_once('@') {
        Some((local, domain)) => {
            let first: String = local.chars().take(1).collect();
            format!("{first}***@{domain}")
        }
        None => "***".to_string(),
    }
}

pub fn masked_chat(chat: &str) -> String {
    let tail: String = chat
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("…{tail}")
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

/// One Telegram message.
pub async fn send_telegram(
    state: &AppState,
    config: &TelegramConfig,
    chat: &str,
    rendered: &Rendered,
) -> Result<(), String> {
    let token = reveal(state, &config.token)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| "The saved bot token cannot be read: save it again".to_string())?;
    telegram::send(&token, chat, &rendered.telegram)
        .await
        .map_err(|e| e.0)
}

async fn log(
    state: &AppState,
    key: &str,
    user: &User,
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
            user_id: Some(user.id),
            username: Some(&user.username),
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
        tracing::warn!(user = %user.username, channel, event = key, "a notification was not sent: {why}");
    }
}

/// Everything an event makes, to everyone who asked to hear of it, by every
/// way they chose. Waits for the sending: a one-shot process calls this
/// before it exits; a request hands it to [`spawn`] instead.
pub async fn deliver(state: &AppState, event: Event) {
    if !installed() {
        return;
    }
    let channels = load_channels();
    if channels.smtp.is_none() && channels.telegram.is_none() {
        return;
    }
    let messages = event.messages();
    if messages.is_empty() {
        return;
    }
    let users = match state.db.users().list_all().await {
        Ok(users) => users,
        Err(e) => {
            tracing::error!("notifications: cannot list the accounts: {e}");
            return;
        }
    };
    // Each reader's candidates, the administrators' message first: it says
    // more, and one message is enough.
    let mut candidates: BTreeMap<i64, Vec<&Message>> = BTreeMap::new();
    for message in messages.iter().filter(|m| m.audience == Audience::Admins) {
        for user in users.iter().filter(|u| u.is_active && u.is_admin()) {
            candidates.entry(user.id).or_default().push(message);
        }
    }
    for message in &messages {
        if let Audience::Owner(owner) = message.audience {
            if users.iter().any(|u| u.id == owner && u.is_active) {
                candidates.entry(owner).or_default().push(message);
            }
        }
    }

    let app = app_name(state);
    let base = base_url(state);
    let default_lang = Lang::parse(channels.language.as_deref()).unwrap_or(Lang::Vi);
    for (user_id, offered) in candidates {
        let Some(user) = users.iter().find(|u| u.id == user_id) else {
            continue;
        };
        let settings = state
            .db
            .notifications()
            .get(user.id, &user.username)
            .await
            .unwrap_or_default();
        // Two messages of one event for the same reader - "Service stopped"
        // and "Service running again" - are both theirs; the administrator's
        // and the owner's view of the same thing are one.
        let mut chosen: Vec<&Message> = Vec::new();
        for message in offered {
            if !wants(&settings, message.key) {
                continue;
            }
            let duplicate = chosen
                .iter()
                .any(|c| c.content.page == message.content.page && c.audience != message.audience);
            if !duplicate {
                chosen.push(message);
            }
        }
        let lang = Lang::parse(settings.language.as_deref()).unwrap_or(default_lang);
        for message in chosen {
            let rendered = render(&message.content, lang, &app, &user.username, &base);
            if let Some(config) = channels.smtp.as_ref().filter(|_| settings.email_enabled) {
                let to = settings
                    .email
                    .clone()
                    .filter(|e| !e.trim().is_empty())
                    .unwrap_or_else(|| user.email.clone());
                if smtp::valid_address(&to) {
                    let outcome = send_mail(state, config, &to, &rendered).await;
                    log(
                        state,
                        message.key,
                        user,
                        "email",
                        &masked_address(&to),
                        &rendered.subject,
                        &outcome,
                    )
                    .await;
                }
            }
            if let Some(config) = channels
                .telegram
                .as_ref()
                .filter(|_| settings.telegram_enabled)
            {
                if let Some(chat) = settings
                    .telegram_chat_id
                    .as_deref()
                    .filter(|c| !c.is_empty())
                {
                    let outcome = send_telegram(state, config, chat, &rendered).await;
                    log(
                        state,
                        message.key,
                        user,
                        "telegram",
                        &masked_chat(chat),
                        &rendered.subject,
                        &outcome,
                    )
                    .await;
                }
            }
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
            "If you can read this, notifications reach you here.",
            "Nếu bạn đọc được tin này, thông báo sẽ đến được với bạn ở đây.",
        )],
        page: "/notifications",
    }
}

/// What the bot says in a chat it was just linked to, in Telegram's HTML.
pub fn linked_hello(lang: Lang, username: &str, app: &str) -> String {
    let (username, app) = (telegram::escape(username), telegram::escape(app));
    match lang {
        Lang::En => {
            format!("Linked. This chat now gets the notifications of <b>{username}</b> on {app}.")
        }
        Lang::Vi => format!(
            "Đã liên kết. Cuộc trò chuyện này sẽ nhận thông báo của <b>{username}</b> trên {app}."
        ),
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
    let websites = state
        .db
        .websites()
        .all_by_domain()
        .await
        .unwrap_or_default();
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
            let owner = websites
                .iter()
                .find(|w| w.domain == domain)
                .map(|w| w.owner_id);
            Threat {
                signature: t["signature"].as_str().unwrap_or_default().to_string(),
                quarantined: t["state"].as_str() == Some("quarantined"),
                path,
                domain,
                owner,
            }
        })
        .collect();
    if !threats.is_empty() {
        deliver(state, Event::Malware { threats }).await;
    }
}

/// A sign-in: recorded against the account, and told of when the address is
/// new to it. `how` is `password`, `code` or `passkey`.
pub fn signed_in(state: &AppState, user: &User, address: &str, agent: &str, how: &'static str) {
    if !installed() || address.is_empty() {
        return;
    }
    let state = state.clone();
    let (owner, username) = (user.id, user.username.clone());
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
            .note_address(owner, &username, &address, &now)
            .await
        {
            Ok(true) => {
                deliver(
                    &state,
                    Event::SignIn {
                        owner,
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

/// A change to how an account signs in, told to its owner.
pub fn security_change(
    state: &AppState,
    owner: &User,
    change: Change,
    address: &str,
    by: Option<&User>,
) {
    let by = by.filter(|b| b.id != owner.id).map(|b| b.username.clone());
    spawn(
        state,
        Event::Security {
            owner: owner.id,
            change,
            address: address.to_string(),
            by,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(events: &str) -> NotificationSettings {
        NotificationSettings {
            events: events.into(),
            ..NotificationSettings::default()
        }
    }

    #[test]
    fn a_reader_who_never_chose_hears_of_the_defaults() {
        let none = settings("{}");
        assert!(wants(&none, "backup_failed"));
        assert!(!wants(&none, "backup_done"));
        assert!(wants(&none, "server_malware"));
        assert!(!wants(&none, "no_such_event"));
        let chose = settings(r#"{"backup_done":true,"sign_in":false}"#);
        assert!(wants(&chose, "backup_done"));
        assert!(!wants(&chose, "sign_in"));
        assert!(wants(&settings("not json"), "security"));
        // Every kind has a key of its own.
        let mut keys: Vec<&str> = KINDS.iter().map(|k| k.key).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), KINDS.len());
    }

    #[test]
    fn a_failed_schedule_tells_the_administrators_and_each_owner_their_part() {
        let event = Event::ScheduleRun {
            schedule: "Nightly".into(),
            users: vec![
                UserBackup {
                    user_id: 2,
                    username: "alice".into(),
                    outcome: Ok("alice.tar.gz".into()),
                },
                UserBackup {
                    user_id: 3,
                    username: "bob".into(),
                    outcome: Err("disk full".into()),
                },
            ],
            problem: None,
        };
        let messages = event.messages();
        let admin = messages
            .iter()
            .find(|m| m.audience == Audience::Admins)
            .unwrap();
        assert_eq!(admin.key, "server_backup_failed");
        assert_eq!(admin.content.subject.en, "Scheduled backup failed: Nightly");
        assert_eq!(admin.content.subject.vi, "Lịch sao lưu bị lỗi: Nightly");
        assert!(admin.content.lines.iter().any(|l| l.en == "bob: disk full"));
        let bob = messages
            .iter()
            .find(|m| m.audience == Audience::Owner(3))
            .unwrap();
        assert_eq!(bob.key, "backup_failed");
        assert!(bob.content.lines.iter().any(|l| l.vi == "Lý do: disk full"));
        let alice = messages
            .iter()
            .find(|m| m.audience == Audience::Owner(2))
            .unwrap();
        assert_eq!(alice.key, "backup_done");
    }

    #[test]
    fn malware_tells_each_owner_only_of_their_own_websites() {
        let threat = |path: &str, domain: &str, owner| Threat {
            path: path.into(),
            signature: "Eicar-Signature".into(),
            domain: domain.into(),
            owner,
            quarantined: true,
        };
        let messages = Event::Malware {
            threats: vec![
                threat("/home/a/a.com/x.php", "a.com", Some(2)),
                threat("/home/b/b.com/y.php", "b.com", Some(3)),
                threat("/home/b/b.com/z.php", "b.com", Some(3)),
            ],
        }
        .messages();
        let admin = messages
            .iter()
            .find(|m| m.audience == Audience::Admins)
            .unwrap();
        assert_eq!(admin.content.subject.en, "Malware found on 2 websites");
        let bob = messages
            .iter()
            .find(|m| m.audience == Audience::Owner(3))
            .unwrap();
        assert_eq!(bob.content.subject.vi, "Phát hiện mã độc trên b.com");
        assert!(bob.content.lines.iter().all(|l| !l.en.contains("a.com")));
        assert!(bob.content.lines[0]
            .en
            .starts_with("2 infected file(s); 2 moved to quarantine"));
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
            "alice",
            "https://panel.example.com:2222",
        );
        assert_eq!(out.subject, "Phát hiện mã độc trên <a.com>");
        assert!(out
            .text
            .contains("Mở panel: https://panel.example.com:2222/malware"));
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
        let bare = render(&content, Lang::En, "SNPanel", "alice", "");
        assert!(!bare.text.contains("Open the panel"));
    }

    #[test]
    fn the_log_shows_which_address_not_all_of_it() {
        assert_eq!(masked_address("alice@example.com"), "a***@example.com");
        assert_eq!(masked_chat("-1001234567890"), "…7890");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(512), "512 B");
    }
}
