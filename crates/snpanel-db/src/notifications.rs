//! `notification_settings` and `notification_log` - the Notifications
//! addon's two tables.
//!
//! Not in the Python. A settings row is one account's choices: whether and
//! where it hears by e-mail and by Telegram, the language, and which events
//! it asked to hear of or not - a JSON object of `{event: bool}`, where an
//! event not in it takes its default. An account with no row hears of every
//! default event, by e-mail at its own address. The row also keeps the
//! addresses the account has signed in from, for "a sign-in from a new
//! address".
//!
//! The log is what was sent, to whom and how it went - the newest thousand
//! rows, for an administrator looking into why a message never arrived.
//!
//! **Rows answer to the username as well as the id**, as passkeys do: SQLite
//! can hand a deleted user's id to the next account created.

use sqlx::sqlite::SqlitePool;

use super::DbError;

/// How many sign-in addresses an account keeps, newest last.
pub const KNOWN_ADDRESSES: usize = 20;
/// How many log rows are kept.
pub const LOG_ROWS: i64 = 1000;

/// One account's choices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationSettings {
    pub email_enabled: bool,
    /// An address of the account's own choosing; `None` is the account's.
    pub email: Option<String>,
    pub telegram_enabled: bool,
    /// The chat a linked Telegram account is reached at.
    pub telegram_chat_id: Option<String>,
    /// Who it is on Telegram, as the link said: for the page.
    pub telegram_name: Option<String>,
    /// `{event: bool}`, JSON. An event not in it takes its default.
    pub events: String,
    /// `en` or `vi`; `None` is the panel's default.
    pub language: Option<String>,
}

impl Default for NotificationSettings {
    fn default() -> Self {
        Self {
            email_enabled: true,
            email: None,
            telegram_enabled: true,
            telegram_chat_id: None,
            telegram_name: None,
            events: "{}".to_string(),
            language: None,
        }
    }
}

/// A delivery, as the log keeps it.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct LogEntry {
    pub id: i64,
    pub created_at: String,
    pub event: String,
    pub user_id: Option<i64>,
    pub username: Option<String>,
    pub channel: String,
    /// The address or chat, as the log may show it.
    pub target: String,
    pub subject: String,
    /// `sent`, `failed` or `skipped`.
    pub status: String,
    pub detail: String,
}

/// A delivery to record.
#[derive(Debug, Clone)]
pub struct NewLogEntry<'a> {
    pub created_at: &'a str,
    pub event: &'a str,
    pub user_id: Option<i64>,
    pub username: Option<&'a str>,
    pub channel: &'a str,
    pub target: &'a str,
    pub subject: &'a str,
    pub status: &'a str,
    pub detail: &'a str,
}

type SettingsRow = (
    bool,
    Option<String>,
    bool,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
);

pub struct NotificationRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> NotificationRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// The account's choices, or the defaults when it made none.
    pub async fn get(&self, user_id: i64, username: &str) -> Result<NotificationSettings, DbError> {
        let row: Option<SettingsRow> = sqlx::query_as(
            "SELECT email_enabled, email, telegram_enabled, telegram_chat_id, telegram_name, \
             events, language FROM notification_settings WHERE user_id = ? AND username = ?",
        )
        .bind(user_id)
        .bind(username)
        .fetch_optional(self.pool)
        .await?;
        Ok(row
            .map(
                |(
                    email_enabled,
                    email,
                    telegram_enabled,
                    telegram_chat_id,
                    telegram_name,
                    events,
                    language,
                )| {
                    NotificationSettings {
                        email_enabled,
                        email,
                        telegram_enabled,
                        telegram_chat_id,
                        telegram_name,
                        events,
                        language,
                    }
                },
            )
            .unwrap_or_default())
    }

    /// Record the account's choices - all but its sign-in addresses, which
    /// stay as they were. A row of a deleted account with the same id is
    /// taken over, addresses and all forgotten.
    pub async fn save(
        &self,
        user_id: i64,
        username: &str,
        settings: &NotificationSettings,
        now: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO notification_settings (user_id, username, email_enabled, email, \
             telegram_enabled, telegram_chat_id, telegram_name, events, language, known_ips, \
             updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?) \
             ON CONFLICT (user_id) DO UPDATE SET \
             known_ips = CASE WHEN username = excluded.username THEN known_ips ELSE '' END, \
             username = excluded.username, email_enabled = excluded.email_enabled, \
             email = excluded.email, telegram_enabled = excluded.telegram_enabled, \
             telegram_chat_id = excluded.telegram_chat_id, \
             telegram_name = excluded.telegram_name, events = excluded.events, \
             language = excluded.language, updated_at = excluded.updated_at",
        )
        .bind(user_id)
        .bind(username)
        .bind(settings.email_enabled)
        .bind(&settings.email)
        .bind(settings.telegram_enabled)
        .bind(&settings.telegram_chat_id)
        .bind(&settings.telegram_name)
        .bind(&settings.events)
        .bind(&settings.language)
        .bind(now)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// A sign-in from `address`: recorded, and whether it is one to tell the
    /// account of - an address it has not signed in from before, when it has
    /// signed in from somewhere before. The first address on record tells
    /// nobody anything.
    pub async fn note_address(
        &self,
        user_id: i64,
        username: &str,
        address: &str,
        now: &str,
    ) -> Result<bool, DbError> {
        let known: Option<(String, String)> = sqlx::query_as(
            "SELECT username, known_ips FROM notification_settings WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_optional(self.pool)
        .await?;
        let mut addresses: Vec<String> = match &known {
            Some((owner, list)) if owner == username => list
                .split(',')
                .filter(|a| !a.is_empty())
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        };
        let new = !addresses.iter().any(|a| a == address);
        let tell = new && !addresses.is_empty();
        addresses.retain(|a| a != address);
        addresses.push(address.to_string());
        let keep = addresses.len().saturating_sub(KNOWN_ADDRESSES);
        let list = addresses[keep..].join(",");
        match known {
            Some((owner, _)) if owner == username => {
                sqlx::query("UPDATE notification_settings SET known_ips = ? WHERE user_id = ?")
                    .bind(&list)
                    .bind(user_id)
                    .execute(self.pool)
                    .await?;
            }
            _ => {
                let fresh = NotificationSettings::default();
                sqlx::query(
                    "INSERT INTO notification_settings (user_id, username, email_enabled, \
                     telegram_enabled, events, known_ips, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) \
                     ON CONFLICT (user_id) DO UPDATE SET username = excluded.username, \
                     email_enabled = excluded.email_enabled, email = NULL, \
                     telegram_enabled = excluded.telegram_enabled, telegram_chat_id = NULL, \
                     telegram_name = NULL, events = excluded.events, language = NULL, \
                     known_ips = excluded.known_ips, updated_at = excluded.updated_at",
                )
                .bind(user_id)
                .bind(username)
                .bind(fresh.email_enabled)
                .bind(fresh.telegram_enabled)
                .bind(&fresh.events)
                .bind(&list)
                .bind(now)
                .execute(self.pool)
                .await?;
            }
        }
        Ok(tell)
    }

    /// One delivery, and the oldest rows past [`LOG_ROWS`] gone.
    pub async fn log(&self, entry: &NewLogEntry<'_>) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO notification_log (created_at, event, user_id, username, channel, \
             target, subject, status, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(entry.created_at)
        .bind(entry.event)
        .bind(entry.user_id)
        .bind(entry.username)
        .bind(entry.channel)
        .bind(entry.target)
        .bind(entry.subject)
        .bind(entry.status)
        .bind(entry.detail)
        .execute(self.pool)
        .await?;
        sqlx::query(
            "DELETE FROM notification_log WHERE id <= \
             (SELECT id FROM notification_log ORDER BY id DESC LIMIT 1 OFFSET ?)",
        )
        .bind(LOG_ROWS)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// The newest deliveries, newest first.
    pub async fn recent(&self, limit: i64) -> Result<Vec<LogEntry>, DbError> {
        Ok(sqlx::query_as::<_, LogEntry>(
            "SELECT id, created_at, event, user_id, username, channel, target, subject, status, \
             detail FROM notification_log ORDER BY id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(self.pool)
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> super::super::Database {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let db = super::super::Database::from_pool(pool);
        db.create_fresh_schema().await.unwrap();
        db.apply_rust_migrations().await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, email, hashed_password) \
             VALUES (7, 'alice', 'alice@example.com', 'x'), (8, 'bob', 'bob@example.com', 'x')",
        )
        .execute(db.pool())
        .await
        .unwrap();
        db
    }

    #[tokio::test]
    async fn an_account_with_no_row_hears_of_the_defaults_by_email() {
        let db = db().await;
        let repo = db.notifications();
        assert_eq!(
            repo.get(7, "alice").await.unwrap(),
            NotificationSettings::default()
        );
        let mine = NotificationSettings {
            email: Some("me@example.net".into()),
            telegram_chat_id: Some("12345".into()),
            telegram_name: Some("@alice".into()),
            events: r#"{"sign_in":false}"#.into(),
            language: Some("vi".into()),
            ..NotificationSettings::default()
        };
        repo.save(7, "alice", &mine, "2026-09-26 10:00:00")
            .await
            .unwrap();
        assert_eq!(repo.get(7, "alice").await.unwrap(), mine);
        // The row answers to the username too.
        assert_eq!(
            repo.get(7, "mallory").await.unwrap(),
            NotificationSettings::default()
        );
        assert_eq!(
            repo.get(8, "bob").await.unwrap(),
            NotificationSettings::default()
        );
    }

    #[tokio::test]
    async fn a_new_sign_in_address_is_told_but_not_the_first() {
        let db = db().await;
        let repo = db.notifications();
        let now = "2026-09-26 10:00:00";
        assert!(
            !repo
                .note_address(7, "alice", "203.0.113.1", now)
                .await
                .unwrap(),
            "the first"
        );
        assert!(
            !repo
                .note_address(7, "alice", "203.0.113.1", now)
                .await
                .unwrap(),
            "known"
        );
        assert!(
            repo.note_address(7, "alice", "203.0.113.2", now)
                .await
                .unwrap(),
            "new"
        );
        assert!(
            !repo
                .note_address(7, "alice", "203.0.113.1", now)
                .await
                .unwrap(),
            "known again"
        );
        // Saving choices keeps the addresses.
        repo.save(7, "alice", &NotificationSettings::default(), now)
            .await
            .unwrap();
        assert!(!repo
            .note_address(7, "alice", "203.0.113.2", now)
            .await
            .unwrap());
        // Only the newest are kept: the oldest falls out and is new again.
        for i in 0..KNOWN_ADDRESSES {
            repo.note_address(7, "alice", &format!("198.51.100.{i}"), now)
                .await
                .unwrap();
        }
        assert!(repo
            .note_address(7, "alice", "203.0.113.1", now)
            .await
            .unwrap());
        // A reused id is someone else: nothing of alice's follows it.
        assert!(!repo
            .note_address(7, "carol", "203.0.113.9", now)
            .await
            .unwrap());
        assert!(!repo
            .note_address(7, "carol", "203.0.113.9", now)
            .await
            .unwrap());
        assert!(repo
            .note_address(7, "carol", "203.0.113.10", now)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn the_log_keeps_the_newest_rows() {
        let db = db().await;
        let repo = db.notifications();
        for i in 0..(LOG_ROWS + 5) {
            repo.log(&NewLogEntry {
                created_at: "2026-09-26 10:00:00",
                event: "sign_in",
                user_id: Some(7),
                username: Some("alice"),
                channel: "email",
                target: "a***@example.com",
                subject: &format!("message {i}"),
                status: "sent",
                detail: "",
            })
            .await
            .unwrap();
        }
        let recent = repo.recent(3).await.unwrap();
        assert_eq!(recent[0].subject, format!("message {}", LOG_ROWS + 4));
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notification_log")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, LOG_ROWS);
    }
}
