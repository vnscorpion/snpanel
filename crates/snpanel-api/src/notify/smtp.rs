//! Mail, through the SMTP server an administrator gives the panel.
//!
//! Not in the Python. Written on what the workspace already has, as the S3
//! and Cloudflare clients are: tokio, `tokio-rustls` and the machine's trust
//! store ([`crate::cloudflare::system_roots`]). A few hundred lines of SMTP
//! are less to audit than a mail crate and its client stack.
//!
//! What it speaks: implicit TLS (port 465), STARTTLS (587, and 25 where a
//! server offers it), or neither - for a relay on this machine only. AUTH
//! PLAIN, or LOGIN where PLAIN is not offered. One message to one recipient
//! per connection: a notification is a handful of messages at most.
//!
//! What it will not do: sign in over a connection that is not encrypted,
//! unless the server is on the loopback, and put a line break of a caller's
//! into a header - a subject or a name with one would otherwise be a way to
//! add headers, or recipients, of its own. The password is never in an
//! error, a log line or a trace.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Connecting, and each reply after that.
const STEP_TIMEOUT: Duration = Duration::from_secs(30);
/// A whole message, from connecting to QUIT.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(90);
/// The longest reply line read; a server that sends more is not an SMTP
/// server.
const MAX_LINE: usize = 4096;

/// How the connection is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    /// Plain first, then `STARTTLS` - which the server has to offer.
    StartTls,
    /// TLS from the first byte: port 465.
    Tls,
    /// Neither: only for a relay on this machine.
    None,
}

impl Security {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "starttls" => Some(Self::StartTls),
            "tls" => Some(Self::Tls),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::StartTls => "starttls",
            Self::Tls => "tls",
            Self::None => "none",
        }
    }
}

/// Where mail goes out.
#[derive(Debug, Clone)]
pub struct Server {
    pub host: String,
    pub port: u16,
    pub security: Security,
    /// Empty: the server is not signed in to.
    pub username: String,
    pub password: String,
}

/// One message.
#[derive(Debug, Clone)]
pub struct Mail<'a> {
    pub from_address: &'a str,
    pub from_name: &'a str,
    pub to: &'a str,
    pub subject: &'a str,
    pub text: &'a str,
    pub html: &'a str,
}

/// Why a message did not go, in words for the person who set the server up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpError(pub String);

impl std::fmt::Display for SmtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn fail(message: impl Into<String>) -> SmtpError {
    SmtpError(message.into())
}

/// Whether `host` is this machine: the only place mail may be handed over,
/// or a password given, without encryption.
pub fn is_loopback(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// Whether `text` can be an address in a header and an envelope: one `@`,
/// something either side, and nothing that would end the header, the
/// `<...>` around it or the command it goes in.
pub fn valid_address(text: &str) -> bool {
    let Some((local, domain)) = text.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && text.len() <= 254
        && !domain.contains('@')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain.contains('.')
        && text
            .chars()
            .all(|c| c.is_ascii_graphic() && !"<>()[],;:\"\\".contains(c))
}

/// A header value with nothing in it that could end the header.
fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

/// RFC 2047: a header value as encoded words when it is not plain ASCII,
/// each at most 75 characters and split on character boundaries.
fn encoded_words(text: &str) -> String {
    let text = one_line(text);
    if text.is_ascii() {
        return text;
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in text.chars() {
        // 45 bytes encode to 60 characters; with "=?utf-8?b?" and "?=" that
        // is 72, inside the 75 an encoded word may be.
        if chunk.len() + c.len_utf8() > 45 {
            words.push(format!("=?utf-8?b?{}?=", engine.encode(chunk.as_bytes())));
            chunk.clear();
        }
        chunk.push(c);
    }
    if !chunk.is_empty() {
        words.push(format!("=?utf-8?b?{}?=", engine.encode(chunk.as_bytes())));
    }
    words.join("\r\n ")
}

/// A display name and an address, as a `From:` or `To:` value.
fn mailbox(name: &str, address: &str) -> String {
    let name = one_line(name);
    if name.is_empty() {
        return format!("<{address}>");
    }
    if name.is_ascii() {
        let quoted = name.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{quoted}\" <{address}>")
    } else {
        format!("{} <{address}>", encoded_words(&name))
    }
}

/// Base64 in lines of 76, as a body part is sent.
fn base64_lines(bytes: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    encoded
        .as_bytes()
        .chunks(76)
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// The domain half of an address, for the Message-ID.
fn domain_of(address: &str) -> &str {
    address
        .rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or("localhost")
}

/// The whole message: headers, then a plain and an HTML part. CRLF line
/// ends, and no line longer than 998 characters.
pub fn message(mail: &Mail<'_>, date: &str) -> String {
    let boundary = format!("snpanel-{}", random_hex(12));
    let message_id = format!("<{}@{}>", random_hex(16), domain_of(mail.from_address));
    let mut out = String::new();
    out.push_str(&format!(
        "From: {}\r\n",
        mailbox(mail.from_name, mail.from_address)
    ));
    out.push_str(&format!("To: <{}>\r\n", mail.to));
    out.push_str(&format!("Subject: {}\r\n", encoded_words(mail.subject)));
    out.push_str(&format!("Date: {date}\r\n"));
    out.push_str(&format!("Message-ID: {message_id}\r\n"));
    out.push_str("MIME-Version: 1.0\r\n");
    // RFC 3834: nobody's auto-responder should answer a notification.
    out.push_str("Auto-Submitted: auto-generated\r\n");
    out.push_str("X-Mailer: SNPanel\r\n");
    out.push_str(&format!(
        "Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n"
    ));
    for (kind, body) in [("text/plain", mail.text), ("text/html", mail.html)] {
        out.push_str(&format!("--{boundary}\r\n"));
        out.push_str(&format!("Content-Type: {kind}; charset=utf-8\r\n"));
        out.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
        out.push_str(&base64_lines(body.as_bytes()));
        out.push_str("\r\n");
    }
    out.push_str(&format!("--{boundary}--\r\n"));
    out
}

/// DATA's transparency: a line that starts with a dot gets another one, so
/// no line of the message can be the end of it.
fn dot_stuffed(message: &str) -> String {
    let mut out = String::with_capacity(message.len() + 8);
    for line in message.split_inclusive("\r\n") {
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
    }
    if !out.ends_with("\r\n") {
        out.push_str("\r\n");
    }
    out
}

/// A reply: its code and its lines' text.
#[derive(Debug)]
struct Reply {
    code: u16,
    lines: Vec<String>,
}

impl Reply {
    /// The reply as a message: the code and the server's own words, which
    /// are what tells an administrator what to fix - "535 Username and
    /// Password not accepted" says more than anything written here.
    fn said(&self) -> String {
        let text = self.lines.join(" ");
        let text: String = text.chars().filter(|c| !c.is_control()).take(300).collect();
        format!("{} {}", self.code, text.trim())
    }

    fn offers(&self, extension: &str) -> bool {
        self.lines.iter().any(|line| {
            line.split_whitespace()
                .next()
                .is_some_and(|word| word.eq_ignore_ascii_case(extension))
        })
    }

    fn auth_methods(&self) -> Vec<String> {
        self.lines
            .iter()
            .filter_map(|line| {
                let mut words = line.split_whitespace();
                let first = words.next()?;
                (first.eq_ignore_ascii_case("AUTH") || first.eq_ignore_ascii_case("AUTH="))
                    .then(|| words.map(|w| w.to_ascii_uppercase()).collect::<Vec<_>>())
            })
            .flatten()
            .collect()
    }
}

/// One side of a conversation with the server.
struct Conn<S> {
    stream: BufReader<S>,
}

/// A step of the conversation, for what the server refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Greeting,
    StartTls,
    SignIn,
    Sender,
    Recipient,
    Message,
}

/// The server refused a step, and said this.
fn refused(step: Step, said: &str) -> SmtpError {
    fail(match step {
        Step::Greeting => format!("The SMTP server refused the greeting: {said}"),
        Step::StartTls => format!("The SMTP server refused STARTTLS: {said}"),
        Step::SignIn => format!("The SMTP server refused the sign-in: {said}"),
        Step::Sender => format!("The SMTP server refused the sender: {said}"),
        Step::Recipient => format!("The SMTP server refused the recipient: {said}"),
        Step::Message => format!("The SMTP server refused the message: {said}"),
    })
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    fn new(stream: S) -> Self {
        Self {
            stream: BufReader::new(stream),
        }
    }

    async fn reply(&mut self) -> Result<Reply, SmtpError> {
        let mut lines = Vec::new();
        loop {
            let mut raw = Vec::new();
            let read = tokio::time::timeout(STEP_TIMEOUT, async {
                let mut limited = (&mut self.stream).take(MAX_LINE as u64);
                limited.read_until(b'\n', &mut raw).await
            })
            .await
            .map_err(|_| fail("The SMTP server stopped answering"))?
            .map_err(|e| fail(format!("The connection to the SMTP server broke: {e}")))?;
            if read == 0 {
                return Err(fail("The SMTP server closed the connection"));
            }
            let line = String::from_utf8_lossy(&raw);
            let line = line.trim_end_matches(['\r', '\n']);
            if line.len() < 3 {
                return Err(fail("The SMTP server's answer is not SMTP"));
            }
            let code: u16 = line[..3]
                .parse()
                .map_err(|_| fail("The SMTP server's answer is not SMTP"))?;
            let last = line.as_bytes().get(3) != Some(&b'-');
            lines.push(line.get(4..).unwrap_or("").to_string());
            if last {
                return Ok(Reply { code, lines });
            }
            if lines.len() > 100 {
                return Err(fail("The SMTP server's answer does not end"));
            }
        }
    }

    async fn send(&mut self, line: &str) -> Result<(), SmtpError> {
        let stream = self.stream.get_mut();
        tokio::time::timeout(STEP_TIMEOUT, async {
            stream.write_all(line.as_bytes()).await?;
            stream.write_all(b"\r\n").await?;
            stream.flush().await
        })
        .await
        .map_err(|_| fail("The SMTP server stopped reading"))?
        .map_err(|e| fail(format!("The connection to the SMTP server broke: {e}")))
    }

    /// A command, and the reply it has to get. `step` says what was refused
    /// when it does not.
    async fn command(
        &mut self,
        line: &str,
        expect: &[u16],
        step: Step,
    ) -> Result<Reply, SmtpError> {
        self.send(line).await?;
        let reply = self.reply().await?;
        if expect.contains(&reply.code) {
            Ok(reply)
        } else {
            Err(refused(step, &reply.said()))
        }
    }

    async fn ehlo(&mut self, name: &str) -> Result<Reply, SmtpError> {
        self.command(&format!("EHLO {name}"), &[250], Step::Greeting)
            .await
    }

    /// The stream back, for STARTTLS. Nothing may be waiting in the buffer:
    /// what a server sent before the handshake would otherwise be read as
    /// if it had come over TLS.
    fn into_inner(self) -> Result<S, SmtpError> {
        if !self.stream.buffer().is_empty() {
            return Err(fail(
                "The SMTP server sent more than it should before STARTTLS",
            ));
        }
        Ok(self.stream.into_inner())
    }
}

/// The name this machine greets the server with.
fn helo_name() -> String {
    let name = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let name = name.trim();
    if !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        name.to_string()
    } else {
        "snpanel".to_string()
    }
}

async fn tls(
    host: &str,
    tcp: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, SmtpError> {
    let roots = crate::cloudflare::system_roots().ok_or_else(|| {
        fail("This machine has no trusted certificates to check the SMTP server's against")
    })?;
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| fail("The SMTP server's name cannot be checked against a certificate"))?;
    tokio::time::timeout(
        STEP_TIMEOUT,
        tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp),
    )
    .await
    .map_err(|_| fail("The TLS handshake with the SMTP server timed out"))?
    .map_err(|e| {
        fail(format!(
            "The TLS handshake with the SMTP server failed: {e}"
        ))
    })
}

/// Sign in, then hand the message over. `caps` is the EHLO reply of the
/// connection as it is now - after STARTTLS, the second one.
async fn deliver<S: AsyncRead + AsyncWrite + Unpin>(
    mut conn: Conn<S>,
    caps: &Reply,
    server: &Server,
    encrypted: bool,
    mail: &Mail<'_>,
    date: &str,
) -> Result<(), SmtpError> {
    if !server.username.is_empty() {
        if !encrypted && !is_loopback(&server.host) {
            return Err(fail(
                "The password would cross the network unencrypted: choose STARTTLS or SSL/TLS",
            ));
        }
        let methods = caps.auth_methods();
        let engine = base64::engine::general_purpose::STANDARD;
        if methods.iter().any(|m| m == "PLAIN") {
            let token = engine.encode(format!("\0{}\0{}", server.username, server.password));
            conn.command(&format!("AUTH PLAIN {token}"), &[235], Step::SignIn)
                .await?;
        } else if methods.iter().any(|m| m == "LOGIN") {
            conn.command("AUTH LOGIN", &[334], Step::SignIn).await?;
            conn.command(&engine.encode(&server.username), &[334], Step::SignIn)
                .await?;
            conn.command(&engine.encode(&server.password), &[235], Step::SignIn)
                .await?;
        } else {
            return Err(fail(
                "The SMTP server offers no sign-in the panel knows (PLAIN or LOGIN)",
            ));
        }
    }
    conn.command(
        &format!("MAIL FROM:<{}>", mail.from_address),
        &[250],
        Step::Sender,
    )
    .await?;
    conn.command(
        &format!("RCPT TO:<{}>", mail.to),
        &[250, 251],
        Step::Recipient,
    )
    .await?;
    conn.command("DATA", &[354], Step::Message).await?;
    let body = dot_stuffed(&message(mail, date));
    let stream = conn.stream.get_mut();
    tokio::time::timeout(STEP_TIMEOUT, async {
        stream.write_all(body.as_bytes()).await?;
        stream.write_all(b".\r\n").await?;
        stream.flush().await
    })
    .await
    .map_err(|_| fail("The SMTP server stopped reading the message"))?
    .map_err(|e| fail(format!("The connection to the SMTP server broke: {e}")))?;
    let accepted = conn.reply().await?;
    if accepted.code != 250 {
        return Err(refused(Step::Message, &accepted.said()));
    }
    // Politeness: the message is already accepted, whatever QUIT gets.
    if conn.send("QUIT").await.is_ok() {
        let _ = conn.reply().await;
    }
    Ok(())
}

/// Send one message. `date` is RFC 5322's, from the caller's clock.
pub async fn send(server: &Server, mail: &Mail<'_>, date: &str) -> Result<(), SmtpError> {
    for address in [mail.from_address, mail.to] {
        if !valid_address(address) {
            return Err(fail(format!("{address:?} is not an e-mail address")));
        }
    }
    let exchange = async {
        let tcp = tokio::time::timeout(
            STEP_TIMEOUT,
            TcpStream::connect((server.host.as_str(), server.port)),
        )
        .await
        .map_err(|_| {
            fail(format!(
                "Connecting to {}:{} timed out",
                server.host, server.port
            ))
        })?
        .map_err(|e| {
            fail(format!(
                "Cannot connect to {}:{}: {e}",
                server.host, server.port
            ))
        })?;
        let helo = helo_name();
        match server.security {
            Security::Tls => {
                let mut conn = Conn::new(tls(&server.host, tcp).await?);
                expect_greeting(&mut conn).await?;
                let caps = conn.ehlo(&helo).await?;
                deliver(conn, &caps, server, true, mail, date).await
            }
            Security::None => {
                let mut conn = Conn::new(tcp);
                expect_greeting(&mut conn).await?;
                let caps = conn.ehlo(&helo).await?;
                deliver(conn, &caps, server, false, mail, date).await
            }
            Security::StartTls => {
                let mut conn = Conn::new(tcp);
                expect_greeting(&mut conn).await?;
                let caps = conn.ehlo(&helo).await?;
                if !caps.offers("STARTTLS") {
                    return Err(fail(
                        "The SMTP server does not offer STARTTLS: choose SSL/TLS, or another port",
                    ));
                }
                conn.command("STARTTLS", &[220], Step::StartTls).await?;
                let mut conn = Conn::new(tls(&server.host, conn.into_inner()?).await?);
                let caps = conn.ehlo(&helo).await?;
                deliver(conn, &caps, server, true, mail, date).await
            }
        }
    };
    tokio::time::timeout(TOTAL_TIMEOUT, exchange)
        .await
        .map_err(|_| fail("Sending took too long and was given up"))?
}

async fn expect_greeting<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<S>,
) -> Result<(), SmtpError> {
    let greeting = conn.reply().await?;
    if greeting.code != 220 {
        return Err(fail(format!(
            "The SMTP server turned the connection away: {}",
            greeting.said()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn decode_words(value: &str) -> String {
        value
            .split("\r\n ")
            .map(|word| {
                let inner = word
                    .strip_prefix("=?utf-8?b?")
                    .and_then(|w| w.strip_suffix("?="))
                    .expect("an encoded word");
                String::from_utf8(
                    base64::engine::general_purpose::STANDARD
                        .decode(inner)
                        .unwrap(),
                )
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn a_vietnamese_subject_is_encoded_words_split_on_characters() {
        let subject = "Sao lưu thất bại: lịch hằng ngày của máy chủ web chính - 3 tài khoản lỗi";
        let encoded = encoded_words(subject);
        assert!(encoded.is_ascii());
        for word in encoded.split("\r\n ") {
            assert!(word.len() <= 75, "{word}");
        }
        assert_eq!(decode_words(&encoded), subject);
        assert_eq!(encoded_words("Backup failed"), "Backup failed");
    }

    #[test]
    fn nothing_a_caller_gives_can_add_a_header() {
        let mail = Mail {
            from_address: "panel@example.com",
            from_name: "SNPanel\r\nBcc: victim@example.net",
            to: "admin@example.com",
            subject: "Hello\r\nBcc: victim@example.net",
            text: "body",
            html: "<p>body</p>",
        };
        let text = message(&mail, "Sat, 26 Sep 2026 10:00:00 +0000");
        let headers = text.split("\r\n\r\n").next().unwrap();
        assert!(!headers.lines().any(|l| l.starts_with("Bcc:")), "{headers}");
        assert!(headers.contains("Subject: Hello  Bcc: victim@example.net"));
        // And an address with a line break is not an address.
        assert!(!valid_address("a@example.com\r\nRCPT TO:<b@example.net>"));
        assert!(!valid_address("a@example.com>"));
        assert!(!valid_address("no-at-sign"));
        assert!(!valid_address("a@b"));
        assert!(!valid_address("a@@example.com"));
        assert!(valid_address("first.last+tag@mail.example.co.uk"));
    }

    #[test]
    fn the_parts_are_base64_in_short_lines_and_dots_are_stuffed() {
        let text = "Máy chủ ".repeat(40);
        let mail = Mail {
            from_address: "panel@example.com",
            from_name: "SNPanel",
            to: "admin@example.com",
            subject: "x",
            text: &text,
            html: "<p>x</p>",
        };
        let whole = message(&mail, "Sat, 26 Sep 2026 10:00:00 +0000");
        assert!(whole.lines().all(|l| l.len() <= 998));
        assert!(whole.contains("From: \"SNPanel\" <panel@example.com>"));
        assert!(whole.contains("Content-Type: text/plain; charset=utf-8"));
        assert!(whole.contains("Auto-Submitted: auto-generated"));
        assert_eq!(dot_stuffed(".a\r\nb\r\n..c\r\n"), "..a\r\nb\r\n...c\r\n");
    }

    /// A server that answers from a script and keeps what it was sent.
    async fn scripted(
        script: &'static [(&'static str, &'static str)],
    ) -> (u16, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut conn = BufReader::new(socket);
            conn.get_mut()
                .write_all(b"220 mail.example.com ESMTP ready\r\n")
                .await
                .unwrap();
            let mut heard = Vec::new();
            let mut in_data = false;
            loop {
                let mut line = String::new();
                if conn.read_line(&mut line).await.unwrap_or(0) == 0 {
                    break;
                }
                let line = line.trim_end().to_string();
                if in_data {
                    if line == "." {
                        in_data = false;
                        conn.get_mut()
                            .write_all(b"250 2.0.0 queued\r\n")
                            .await
                            .unwrap();
                    }
                    heard.push(format!("DATA| {line}"));
                    continue;
                }
                heard.push(line.clone());
                let verb = line.split([' ', ':']).next().unwrap_or("").to_string();
                let answer = script
                    .iter()
                    .find(|(v, _)| v.eq_ignore_ascii_case(&verb))
                    .map(|(_, a)| *a)
                    .unwrap_or("500 what");
                conn.get_mut().write_all(answer.as_bytes()).await.unwrap();
                if verb.eq_ignore_ascii_case("DATA") && answer.starts_with("354") {
                    in_data = true;
                }
                if verb.eq_ignore_ascii_case("QUIT") {
                    break;
                }
            }
            let mut rest = Vec::new();
            let _ = conn.read_to_end(&mut rest).await;
            heard
        });
        (port, handle)
    }

    fn server(port: u16, username: &str) -> Server {
        Server {
            host: "127.0.0.1".into(),
            port,
            security: Security::None,
            username: username.into(),
            password: "s3cret-pass".into(),
        }
    }

    const MAIL: Mail<'static> = Mail {
        from_address: "panel@example.com",
        from_name: "SNPanel",
        to: "admin@example.com",
        subject: "Sao lưu thất bại",
        text: "Chi tiết",
        html: "<p>Chi tiết</p>",
    };

    #[tokio::test]
    async fn a_message_goes_through_a_relay_on_this_machine() {
        static SCRIPT: &[(&str, &str)] = &[
            (
                "EHLO",
                "250-mail.example.com\r\n250-AUTH LOGIN PLAIN\r\n250 8BITMIME\r\n",
            ),
            ("AUTH", "235 2.7.0 Authentication successful\r\n"),
            ("MAIL", "250 2.1.0 Ok\r\n"),
            ("RCPT", "250 2.1.5 Ok\r\n"),
            ("DATA", "354 End data with <CR><LF>.<CR><LF>\r\n"),
            ("QUIT", "221 2.0.0 Bye\r\n"),
        ];
        let (port, heard) = scripted(SCRIPT).await;
        send(
            &server(port, "panel"),
            &MAIL,
            "Sat, 26 Sep 2026 10:00:00 +0000",
        )
        .await
        .unwrap();
        let heard = heard.await.unwrap();
        assert!(heard[0].starts_with("EHLO "), "{heard:?}");
        let plain = base64::engine::general_purpose::STANDARD.encode("\0panel\0s3cret-pass");
        assert_eq!(
            heard[1],
            format!("AUTH PLAIN {plain}"),
            "PLAIN when it is offered"
        );
        assert_eq!(heard[2], "MAIL FROM:<panel@example.com>");
        assert_eq!(heard[3], "RCPT TO:<admin@example.com>");
        assert!(heard
            .iter()
            .any(|l| l.starts_with("DATA| Subject: =?utf-8?b?")));
        assert_eq!(heard.last().map(String::as_str), Some("QUIT"));
    }

    #[tokio::test]
    async fn a_refused_sign_in_says_what_the_server_said_and_not_the_password() {
        static SCRIPT: &[(&str, &str)] = &[
            ("EHLO", "250-mail.example.com\r\n250 AUTH LOGIN\r\n"),
            ("AUTH", "334 VXNlcm5hbWU6\r\n"),
            ("cGFuZWw=", "334 UGFzc3dvcmQ6\r\n"),
            (
                "czNjcmV0LXBhc3M=",
                "535 5.7.8 Username and Password not accepted\r\n",
            ),
        ];
        let (port, _heard) = scripted(SCRIPT).await;
        let err = send(
            &server(port, "panel"),
            &MAIL,
            "Sat, 26 Sep 2026 10:00:00 +0000",
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.0,
            "The SMTP server refused the sign-in: 535 5.7.8 Username and Password not accepted"
        );
        assert!(!err.0.contains("s3cret"));
    }

    #[tokio::test]
    async fn no_password_crosses_the_network_unencrypted() {
        let (near, _far) = tokio::io::duplex(64);
        let err = deliver(
            Conn::new(near),
            &Reply {
                code: 250,
                lines: vec!["AUTH PLAIN".into()],
            },
            &Server {
                host: "mail.example.com".into(),
                ..server(25, "panel")
            },
            false,
            &MAIL,
            "Sat, 26 Sep 2026 10:00:00 +0000",
        )
        .await
        .unwrap_err();
        assert!(err.0.contains("unencrypted"), "{err}");
    }
}
