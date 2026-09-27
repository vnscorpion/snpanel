//! FTP and FTPS, as far as a restore needs them: sign in, list the backup
//! archives in a folder, and fetch one.
//!
//! Not in the Python. Written on what the workspace already has - tokio and
//! rustls, as the SMTP client is - rather than a crate of its own for the few
//! commands a restore sends. Passive mode only, `EPSV` first and `PASV` when
//! the server has no `EPSV`, and the data connection always goes to the
//! address the control connection reached: a server behind NAT names its
//! private address in `227`. The folder is listed with `MLSD`, or - for a
//! server without it, such as vsftpd - with `NLST` and a `SIZE` and `MDTM`
//! for each archive.
//!
//! **FTPS** is explicit: `AUTH TLS` before the user name, `PBSZ 0` and
//! `PROT P` after it, so the password and every transfer are encrypted. The
//! data connections resume the control connection's TLS session, which
//! vsftpd insists on. The certificate is checked against this machine's
//! roots; one they do not vouch for - a self-signed one, as FTP servers often
//! have - fails with its SHA-256, and is trusted from then on only when the
//! administrator gives that fingerprint back, the way an SFTP host key is
//! pinned. Given back, it is the only one taken: another - the server's
//! certificate replaced - fails with its own SHA-256 the same way.
//!
//! Plain FTP sends the password in the clear, which the page says; it is
//! still the only way into some old servers a restore has to come from.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::sftp::{archive_name_ok, RemoteArchive};

/// Any one step: connecting, a reply, a handshake.
const STEP_TIMEOUT: Duration = Duration::from_secs(20);
/// A reply's lines, at most.
const MAX_REPLY: usize = 64 * 1024;
/// A folder's listing, at most.
const MAX_LISTING: u64 = 4 * 1024 * 1024;

/// Where to sign in, and how.
pub struct Server<'a> {
    pub host: &'a str,
    pub port: u16,
    pub username: &'a str,
    pub password: &'a str,
    /// FTPS: `AUTH TLS` before signing in, and every transfer encrypted.
    pub tls: bool,
    /// FTPS: a certificate this machine's roots do not vouch for, trusted by
    /// its SHA-256 (hex).
    pub trusted: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FtpError {
    /// FTPS: the server's certificate is not one this machine trusts. Its
    /// SHA-256, for the administrator to trust or not.
    Untrusted(String),
    Failed(String),
}

impl std::fmt::Display for FtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Untrusted(fingerprint) => write!(
                f,
                "The FTP server's certificate is not one this machine trusts (SHA-256 {fingerprint})"
            ),
            Self::Failed(message) => f.write_str(message),
        }
    }
}

fn fail(message: impl Into<String>) -> FtpError {
    FtpError::Failed(message.into())
}

/// A step of the conversation, for what the server refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Greeting,
    Encryption,
    SignIn,
    Folder,
    Listing,
    Passive,
    Mode,
    Transfer,
}

fn refused(step: Step, said: &str) -> FtpError {
    fail(match step {
        Step::Greeting => format!("The FTP server turned the connection away: {said}"),
        Step::Encryption => format!("The FTP server refused encryption: {said}"),
        Step::SignIn => format!("The FTP server refused the sign-in: {said}"),
        Step::Folder => format!("The FTP server cannot open the folder: {said}"),
        Step::Listing => format!("The FTP server refused to list the folder: {said}"),
        Step::Passive => format!("The FTP server offers no passive connection: {said}"),
        Step::Mode => format!("The FTP server refused binary transfers: {said}"),
        Step::Transfer => format!("The FTP server did not finish the transfer: {said}"),
    })
}

/// A reply: its code, and its text on one line.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reply {
    code: u16,
    text: String,
}

impl Reply {
    fn said(&self) -> String {
        let text: String = self
            .text
            .chars()
            .filter(|c| !c.is_control())
            .take(200)
            .collect();
        format!("{} {}", self.code, text.trim())
    }
}

/// The control connection, plain or encrypted.
struct Session<S> {
    control: BufReader<S>,
    /// Where the control connection went: the data connections go there too.
    peer: IpAddr,
    /// FTPS: how each data connection is encrypted.
    tls: Option<(tokio_rustls::TlsConnector, ServerName<'static>)>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Session<S> {
    fn new(stream: S, peer: IpAddr) -> Self {
        Self {
            control: BufReader::new(stream),
            peer,
            tls: None,
        }
    }

    async fn line(&mut self, budget: &mut usize) -> Result<String, FtpError> {
        let mut raw = Vec::new();
        let read = tokio::time::timeout(STEP_TIMEOUT, async {
            (&mut self.control)
                .take(*budget as u64 + 1)
                .read_until(b'\n', &mut raw)
                .await
        })
        .await
        .map_err(|_| fail("The FTP server stopped answering"))?
        .map_err(|e| fail(format!("The connection to the FTP server broke: {e}")))?;
        if read == 0 {
            return Err(fail("The FTP server closed the connection"));
        }
        if read > *budget {
            return Err(fail("The FTP server's answer does not end"));
        }
        *budget -= read;
        Ok(String::from_utf8_lossy(&raw)
            .trim_end_matches(['\r', '\n'])
            .to_string())
    }

    /// A reply: `123 text`, or `123-text` and lines up to `123 text`.
    async fn reply(&mut self) -> Result<Reply, FtpError> {
        let mut budget = MAX_REPLY;
        let first = self.line(&mut budget).await?;
        let code = first
            .get(..3)
            .filter(|c| c.chars().all(|d| d.is_ascii_digit()))
            .and_then(|c| c.parse::<u16>().ok())
            .ok_or_else(|| fail("The FTP server's answer is not FTP"))?;
        let mut text = first.get(4..).unwrap_or("").to_string();
        if first.as_bytes().get(3) == Some(&b'-') {
            let end = format!("{code} ");
            loop {
                let next = self.line(&mut budget).await?;
                if next.starts_with(&end) || next == code.to_string() {
                    text.push(' ');
                    text.push_str(next.get(4..).unwrap_or(""));
                    break;
                }
            }
        }
        Ok(Reply { code, text })
    }

    async fn send(&mut self, line: &str) -> Result<(), FtpError> {
        if line.contains(['\r', '\n', '\0']) {
            return Err(fail("A line break cannot be sent to the FTP server"));
        }
        let stream = self.control.get_mut();
        tokio::time::timeout(STEP_TIMEOUT, async {
            stream.write_all(line.as_bytes()).await?;
            stream.write_all(b"\r\n").await?;
            stream.flush().await
        })
        .await
        .map_err(|_| fail("The FTP server stopped reading"))?
        .map_err(|e| fail(format!("The connection to the FTP server broke: {e}")))
    }

    async fn command(&mut self, line: &str, expect: &[u16], step: Step) -> Result<Reply, FtpError> {
        self.send(line).await?;
        let reply = self.reply().await?;
        if expect.contains(&reply.code) {
            Ok(reply)
        } else {
            Err(refused(step, &reply.said()))
        }
    }

    /// The stream back, for `AUTH TLS`. Nothing may be waiting in the
    /// buffer: it would be read as if it had come over TLS.
    fn into_inner(self) -> Result<S, FtpError> {
        if !self.control.buffer().is_empty() {
            return Err(fail(
                "The FTP server sent more than it should before encryption",
            ));
        }
        Ok(self.control.into_inner())
    }

    async fn sign_in(&mut self, server: &Server<'_>) -> Result<(), FtpError> {
        let user = self
            .command(
                &format!("USER {}", server.username),
                &[230, 331],
                Step::SignIn,
            )
            .await?;
        if user.code == 331 {
            self.command(
                &format!("PASS {}", server.password),
                &[230, 202],
                Step::SignIn,
            )
            .await?;
        }
        Ok(())
    }

    /// A passive data connection, to the control connection's own address.
    async fn data(&mut self) -> Result<TcpStream, FtpError> {
        self.send("EPSV").await?;
        let reply = self.reply().await?;
        let port = if reply.code == 229 {
            epsv_port(&reply.text).ok_or_else(|| refused(Step::Passive, &reply.said()))?
        } else {
            let reply = self.command("PASV", &[227], Step::Passive).await?;
            pasv_port(&reply.text).ok_or_else(|| refused(Step::Passive, &reply.said()))?
        };
        let address = SocketAddr::new(self.peer, port);
        tokio::time::timeout(STEP_TIMEOUT, TcpStream::connect(address))
            .await
            .map_err(|_| fail(format!("Connecting to {address} timed out")))?
            .map_err(|e| fail(format!("Cannot connect to {address}: {e}")))
    }

    /// The rest of a transfer's reply, once its data has been read.
    async fn finished(&mut self, step: Step) -> Result<(), FtpError> {
        let reply = self.reply().await?;
        if matches!(reply.code, 226 | 250) {
            Ok(())
        } else {
            Err(refused(step, &reply.said()))
        }
    }

    /// Everything a data connection carries, up to `limit` bytes - into
    /// `sink`, through TLS when the session is FTPS. How many bytes.
    async fn receive<W: AsyncWrite + Unpin>(
        &self,
        tcp: TcpStream,
        limit: u64,
        sink: &mut W,
    ) -> Result<u64, FtpError> {
        match &self.tls {
            Some((connector, name)) => {
                let stream =
                    tokio::time::timeout(STEP_TIMEOUT, connector.connect(name.clone(), tcp))
                        .await
                        .map_err(|_| fail("The TLS handshake with the FTP server timed out"))?
                        .map_err(|e| {
                            fail(format!("The TLS handshake with the FTP server failed: {e}"))
                        })?;
                pump(stream, limit, sink).await
            }
            None => pump(tcp, limit, sink).await,
        }
    }

    async fn change_folder(&mut self, folder: &str) -> Result<(), FtpError> {
        let folder = folder.trim();
        if folder.is_empty() || folder == "." {
            return Ok(());
        }
        self.command(&format!("CWD {folder}"), &[250, 200], Step::Folder)
            .await
            .map(|_| ())
    }

    /// The archives in the folder the session is in.
    async fn archives(&mut self) -> Result<Vec<RemoteArchive>, FtpError> {
        let tcp = self.data().await?;
        self.send("MLSD").await?;
        let reply = self.reply().await?;
        if matches!(reply.code, 125 | 150) {
            let mut body = Vec::new();
            self.receive(tcp, MAX_LISTING, &mut body).await?;
            self.finished(Step::Listing).await?;
            return Ok(sorted(parse_mlsd(&String::from_utf8_lossy(&body))));
        }
        if !matches!(reply.code, 500 | 501 | 502 | 504) {
            return Err(refused(Step::Listing, &reply.said()));
        }
        // No MLSD: the names, then each archive's size and time.
        drop(tcp);
        let tcp = self.data().await?;
        self.command("NLST", &[125, 150], Step::Listing).await?;
        let mut body = Vec::new();
        self.receive(tcp, MAX_LISTING, &mut body).await?;
        self.finished(Step::Listing).await?;
        let names: Vec<String> = String::from_utf8_lossy(&body)
            .lines()
            .map(|line| line.trim().rsplit('/').next().unwrap_or("").to_string())
            .filter(|name| archive_name_ok(name))
            .collect();
        let mut found = Vec::new();
        for name in names {
            self.send(&format!("SIZE {name}")).await?;
            let size = self.reply().await?;
            if size.code != 213 {
                // Not a plain file the server will send: left out.
                continue;
            }
            self.send(&format!("MDTM {name}")).await?;
            let modified = self.reply().await?;
            found.push(RemoteArchive {
                size: size.text.trim().parse().unwrap_or(0),
                modified: (modified.code == 213)
                    .then(|| mdtm_seconds(modified.text.trim()))
                    .flatten(),
                name,
            });
        }
        Ok(sorted(found))
    }

    async fn quit(&mut self) {
        let _ = self.send("QUIT").await;
    }
}

/// Up to `limit` bytes from `reader` into `sink`; one byte past it is an
/// error, not a truncated file. A data connection closed without TLS's
/// `close_notify` - which FTPS servers often do - is the end of its data; a
/// file's length is checked against `SIZE` by the caller.
async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    limit: u64,
    sink: &mut W,
) -> Result<u64, FtpError> {
    let mut buffer = vec![0u8; 128 * 1024];
    let mut copied: u64 = 0;
    loop {
        let read = match tokio::time::timeout(STEP_TIMEOUT * 3, reader.read(&mut buffer)).await {
            Err(_) => return Err(fail("The FTP server stopped sending")),
            Ok(Ok(0)) => break,
            Ok(Ok(read)) => read,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => return Err(fail(format!("The connection to the FTP server broke: {e}"))),
        };
        copied += read as u64;
        if copied > limit {
            return Err(fail(format!("The FTP server sent more than {limit} bytes")));
        }
        sink.write_all(&buffer[..read])
            .await
            .map_err(|e| fail(format!("The connection to the FTP server broke: {e}")))?;
    }
    sink.flush()
        .await
        .map_err(|e| fail(format!("The connection to the FTP server broke: {e}")))?;
    Ok(copied)
}

fn sorted(mut found: Vec<RemoteArchive>) -> Vec<RemoteArchive> {
    found.sort_by(|a, b| {
        b.modified
            .cmp(&a.modified)
            .then_with(|| a.name.cmp(&b.name))
    });
    found
}

/// `229 Entering Extended Passive Mode (|||6446|)` - the port.
fn epsv_port(text: &str) -> Option<u16> {
    let inside = text.split_once('(')?.1.split_once(')')?.0;
    let delimiter = inside.chars().next()?;
    let parts: Vec<&str> = inside.split(delimiter).collect();
    parts.get(3)?.parse().ok().filter(|p| *p > 0)
}

/// `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)` - the port. The address
/// it names is ignored for the control connection's.
fn pasv_port(text: &str) -> Option<u16> {
    let start = text.find(|c: char| c.is_ascii_digit())?;
    let numbers: Vec<u16> = text[start..]
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .take(6)
        .map(|part| part.parse().ok())
        .collect::<Option<Vec<u16>>>()?;
    if numbers.len() != 6 || numbers[4] > 255 || numbers[5] > 255 {
        return None;
    }
    Some(numbers[4] * 256 + numbers[5]).filter(|p| *p > 0)
}

/// `MLSD`'s lines: `type=file;size=123;modify=20260926101549; name`.
fn parse_mlsd(body: &str) -> Vec<RemoteArchive> {
    body.lines()
        .filter_map(|line| {
            let (facts, name) = line.split_once(' ')?;
            let name = name.trim_end_matches('\r');
            let mut kind = "";
            let mut size = 0;
            let mut modified = None;
            for fact in facts.split(';') {
                let Some((key, value)) = fact.split_once('=') else {
                    continue;
                };
                match key.to_ascii_lowercase().as_str() {
                    "type" => kind = value,
                    "size" => size = value.parse().unwrap_or(0),
                    "modify" => modified = mdtm_seconds(value),
                    _ => {}
                }
            }
            (kind.eq_ignore_ascii_case("file") && archive_name_ok(name)).then(|| RemoteArchive {
                name: name.to_string(),
                size,
                modified,
            })
        })
        .collect()
}

/// `20260926101549` or `20260926101549.123`, UTC, as seconds since the epoch.
fn mdtm_seconds(text: &str) -> Option<u32> {
    let digits = text.split('.').next()?;
    let time = chrono::NaiveDateTime::parse_from_str(digits, "%Y%m%d%H%M%S").ok()?;
    u32::try_from(time.and_utc().timestamp()).ok()
}

// ---------------------------------------------------------------- TLS

/// The certificate check: this machine's roots, or - when the administrator
/// trusted one - that certificate's SHA-256. The SHA-256 of a certificate
/// refused is kept, for the error that asks.
#[derive(Debug)]
struct Checker {
    roots: Arc<rustls::client::WebPkiServerVerifier>,
    trusted: Option<String>,
    refused: Arc<Mutex<Option<String>>>,
}

impl ServerCertVerifier for Checker {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fingerprint = snpanel_core::crypto::sigv4::sha256_hex(end_entity.as_ref());
        let verdict = match &self.trusted {
            Some(trusted) => {
                use subtle::ConstantTimeEq;
                let same = trusted.len() == fingerprint.len()
                    && bool::from(trusted.as_bytes().ct_eq(fingerprint.as_bytes()));
                if same {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::ApplicationVerificationFailure,
                    ))
                }
            }
            None => self.roots.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ),
        };
        if verdict.is_err() {
            if let Ok(mut slot) = self.refused.lock() {
                *slot = Some(fingerprint);
            }
        }
        verdict
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.roots.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.roots.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.roots.supported_verify_schemes()
    }
}

/// The TLS client for one server.
struct TlsClient {
    connector: tokio_rustls::TlsConnector,
    /// The name the certificate is checked under.
    name: ServerName<'static>,
    /// Where the SHA-256 of a certificate refused is left.
    refused: Arc<Mutex<Option<String>>>,
}

fn tls_client(server: &Server<'_>) -> Result<TlsClient, FtpError> {
    let roots = crate::cloudflare::system_roots()
        .unwrap_or_else(|| Arc::new(rustls::RootCertStore::empty()));
    let verifier = rustls::client::WebPkiServerVerifier::builder(roots)
        .build()
        .map_err(|e| fail(format!("The TLS handshake with the FTP server failed: {e}")))?;
    let refused = Arc::new(Mutex::new(None));
    let checker = Checker {
        roots: verifier,
        trusted: server
            .trusted
            .map(|t| t.trim().to_ascii_lowercase().replace(':', ""))
            .filter(|t| !t.is_empty()),
        refused: refused.clone(),
    };
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(checker))
        .with_no_client_auth();
    let name = ServerName::try_from(server.host.trim_matches(['[', ']']).to_string())
        .map_err(|_| fail("The FTP server's name cannot be checked against a certificate"))?;
    Ok(TlsClient {
        connector: tokio_rustls::TlsConnector::from(Arc::new(config)),
        name,
        refused,
    })
}

// ---------------------------------------------------------------- a session

/// What a session is run for, plain or encrypted alike.
enum Work<'a> {
    List,
    Fetch {
        name: &'a str,
        dest: &'a Path,
        max_bytes: u64,
    },
}

enum Done {
    Listed(Vec<RemoteArchive>),
    Fetched(u64),
}

async fn work_in<S: AsyncRead + AsyncWrite + Unpin>(
    session: &mut Session<S>,
    folder: &str,
    work: &Work<'_>,
) -> Result<Done, FtpError> {
    session.command("TYPE I", &[200], Step::Mode).await?;
    session.change_folder(folder).await?;
    let done = match work {
        Work::List => Done::Listed(session.archives().await?),
        Work::Fetch {
            name,
            dest,
            max_bytes,
        } => {
            // Its length first: what a transfer that ends early is found by.
            session.send(&format!("SIZE {name}")).await?;
            let size = session.reply().await?;
            let expected = (size.code == 213)
                .then(|| size.text.trim().parse::<u64>().ok())
                .flatten();
            if expected.is_some_and(|bytes| bytes > *max_bytes) {
                return Err(fail(format!("{name} is larger than {max_bytes} bytes")));
            }
            let tcp = session.data().await?;
            session.send(&format!("RETR {name}")).await?;
            let reply = session.reply().await?;
            if !matches!(reply.code, 125 | 150) {
                return Err(fail(format!(
                    "The FTP server will not send {name}: {}",
                    reply.said()
                )));
            }
            let local = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dest)
                .await
                .map_err(|e| fail(format!("Cannot write {}: {e}", dest.display())))?;
            let mut local = tokio::io::BufWriter::with_capacity(256 * 1024, local);
            let received = session.receive(tcp, *max_bytes, &mut local).await;
            let written = match received {
                Ok(written) => written,
                Err(FtpError::Failed(message))
                    if message.starts_with("The FTP server sent more than") =>
                {
                    let _ = tokio::fs::remove_file(dest).await;
                    return Err(fail(format!("{name} is larger than {max_bytes} bytes")));
                }
                Err(e) => {
                    let _ = tokio::fs::remove_file(dest).await;
                    return Err(e);
                }
            };
            if let Err(e) = session.finished(Step::Transfer).await {
                let _ = tokio::fs::remove_file(dest).await;
                return Err(e);
            }
            if expected.is_some_and(|bytes| bytes != written) {
                let _ = tokio::fs::remove_file(dest).await;
                return Err(fail(format!(
                    "The transfer of {name} ended early: {written} of {} bytes",
                    expected.unwrap_or(0)
                )));
            }
            Done::Fetched(written)
        }
    };
    session.quit().await;
    Ok(done)
}

/// Connected, encrypted when FTPS, signed in - and the work done.
async fn run(server: &Server<'_>, folder: &str, work: Work<'_>) -> Result<Done, FtpError> {
    let host = server.host.trim_matches(['[', ']']);
    let tcp = tokio::time::timeout(STEP_TIMEOUT, TcpStream::connect((host, server.port)))
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
    let peer = tcp
        .peer_addr()
        .map_err(|e| {
            fail(format!(
                "Cannot connect to {}:{}: {e}",
                server.host, server.port
            ))
        })?
        .ip();
    let mut plain = Session::new(tcp, peer);
    let greeting = plain.reply().await?;
    if greeting.code != 220 {
        return Err(refused(Step::Greeting, &greeting.said()));
    }
    if !server.tls {
        plain.sign_in(server).await?;
        return work_in(&mut plain, folder, &work).await;
    }
    plain.command("AUTH TLS", &[234], Step::Encryption).await?;
    let tcp = plain.into_inner()?;
    let TlsClient {
        connector,
        name,
        refused,
    } = tls_client(server)?;
    let stream =
        match tokio::time::timeout(STEP_TIMEOUT, connector.connect(name.clone(), tcp)).await {
            Err(_) => return Err(fail("The TLS handshake with the FTP server timed out")),
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                // A certificate refused - one the machine does not vouch for,
                // or not the one trusted - asks to be trusted; anything else is
                // a failed handshake.
                let fingerprint = refused.lock().ok().and_then(|slot| slot.clone());
                return Err(match fingerprint {
                    Some(fingerprint) => FtpError::Untrusted(fingerprint),
                    None => fail(format!("The TLS handshake with the FTP server failed: {e}")),
                });
            }
        };
    let mut secure = Session::new(stream, peer);
    secure.tls = Some((connector, name));
    secure.sign_in(server).await?;
    secure.command("PBSZ 0", &[200], Step::Encryption).await?;
    secure.command("PROT P", &[200], Step::Encryption).await?;
    work_in(&mut secure, folder, &work).await
}

/// The backup archives in `folder`, newest first.
pub async fn list(server: &Server<'_>, folder: &str) -> Result<Vec<RemoteArchive>, FtpError> {
    match run(server, folder, Work::List).await? {
        Done::Listed(found) => Ok(found),
        Done::Fetched(_) => Ok(Vec::new()),
    }
}

/// One archive of `folder` into `dest`, which must not exist yet; removed
/// again when the transfer fails or the server sends more than `max_bytes`.
/// How many bytes.
pub async fn download(
    server: &Server<'_>,
    folder: &str,
    name: &str,
    dest: &Path,
    max_bytes: u64,
) -> Result<u64, FtpError> {
    if !archive_name_ok(name) {
        return Err(fail(format!("Not a backup archive: {name}")));
    }
    match run(
        server,
        folder,
        Work::Fetch {
            name,
            dest,
            max_bytes,
        },
    )
    .await?
    {
        Done::Fetched(written) => Ok(written),
        Done::Listed(_) => Ok(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn the_passive_ports_are_read_from_either_reply() {
        assert_eq!(
            epsv_port("Entering Extended Passive Mode (|||6446|)"),
            Some(6446)
        );
        assert_eq!(
            epsv_port("Entering Extended Passive Mode (!!!6446!)"),
            Some(6446)
        );
        assert_eq!(epsv_port("no port"), None);
        assert_eq!(
            pasv_port("Entering Passive Mode (10,0,0,5,25,46)."),
            Some(25 * 256 + 46)
        );
        assert_eq!(pasv_port("Entering Passive Mode (10,0,0,5,999,1)"), None);
        assert_eq!(pasv_port("Entering Passive Mode"), None);
    }

    #[test]
    fn an_mlsd_listing_keeps_the_archives_that_are_files() {
        let found = parse_mlsd(
            "type=cdir;modify=20260926000000; .\r\n\
             type=file;size=4120;modify=20260926101549; user-demo-20260926101549.tar.gz\r\n\
             type=file;size=9;modify=20260926101549; notes.txt\r\n\
             type=dir;modify=20260926101549; old.tar.gz\r\n\
             Type=File;Size=77;Modify=20260927030000.123; demo-sunday.tar.gz\r\n",
        );
        let names: Vec<(&str, u64)> = found.iter().map(|a| (a.name.as_str(), a.size)).collect();
        assert_eq!(
            names,
            [
                ("user-demo-20260926101549.tar.gz", 4120),
                ("demo-sunday.tar.gz", 77)
            ]
        );
        assert_eq!(found[0].modified, mdtm_seconds("20260926101549"));
        assert_eq!(mdtm_seconds("20260926101549"), Some(1_790_417_749));
        assert_eq!(mdtm_seconds("garbage"), None);
    }

    /// A server that answers from a script and serves one passive listing
    /// and one file: enough to see a session go the way a real one does.
    async fn scripted(
        mlsd: bool,
        password_ok: bool,
    ) -> (u16, tokio::task::JoinHandle<Vec<String>>) {
        let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = control.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (socket, _) = control.accept().await.unwrap();
            let (read, mut write) = socket.into_split();
            let mut lines = BufReader::new(read).lines();
            let mut seen = Vec::new();
            // Each passive command a listener of its own, as a real server.
            let mut data: Option<TcpListener> = None;
            async fn passive(slot: &mut Option<TcpListener>) -> u16 {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = listener.local_addr().unwrap().port();
                *slot = Some(listener);
                port
            }
            write
                .write_all(b"220-Welcome\r\n to the test\r\n220 ready\r\n")
                .await
                .unwrap();
            while let Ok(Some(line)) = lines.next_line().await {
                seen.push(line.clone());
                let (verb, arg) = line.split_once(' ').unwrap_or((line.as_str(), ""));
                let answer: String = match verb {
                    "USER" => "331 password please\r\n".into(),
                    "PASS" if password_ok => "230 in\r\n".into(),
                    "PASS" => "530 Login incorrect.\r\n".into(),
                    "TYPE" => "200 binary\r\n".into(),
                    "CWD" if arg == "/backups" => "250 there\r\n".into(),
                    "CWD" => "550 No such directory.\r\n".into(),
                    "EPSV" if mlsd => {
                        let port = passive(&mut data).await;
                        format!("229 Entering Extended Passive Mode (|||{port}|)\r\n")
                    }
                    "EPSV" => "500 unknown\r\n".into(),
                    "PASV" => {
                        let port = passive(&mut data).await;
                        format!(
                            "227 Entering Passive Mode (10,9,8,7,{},{})\r\n",
                            port / 256,
                            port % 256
                        )
                    }
                    "MLSD" if mlsd => {
                        write.write_all(b"150 listing\r\n").await.unwrap();
                        let (mut out, _) = data.take().unwrap().accept().await.unwrap();
                        out.write_all(b"type=file;size=12;modify=20260926101549; user-demo-20260926101549.tar.gz\r\ntype=file;size=3;modify=20260926101549; readme.txt\r\n").await.unwrap();
                        drop(out);
                        "226 done\r\n".into()
                    }
                    "MLSD" => "500 unknown command\r\n".into(),
                    "NLST" => {
                        write.write_all(b"150 names\r\n").await.unwrap();
                        let (mut out, _) = data.take().unwrap().accept().await.unwrap();
                        out.write_all(b"user-demo-20260926101549.tar.gz\r\nreadme.txt\r\n")
                            .await
                            .unwrap();
                        drop(out);
                        "226 done\r\n".into()
                    }
                    "SIZE" => "213 12\r\n".into(),
                    "MDTM" => "213 20260926101549\r\n".into(),
                    "RETR" if arg == "user-demo-20260926101549.tar.gz" => {
                        write.write_all(b"150 sending\r\n").await.unwrap();
                        let (mut out, _) = data.take().unwrap().accept().await.unwrap();
                        out.write_all(b"hello, world").await.unwrap();
                        drop(out);
                        "226 sent\r\n".into()
                    }
                    "RETR" => "550 No such file.\r\n".into(),
                    "QUIT" => {
                        let _ = write.write_all(b"221 bye\r\n").await;
                        break;
                    }
                    _ => "502 not here\r\n".into(),
                };
                if write.write_all(answer.as_bytes()).await.is_err() {
                    break;
                }
            }
            seen
        });
        (port, handle)
    }

    fn server(port: u16, password: &str) -> Server<'_> {
        Server {
            host: "127.0.0.1",
            port,
            username: "demo",
            password,
            tls: false,
            trusted: None,
        }
    }

    #[tokio::test]
    async fn a_folder_is_listed_with_mlsd_and_an_archive_fetched() {
        let (port, handle) = scripted(true, true).await;
        let found = list(&server(port, "secret"), "/backups").await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "user-demo-20260926101549.tar.gz");
        assert_eq!(found[0].size, 12);
        let seen = handle.await.unwrap();
        assert!(seen.contains(&"PASS secret".to_string()) && seen.contains(&"MLSD".to_string()));

        let (port, _handle) = scripted(true, true).await;
        let dest = std::env::temp_dir().join(format!("snpanel-ftp-{}.tar.gz", std::process::id()));
        let _ = std::fs::remove_file(&dest);
        let written = download(
            &server(port, "secret"),
            "/backups",
            "user-demo-20260926101549.tar.gz",
            &dest,
            1024,
        )
        .await
        .unwrap();
        assert_eq!(written, 12);
        assert_eq!(std::fs::read(&dest).unwrap(), b"hello, world");
        let _ = std::fs::remove_file(&dest);
    }

    #[tokio::test]
    async fn without_mlsd_or_epsv_it_uses_pasv_nlst_size_and_mdtm() {
        let (port, handle) = scripted(false, true).await;
        let found = list(&server(port, "secret"), "/backups").await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].size, 12);
        assert_eq!(found[0].modified, mdtm_seconds("20260926101549"));
        let seen = handle.await.unwrap();
        // PASV's address (10.9.8.7) was not where the data went: the control
        // connection's was.
        for verb in [
            "EPSV",
            "PASV",
            "NLST",
            "SIZE user-demo-20260926101549.tar.gz",
        ] {
            assert!(seen.iter().any(|l| l == verb), "{verb} in {seen:?}");
        }
    }

    #[tokio::test]
    async fn a_refusal_says_what_the_server_said_and_a_big_file_is_not_kept() {
        let (port, _handle) = scripted(true, false).await;
        let error = list(&server(port, "wrong"), "/backups").await.unwrap_err();
        assert_eq!(
            error,
            FtpError::Failed("The FTP server refused the sign-in: 530 Login incorrect.".into())
        );
        let (port, _handle) = scripted(true, true).await;
        let error = list(&server(port, "secret"), "/nowhere").await.unwrap_err();
        assert!(error
            .to_string()
            .starts_with("The FTP server cannot open the folder: 550"));

        let (port, _handle) = scripted(true, true).await;
        let dest =
            std::env::temp_dir().join(format!("snpanel-ftp-big-{}.tar.gz", std::process::id()));
        let _ = std::fs::remove_file(&dest);
        let error = download(
            &server(port, "secret"),
            "/backups",
            "user-demo-20260926101549.tar.gz",
            &dest,
            5,
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("is larger than 5 bytes"),
            "{error}"
        );
        assert!(!dest.exists(), "a file cut short is not left behind");
    }

    #[tokio::test]
    async fn a_line_break_is_never_sent() {
        let (port, _handle) = scripted(true, true).await;
        let error = list(&server(port, "secret\r\nDELE x"), "/backups")
            .await
            .unwrap_err();
        assert_eq!(
            error,
            FtpError::Failed("A line break cannot be sent to the FTP server".into())
        );
        assert!(download(
            &server(port, "x"),
            "/",
            "../etc.tar.gz",
            Path::new("/tmp/x"),
            1
        )
        .await
        .is_err());
    }
}
