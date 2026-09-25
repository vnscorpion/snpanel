//! Uploads to an S3-compatible bucket: the S3 backup destination.
//!
//! Not in the Python. AWS S3, Cloudflare R2, Backblaze B2, Wasabi, MinIO and
//! the rest speak the same few requests, signed with Signature Version 4
//! (`snpanel_core::crypto::sigv4`). A backup is one object: one PUT when it
//! fits in a part, a multipart upload when it does not - which is also what
//! keeps a 40 GB archive from being read into memory.
//!
//! Built like the Cloudflare client, from hyper and rustls with the system's
//! trust store. The secret key signs and is never sent, logged or put in an
//! error; nor is anything of an error response past its `Code` and
//! `Message`, since a SignatureDoesNotMatch body carries what was signed.

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use snpanel_core::crypto::sigv4;

/// A part of a multipart upload, and the largest object sent in one PUT.
pub const PART_SIZE: u64 = 16 * 1024 * 1024;
/// S3 takes no more parts than this in one upload.
const MAX_PARTS: u64 = 10_000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// A request with no body to speak of.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(60);
/// A request carrying a part, or completing an upload of many: 16 MiB at
/// 10 KiB/s, and S3's own minutes of assembling a large object.
const DATA_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// How much of a response is read. An error document is a few hundred bytes.
const MAX_RESPONSE: usize = 1024 * 1024;
/// The pause before each retry of a request S3 says to retry.
#[cfg(not(test))]
const BACKOFF: [Duration; 2] = [Duration::from_secs(2), Duration::from_secs(8)];
#[cfg(test)]
const BACKOFF: [Duration; 2] = [Duration::ZERO, Duration::ZERO];
/// The object the connection test writes, and removes when it may.
pub const CHECK_OBJECT: &str = ".snpanel-write-test";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Error(pub String);

impl std::fmt::Display for S3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where the store answers: `https://s3.eu-west-1.amazonaws.com`,
/// `http://10.0.0.5:9000`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub tls: bool,
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    fn default_port(&self) -> u16 {
        if self.tls {
            443
        } else {
            80
        }
    }

    /// `host`, or `host:port` when the port is not the scheme's.
    fn authority(&self, host: &str) -> String {
        if self.port == self.default_port() {
            host.to_string()
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// As it is stored and shown.
    pub fn url(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!("{scheme}://{}", self.authority(&self.host))
    }
}

/// An endpoint as typed: a scheme, a host and perhaps a port. No scheme is
/// HTTPS.
pub fn parse_endpoint(raw: &str) -> Result<Endpoint, String> {
    let raw = raw.trim().to_ascii_lowercase();
    let (tls, rest) = if let Some(rest) = raw.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = raw.strip_prefix("http://") {
        (false, rest)
    } else if raw.contains("://") {
        return Err("The endpoint must start with https:// or http://".to_string());
    } else {
        (true, raw.as_str())
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.contains(['/', '?', '#', '@', '[', ']']) {
        return Err(
            "The endpoint is a host name and a port, with no path, user or IPv6 address"
                .to_string(),
        );
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => match port.parse::<u16>() {
            Ok(port) if port != 0 => (host, Some(port)),
            _ => return Err("The endpoint's port is not a port".to_string()),
        },
        None => (rest, None),
    };
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && !host.contains("..");
    if !host_ok {
        return Err("The endpoint's host name is not valid".to_string());
    }
    Ok(Endpoint {
        tls,
        host: host.to_string(),
        port: port.unwrap_or(if tls { 443 } else { 80 }),
    })
}

/// S3's bucket naming rules: 3 to 63 lower-case letters, digits, dots and
/// hyphens, starting and ending with a letter or digit, and not an address.
pub fn valid_bucket(name: &str) -> bool {
    let bytes = name.as_bytes();
    (3..=63).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && !name.contains("..")
        && name.parse::<Ipv4Addr>().is_err()
}

/// `us-east-1`, `auto` for R2, `garage`: whatever the store signs with.
pub fn valid_region(region: &str) -> bool {
    (1..=64).contains(&region.len())
        && region
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// An access key or a secret: printable ASCII with no spaces, which is what
/// every store issues and all a header can carry.
pub fn valid_key(text: &str, max: usize) -> bool {
    (1..=max).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_graphic())
}

/// The folder in the bucket, without the slashes around it; `None` when it
/// is not one. Letters, digits, `.`, `_` and `-`, in segments that are not
/// `.` or `..`.
pub fn normalise_prefix(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Some(String::new());
    }
    let ok = trimmed.len() <= 200
        && trimmed.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        });
    ok.then(|| trimmed.to_string())
}

/// Why a bucket cannot be addressed as `bucket.host`, when it cannot.
pub fn addressing_problem(
    endpoint: &Endpoint,
    bucket: &str,
    path_style: bool,
) -> Option<&'static str> {
    if path_style {
        return None;
    }
    if endpoint.host.parse::<Ipv4Addr>().is_ok() || endpoint.host == "localhost" {
        return Some("An endpoint given as an IP address or localhost needs path-style addressing");
    }
    if endpoint.tls && bucket.contains('.') {
        return Some(
            "A bucket name with dots needs path-style addressing over HTTPS: the store's certificate does not cover it",
        );
    }
    None
}

/// Who signs, and where to.
pub struct Target<'a> {
    pub endpoint: &'a Endpoint,
    pub region: &'a str,
    pub bucket: &'a str,
    /// Normalised: no slash at either end, empty for the bucket's root.
    pub prefix: &'a str,
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub path_style: bool,
}

/// The key an archive is stored under.
pub fn object_key(prefix: &str, file_name: &str) -> String {
    if prefix.is_empty() {
        file_name.to_string()
    } else {
        format!("{prefix}/{file_name}")
    }
}

/// Where a request goes: the host to connect to, the `Host` header, and the
/// path, encoded.
#[derive(Debug, PartialEq, Eq)]
struct Located {
    host: String,
    authority: String,
    path: String,
}

fn locate(target: &Target<'_>, key: &str) -> Located {
    let endpoint = target.endpoint;
    let encoded = sigv4::uri_encode(key, false);
    if target.path_style {
        Located {
            host: endpoint.host.clone(),
            authority: endpoint.authority(&endpoint.host),
            // No key is the bucket itself, for a listing: `/bucket`.
            path: if key.is_empty() {
                format!("/{}", target.bucket)
            } else {
                format!("/{}/{encoded}", target.bucket)
            },
        }
    } else {
        let host = format!("{}.{}", target.bucket, endpoint.host);
        Located {
            authority: endpoint.authority(&host),
            host,
            path: format!("/{encoded}"),
        }
    }
}

/// The query as sent. A parameter without a value goes as its bare name,
/// `?uploads`, as the AWS SDKs send it; it is signed as `uploads=`.
fn query_string(query: &[(&str, &str)]) -> String {
    query
        .iter()
        .map(|(name, value)| {
            if value.is_empty() {
                sigv4::uri_encode(name, true)
            } else {
                format!(
                    "{}={}",
                    sigv4::uri_encode(name, true),
                    sigv4::uri_encode(value, true)
                )
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// What came back.
#[derive(Debug)]
struct Reply {
    status: u16,
    etag: Option<String>,
    /// `x-amz-bucket-region`: where AWS says the bucket is.
    region: Option<String>,
    body: String,
}

impl Reply {
    /// A status that is not a success, or an `<Error>` inside one - which is
    /// how CompleteMultipartUpload reports a failure after its `200`.
    fn failed(&self) -> bool {
        !(200..300).contains(&self.status) || self.body.contains("<Error>")
    }

    /// The failures S3 says to try again.
    fn retryable(&self) -> bool {
        self.status >= 500
            || self.status == 429
            || matches!(
                xml_text(&self.body, "Code").as_deref(),
                Some("RequestTimeout" | "SlowDown" | "InternalError" | "ServiceUnavailable")
            )
    }
}

/// The text of the first `<tag>`, unescaped.
fn xml_text(body: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = body.find(&open)? + open.len();
    let end = start + body[start..].find(&close)?;
    Some(xml_unescape(&body[start..end]))
}

/// The text of every `<tag>`, in order - the keys of a listing.
fn xml_all(body: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(at) = rest.find(&open) {
        let after = &rest[at + open.len()..];
        let Some(end) = after.find(&close) else {
            break;
        };
        out.push(xml_unescape(&after[..end]));
        rest = &after[end + close.len()..];
    }
    out
}

fn xml_unescape(raw: &str) -> String {
    // Some stores - moto among them - send a message as CDATA, which is
    // the text as it is.
    if let Some(text) = raw
        .trim()
        .strip_prefix("<![CDATA[")
        .and_then(|rest| rest.strip_suffix("]]>"))
    {
        return text.to_string();
    }
    raw.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// A failed reply as a sentence: S3's own code and message, and where the
/// bucket is when AWS said so.
fn refusal(reply: &Reply) -> S3Error {
    let code = xml_text(&reply.body, "Code").filter(|c| !c.is_empty());
    let message: Option<String> = xml_text(&reply.body, "Message")
        .map(|m| m.chars().take(300).collect())
        .filter(|m: &String| !m.is_empty());
    let mut text = match (code, message) {
        (Some(code), Some(message)) => format!("S3 refused the request: {code} ({message})"),
        (Some(code), None) => format!("S3 refused the request: {code}"),
        _ => format!("S3 answered HTTP {}", reply.status),
    };
    if let Some(region) = reply.region.as_deref().filter(|r| valid_region(r)) {
        text.push_str(&format!(". The bucket is in region {region}"));
    }
    S3Error(text)
}

/// One request, signed now.
async fn send(
    target: &Target<'_>,
    method: &str,
    key: &str,
    query: &[(&str, &str)],
    body: Bytes,
    payload_hash: &str,
    timeout: Duration,
) -> Result<Reply, S3Error> {
    let located = locate(target, key);
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let headers = [
        ("host", located.authority.as_str()),
        ("x-amz-content-sha256", payload_hash),
        ("x-amz-date", amz_date.as_str()),
    ];
    let signer = sigv4::Signer {
        access_key: target.access_key,
        secret_key: target.secret_key,
        region: target.region,
        service: "s3",
    };
    let authorization = signer.authorization(
        &amz_date,
        &sigv4::Request {
            method,
            path: &located.path,
            query,
            headers: &headers,
            payload_hash,
        },
    );
    let query = query_string(query);
    let uri = if query.is_empty() {
        located.path.clone()
    } else {
        format!("{}?{query}", located.path)
    };
    let request = hyper::Request::builder()
        .method(method)
        .uri(uri)
        .header(hyper::header::HOST, &located.authority)
        .header("x-amz-content-sha256", payload_hash)
        .header("x-amz-date", &amz_date)
        .header(hyper::header::AUTHORIZATION, authorization)
        .header(hyper::header::CONTENT_LENGTH, body.len())
        .header(hyper::header::USER_AGENT, "SNPanel backup")
        .body(axum::body::Body::from(body))
        // Every part was validated to be printable ASCII; this is the
        // message for the day that stops being so, and it names no key.
        .map_err(|_| {
            S3Error("The destination's settings cannot be sent in a request".to_string())
        })?;

    let port = target.endpoint.port;
    let exchange = async {
        let tcp = match tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio::net::TcpStream::connect((located.host.as_str(), port)),
        )
        .await
        {
            Ok(Ok(tcp)) => tcp,
            Ok(Err(e)) => {
                return Err(S3Error(format!(
                    "Cannot reach {}:{port}: {e}",
                    located.host
                )))
            }
            Err(_) => {
                return Err(S3Error(format!(
                    "Cannot reach {}:{port}: timed out",
                    located.host
                )))
            }
        };
        if !target.endpoint.tls {
            return round_trip(tcp, request).await;
        }
        let roots = crate::cloudflare::system_roots()
            .ok_or_else(|| S3Error("No system CA bundle found".to_string()))?;
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let name = rustls::pki_types::ServerName::try_from(located.host.clone())
            .map_err(|_| S3Error(format!("{} is not a name TLS can check", located.host)))?;
        let tls = connector
            .connect(name, tcp)
            .await
            .map_err(|e| S3Error(format!("TLS with {} failed: {e}", located.host)))?;
        round_trip(tls, request).await
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(result) => result,
        Err(_) => Err(S3Error(format!("{} did not answer in time", located.host))),
    }
}

async fn round_trip<IO>(io: IO, request: hyper::Request<axum::body::Body>) -> Result<Reply, S3Error>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use http_body_util::BodyExt;

    let failed = |e: hyper::Error| S3Error(format!("The request failed: {e}"));
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io))
            .await
            .map_err(failed)?;
    // The connection task owns the socket while the body is read.
    let pump = tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender.send_request(request).await.map_err(failed)?;
    let status = response.status().as_u16();
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let etag = header("etag");
    let region = header("x-amz-bucket-region");
    let body = http_body_util::Limited::new(response.into_body(), MAX_RESPONSE)
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .unwrap_or_default();
    pump.abort();
    Ok(Reply {
        status,
        etag,
        region,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// A request, tried again - signed afresh - when S3 says to or the network
/// dropped it. A refusal is returned as the reply; the caller decides.
async fn send_retrying(
    target: &Target<'_>,
    method: &str,
    key: &str,
    query: &[(&str, &str)],
    body: Bytes,
    timeout: Duration,
) -> Result<Reply, S3Error> {
    let payload_hash = sigv4::sha256_hex(&body);
    let mut outcome = send(
        target,
        method,
        key,
        query,
        body.clone(),
        &payload_hash,
        timeout,
    )
    .await;
    for pause in BACKOFF {
        let again = match &outcome {
            Ok(reply) => reply.failed() && reply.retryable(),
            Err(_) => true,
        };
        if !again {
            break;
        }
        tokio::time::sleep(pause).await;
        outcome = send(
            target,
            method,
            key,
            query,
            body.clone(),
            &payload_hash,
            timeout,
        )
        .await;
    }
    outcome
}

/// Where an archive went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uploaded {
    pub key: String,
    /// `s3://bucket/key`, for the job and the schedule's message.
    pub location: String,
}

/// An archive into the bucket, under the prefix, by its own file name. An
/// object of that name is replaced, which is how the rotating schedule
/// names keep one copy per name.
pub async fn upload(archive: &str, target: &Target<'_>) -> Result<Uploaded, S3Error> {
    upload_in_parts(Path::new(archive), target, PART_SIZE).await
}

async fn upload_in_parts(
    archive: &Path,
    target: &Target<'_>,
    part_size: u64,
) -> Result<Uploaded, S3Error> {
    let name = archive
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| S3Error("The backup file has no name".to_string()))?;
    let key = object_key(target.prefix, &name);
    let size = tokio::fs::metadata(archive)
        .await
        .map_err(|e| S3Error(format!("Cannot read the backup file: {e}")))?
        .len();
    if size <= part_size {
        let body = tokio::fs::read(archive)
            .await
            .map_err(|e| S3Error(format!("Cannot read the backup file: {e}")))?;
        let reply =
            send_retrying(target, "PUT", &key, &[], Bytes::from(body), DATA_TIMEOUT).await?;
        if reply.failed() {
            return Err(refusal(&reply));
        }
    } else {
        multipart(archive, size, part_size, target, &key).await?;
    }
    Ok(Uploaded {
        location: format!("s3://{}/{key}", target.bucket),
        key,
    })
}

/// The part size for an archive: [`PART_SIZE`], or more when that would
/// take more parts than S3 allows - rounded up to a MiB.
fn part_size_for(size: u64, part_size: u64) -> u64 {
    const MIB: u64 = 1024 * 1024;
    if size <= part_size.saturating_mul(MAX_PARTS) {
        return part_size;
    }
    size.div_ceil(MAX_PARTS).div_ceil(MIB) * MIB
}

async fn multipart(
    archive: &Path,
    size: u64,
    part_size: u64,
    target: &Target<'_>,
    key: &str,
) -> Result<(), S3Error> {
    let reply = send_retrying(
        target,
        "POST",
        key,
        &[("uploads", "")],
        Bytes::new(),
        CONTROL_TIMEOUT,
    )
    .await?;
    if reply.failed() {
        return Err(refusal(&reply));
    }
    let upload_id = xml_text(&reply.body, "UploadId")
        .filter(|id| !id.is_empty())
        .ok_or_else(|| S3Error("S3 did not start the upload".to_string()))?;
    let outcome = send_parts(
        archive,
        part_size_for(size, part_size),
        target,
        key,
        &upload_id,
    )
    .await;
    if outcome.is_err() {
        // The parts of an upload nobody completes are stored - and billed -
        // until it is aborted. Best effort: the failure is the news.
        let empty = sigv4::sha256_hex(b"");
        let _ = send(
            target,
            "DELETE",
            key,
            &[("uploadId", upload_id.as_str())],
            Bytes::new(),
            &empty,
            CONTROL_TIMEOUT,
        )
        .await;
    }
    outcome
}

async fn send_parts(
    archive: &Path,
    part_size: u64,
    target: &Target<'_>,
    key: &str,
    upload_id: &str,
) -> Result<(), S3Error> {
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(archive)
        .await
        .map_err(|e| S3Error(format!("Cannot read the backup file: {e}")))?;
    let mut parts: Vec<(u32, String)> = Vec::new();
    for number in 1u32.. {
        let mut chunk = Vec::with_capacity(usize::try_from(part_size).unwrap_or(0));
        (&mut file)
            .take(part_size)
            .read_to_end(&mut chunk)
            .await
            .map_err(|e| S3Error(format!("Cannot read the backup file: {e}")))?;
        if chunk.is_empty() {
            break;
        }
        let part = number.to_string();
        let reply = send_retrying(
            target,
            "PUT",
            key,
            &[("partNumber", part.as_str()), ("uploadId", upload_id)],
            Bytes::from(chunk),
            DATA_TIMEOUT,
        )
        .await?;
        if reply.failed() {
            return Err(refusal(&reply));
        }
        let etag = reply
            .etag
            .filter(|etag| !etag.is_empty())
            .ok_or_else(|| S3Error(format!("S3 did not acknowledge part {number}")))?;
        parts.push((number, etag));
    }
    let mut body = String::from("<CompleteMultipartUpload>");
    for (number, etag) in &parts {
        body.push_str(&format!(
            "<Part><PartNumber>{number}</PartNumber><ETag>{}</ETag></Part>",
            xml_escape(etag)
        ));
    }
    body.push_str("</CompleteMultipartUpload>");
    let reply = send_retrying(
        target,
        "POST",
        key,
        &[("uploadId", upload_id)],
        Bytes::from(body),
        DATA_TIMEOUT,
    )
    .await?;
    if reply.failed() {
        return Err(refusal(&reply));
    }
    Ok(())
}

/// How many keys one listing gathers at most: the archives of one family,
/// where a store that kept answering "there is more" would otherwise keep
/// this asking.
const MAX_LISTED: usize = 50_000;

/// Every key that starts with `prefix` - ListObjectsV2, page after page.
pub async fn list_keys(target: &Target<'_>, prefix: &str) -> Result<Vec<String>, S3Error> {
    let mut keys = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let current = token.take();
        let mut query = vec![("list-type", "2"), ("prefix", prefix)];
        if let Some(next) = current.as_deref() {
            query.push(("continuation-token", next));
        }
        let reply = send_retrying(target, "GET", "", &query, Bytes::new(), CONTROL_TIMEOUT).await?;
        if reply.failed() {
            return Err(refusal(&reply));
        }
        keys.extend(xml_all(&reply.body, "Key"));
        let more = xml_text(&reply.body, "IsTruncated").as_deref() == Some("true");
        match xml_text(&reply.body, "NextContinuationToken").filter(|t| !t.is_empty()) {
            Some(next) if more && keys.len() < MAX_LISTED => token = Some(next),
            _ => break,
        }
    }
    Ok(keys)
}

/// One object removed. A key already gone is not an error: two schedules
/// can prune the same family.
pub async fn delete_key(target: &Target<'_>, key: &str) -> Result<(), S3Error> {
    let reply = send_retrying(target, "DELETE", key, &[], Bytes::new(), CONTROL_TIMEOUT).await?;
    if reply.failed() && reply.status != 404 {
        return Err(refusal(&reply));
    }
    Ok(())
}

/// Whether the destination takes a file: one small object written, and
/// removed again when the key may delete - `false` when it may not, which a
/// write-only backup key often may not.
pub async fn check(target: &Target<'_>) -> Result<bool, S3Error> {
    let key = object_key(target.prefix, CHECK_OBJECT);
    let body = Bytes::from_static(b"SNPanel can write backups here.\n");
    let hash = sigv4::sha256_hex(&body);
    let reply = send(target, "PUT", &key, &[], body, &hash, CONTROL_TIMEOUT).await?;
    if reply.failed() {
        return Err(refusal(&reply));
    }
    let empty = sigv4::sha256_hex(b"");
    let removed = send(
        target,
        "DELETE",
        &key,
        &[],
        Bytes::new(),
        &empty,
        CONTROL_TIMEOUT,
    )
    .await
    .is_ok_and(|reply| !reply.failed());
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn endpoint(raw: &str) -> Endpoint {
        parse_endpoint(raw).unwrap()
    }

    #[test]
    fn an_endpoint_is_a_scheme_a_host_and_a_port() {
        assert_eq!(
            endpoint("https://s3.eu-west-1.amazonaws.com"),
            Endpoint {
                tls: true,
                host: "s3.eu-west-1.amazonaws.com".into(),
                port: 443
            }
        );
        assert_eq!(
            endpoint("HTTP://MinIO.lan:9000/"),
            Endpoint {
                tls: false,
                host: "minio.lan".into(),
                port: 9000
            }
        );
        // No scheme is HTTPS: what a person pasting a host name means.
        assert_eq!(
            endpoint("abc.r2.cloudflarestorage.com").url(),
            "https://abc.r2.cloudflarestorage.com"
        );
        assert_eq!(
            endpoint("http://127.0.0.1:5000").url(),
            "http://127.0.0.1:5000"
        );
        assert_eq!(
            endpoint("https://s3.example.com:443").url(),
            "https://s3.example.com"
        );
        for bad in [
            "",
            "ftp://s3.example.com",
            "https://s3.example.com/bucket",
            "https://key:secret@s3.example.com",
            "https://s3.example.com?x=1",
            "https://[::1]:9000",
            "https://s3.example.com:0",
            "https://s3.example.com:99999",
            "https://-s3.example.com",
            "https://s3..example.com",
            "https://s3_example.com",
        ] {
            assert!(parse_endpoint(bad).is_err(), "{bad} was taken");
        }
    }

    #[test]
    fn bucket_names_follow_s3s_rules() {
        let (longest, too_long) = ("a".repeat(63), "a".repeat(64));
        for good in [
            "abc",
            "my-backups",
            "backups.example.com",
            "a1b2c3",
            longest.as_str(),
        ] {
            assert!(valid_bucket(good), "{good} was refused");
        }
        for bad in [
            "ab",
            "My-Backups",
            "under_score",
            "-dash",
            "dash-",
            "dot..dot",
            "192.168.1.1",
            too_long.as_str(),
            "space here",
        ] {
            assert!(!valid_bucket(bad), "{bad} was taken");
        }
    }

    #[test]
    fn a_prefix_is_a_folder_without_its_slashes() {
        assert_eq!(normalise_prefix("").as_deref(), Some(""));
        assert_eq!(
            normalise_prefix(" /panel/nightly/ ").as_deref(),
            Some("panel/nightly")
        );
        assert_eq!(normalise_prefix("snpanel").as_deref(), Some("snpanel"));
        let too_long = "a".repeat(201);
        for bad in ["a//b", "../etc", "a/./b", "a b", "a?b", too_long.as_str()] {
            assert_eq!(normalise_prefix(bad), None, "{bad} was taken");
        }
    }

    #[test]
    fn regions_and_keys_are_printable_and_short() {
        assert!(valid_region("us-east-1") && valid_region("auto") && valid_region("garage_1"));
        assert!(!valid_region("") && !valid_region("us east") && !valid_region(&"a".repeat(65)));
        assert!(valid_key("AKIAIOSFODNN7EXAMPLE", 128));
        assert!(valid_key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", 256));
        assert!(
            !valid_key("", 128) && !valid_key("with space", 128) && !valid_key("tab\there", 128)
        );
        assert!(!valid_key("é", 128) && !valid_key(&"a".repeat(129), 128));
    }

    #[test]
    fn addressing_by_host_needs_a_name_the_certificate_covers() {
        let aws = endpoint("https://s3.amazonaws.com");
        assert_eq!(addressing_problem(&aws, "backups", false), None);
        assert!(addressing_problem(&aws, "backups.example.com", false).is_some());
        assert_eq!(addressing_problem(&aws, "backups.example.com", true), None);
        let ip = endpoint("http://10.0.0.5:9000");
        assert!(addressing_problem(&ip, "backups", false).is_some());
        assert_eq!(addressing_problem(&ip, "backups", true), None);
        assert!(addressing_problem(&endpoint("http://localhost:9000"), "backups", false).is_some());
        // Plain HTTP has no certificate to disagree with the dots.
        assert_eq!(
            addressing_problem(&endpoint("http://minio.lan"), "a.b", false),
            None
        );
    }

    fn target<'a>(endpoint: &'a Endpoint, path_style: bool) -> Target<'a> {
        Target {
            endpoint,
            region: "us-east-1",
            bucket: "backups",
            prefix: "panel",
            access_key: "AKIDEXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            path_style,
        }
    }

    #[test]
    fn a_key_is_found_by_path_or_by_host() {
        let aws = endpoint("https://s3.amazonaws.com");
        assert_eq!(
            locate(&target(&aws, false), "panel/user-a b.tar.gz"),
            Located {
                host: "backups.s3.amazonaws.com".into(),
                authority: "backups.s3.amazonaws.com".into(),
                path: "/panel/user-a%20b.tar.gz".into(),
            }
        );
        let minio = endpoint("http://minio.lan:9000");
        assert_eq!(
            locate(&target(&minio, true), "panel/alice.tar.gz"),
            Located {
                host: "minio.lan".into(),
                authority: "minio.lan:9000".into(),
                path: "/backups/panel/alice.tar.gz".into(),
            }
        );
        assert_eq!(object_key("", "alice.tar.gz"), "alice.tar.gz");
        assert_eq!(object_key("a/b", "alice.tar.gz"), "a/b/alice.tar.gz");
    }

    #[test]
    fn a_bare_parameter_is_sent_bare() {
        assert_eq!(query_string(&[("uploads", "")]), "uploads");
        assert_eq!(
            query_string(&[("partNumber", "2"), ("uploadId", "a/b+c=")]),
            "partNumber=2&uploadId=a%2Fb%2Bc%3D"
        );
    }

    #[test]
    fn the_part_size_grows_only_past_ten_thousand_parts() {
        let mib = 1024 * 1024;
        assert_eq!(part_size_for(10 * mib, PART_SIZE), PART_SIZE);
        assert_eq!(part_size_for(PART_SIZE * MAX_PARTS, PART_SIZE), PART_SIZE);
        // One byte more than 10,000 parts of 16 MiB holds.
        assert_eq!(
            part_size_for(PART_SIZE * MAX_PARTS + 1, PART_SIZE),
            PART_SIZE + mib
        );
        let huge = 400 * 1024 * mib;
        assert!(huge.div_ceil(part_size_for(huge, PART_SIZE)) <= MAX_PARTS);
    }

    #[test]
    fn an_error_document_reads_as_a_sentence() {
        let reply = |status, body: &str, region: Option<&str>| Reply {
            status,
            etag: None,
            region: region.map(str::to_string),
            body: body.to_string(),
        };
        let denied = reply(
            403,
            "<?xml version=\"1.0\"?><Error><Code>AccessDenied</Code><Message>Access &amp; denied</Message>\
             <StringToSign>AWS4-HMAC-SHA256 secret-ish</StringToSign></Error>",
            None,
        );
        assert!(denied.failed() && !denied.retryable());
        let text = refusal(&denied).0;
        assert_eq!(
            text,
            "S3 refused the request: AccessDenied (Access & denied)"
        );
        assert!(!text.contains("StringToSign") && !text.contains("secret-ish"));

        let moved = reply(
            301,
            "<Error><Code>PermanentRedirect</Code><Message>Use the right one</Message></Error>",
            Some("eu-west-1"),
        );
        assert!(refusal(&moved)
            .0
            .ends_with("The bucket is in region eu-west-1"));

        let cdata = reply(
            403,
            "<Error><Code>SignatureDoesNotMatch</Code><Message><![CDATA[Check your key & method.]]></Message></Error>",
            None,
        );
        assert_eq!(
            refusal(&cdata).0,
            "S3 refused the request: SignatureDoesNotMatch (Check your key & method.)"
        );

        let proxy = reply(502, "<html>Bad gateway</html>", None);
        assert_eq!(refusal(&proxy).0, "S3 answered HTTP 502");
        assert!(proxy.retryable());

        let completed_badly = reply(
            200,
            "<Error><Code>InternalError</Code><Message>Try again</Message></Error>",
            None,
        );
        assert!(completed_badly.failed() && completed_badly.retryable());
        let slow = reply(503, "<Error><Code>SlowDown</Code></Error>", None);
        assert!(slow.retryable());
        assert!(!reply(200, "<InitiateMultipartUploadResult/>", None).failed());
    }

    // --- a fake store, for what the requests are and in what order ---------

    #[derive(Debug, Clone)]
    struct Seen {
        method: String,
        path: String,
        query: String,
        body: Vec<u8>,
        signature_ok: bool,
    }

    type Script =
        Arc<dyn Fn(&Seen, usize) -> (u16, Vec<(&'static str, String)>, String) + Send + Sync>;

    fn decode(text: &str) -> String {
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                out.push(u8::from_str_radix(&text[i + 1..i + 3], 16).unwrap());
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8(out).unwrap()
    }

    /// Recomputes the signature from the request as it arrived, which is
    /// what a real store does: a query or path sent differently from how it
    /// was signed fails here the way it would there.
    fn signature_matches(
        method: &str,
        uri: &axum::http::Uri,
        headers: &axum::http::HeaderMap,
        body: &[u8],
    ) -> bool {
        let get = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        };
        let authorization = get("authorization");
        let amz_date = get("x-amz-date");
        let payload_hash = get("x-amz-content-sha256");
        if payload_hash != sigv4::sha256_hex(body) {
            return false;
        }
        let query: Vec<(String, String)> = uri
            .query()
            .unwrap_or("")
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| match p.split_once('=') {
                Some((k, v)) => (decode(k), decode(v)),
                None => (decode(p), String::new()),
            })
            .collect();
        let query: Vec<(&str, &str)> = query
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let host = get("host");
        let signed = [
            ("host", host.as_str()),
            ("x-amz-content-sha256", payload_hash.as_str()),
            ("x-amz-date", amz_date.as_str()),
        ];
        let expected = sigv4::Signer {
            access_key: "AKIDEXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            service: "s3",
        }
        .authorization(
            &amz_date,
            &sigv4::Request {
                method,
                path: uri.path(),
                query: &query,
                headers: &signed,
                payload_hash: &payload_hash,
            },
        );
        authorization == expected
    }

    async fn fake_store(script: Script) -> (Endpoint, Arc<Mutex<Vec<Seen>>>) {
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let app =
            axum::Router::new().fallback(move |request: axum::http::Request<axum::body::Body>| {
                let log = log.clone();
                let script = script.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let body = axum::body::to_bytes(body, usize::MAX)
                        .await
                        .unwrap()
                        .to_vec();
                    let entry = Seen {
                        method: parts.method.to_string(),
                        path: parts.uri.path().to_string(),
                        query: parts.uri.query().unwrap_or("").to_string(),
                        signature_ok: signature_matches(
                            parts.method.as_str(),
                            &parts.uri,
                            &parts.headers,
                            &body,
                        ),
                        body,
                    };
                    let index = {
                        let mut log = log.lock().unwrap();
                        log.push(entry.clone());
                        log.len() - 1
                    };
                    let (status, headers, text) = script(&entry, index);
                    let mut response = axum::response::Response::new(axum::body::Body::from(text));
                    *response.status_mut() = axum::http::StatusCode::from_u16(status).unwrap();
                    for (name, value) in headers {
                        response.headers_mut().insert(name, value.parse().unwrap());
                    }
                    response
                }
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (endpoint(&format!("http://127.0.0.1:{port}")), seen)
    }

    fn archive(tag: &str, len: usize) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("snpanel-s3-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("user-alice-20260925020000.tar.gz");
        std::fs::write(
            &path,
            (0..len).map(|i| (i % 251) as u8).collect::<Vec<u8>>(),
        )
        .unwrap();
        path
    }

    fn ok() -> (u16, Vec<(&'static str, String)>, String) {
        (200, vec![("etag", "\"e\"".into())], String::new())
    }

    #[test]
    fn the_bucket_itself_is_its_name_without_a_slash() {
        let e = endpoint("http://127.0.0.1:9000");
        assert_eq!(locate(&target(&e, true), "").path, "/backups");
        assert_eq!(locate(&target(&e, false), "").path, "/");
    }

    #[tokio::test]
    async fn a_listing_follows_its_pages_and_signs_each() {
        let (endpoint, seen) = fake_store(Arc::new(|request: &Seen, _| {
            if request.query.contains("continuation-token=") {
                (
                    200,
                    vec![],
                    "<ListBucketResult><IsTruncated>false</IsTruncated>\
                    <Contents><Key>panel/user-alice-20260921020000.tar.gz</Key></Contents>\
                    </ListBucketResult>"
                        .to_string(),
                )
            } else {
                (
                    200,
                    vec![],
                    "<ListBucketResult><IsTruncated>true</IsTruncated>\
                    <Contents><Key>panel/user-alice-20260920020000.tar.gz</Key></Contents>\
                    <Contents><Key>panel/a&amp;b.tar.gz</Key></Contents>\
                    <NextContinuationToken>t/2=</NextContinuationToken></ListBucketResult>"
                        .to_string(),
                )
            }
        }))
        .await;
        let keys = list_keys(&target(&endpoint, true), "panel/user-alice-")
            .await
            .unwrap();
        assert_eq!(
            keys,
            [
                "panel/user-alice-20260920020000.tar.gz",
                "panel/a&b.tar.gz",
                "panel/user-alice-20260921020000.tar.gz"
            ]
        );
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert!(seen
            .iter()
            .all(|s| s.method == "GET" && s.path == "/backups" && s.signature_ok));
        assert_eq!(seen[0].query, "list-type=2&prefix=panel%2Fuser-alice-");
        assert_eq!(
            seen[1].query,
            "list-type=2&prefix=panel%2Fuser-alice-&continuation-token=t%2F2%3D"
        );
    }

    #[tokio::test]
    async fn a_delete_is_signed_and_a_key_already_gone_is_fine() {
        let (endpoint, seen) = fake_store(Arc::new(|request: &Seen, _| {
            if request.path.ends_with("gone.tar.gz") {
                (
                    404,
                    vec![],
                    "<Error><Code>NoSuchKey</Code></Error>".to_string(),
                )
            } else if request.path.ends_with("locked.tar.gz") {
                (
                    403,
                    vec![],
                    "<Error><Code>AccessDenied</Code></Error>".to_string(),
                )
            } else {
                (204, vec![], String::new())
            }
        }))
        .await;
        let t = target(&endpoint, true);
        delete_key(&t, "panel/old.tar.gz").await.unwrap();
        delete_key(&t, "panel/gone.tar.gz").await.unwrap();
        assert_eq!(
            delete_key(&t, "panel/locked.tar.gz").await.unwrap_err().0,
            "S3 refused the request: AccessDenied"
        );
        let seen = seen.lock().unwrap();
        assert_eq!(
            (seen[0].method.as_str(), seen[0].path.as_str()),
            ("DELETE", "/backups/panel/old.tar.gz")
        );
        assert!(seen.iter().all(|s| s.signature_ok));
    }

    #[tokio::test]
    async fn a_small_archive_is_one_signed_put() {
        let (endpoint, seen) = fake_store(Arc::new(|_, _| ok())).await;
        let path = archive("small", 10);
        let done = upload_in_parts(&path, &target(&endpoint, true), 16)
            .await
            .unwrap();
        assert_eq!(done.key, "panel/user-alice-20260925020000.tar.gz");
        assert_eq!(
            done.location,
            "s3://backups/panel/user-alice-20260925020000.tar.gz"
        );
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            (seen[0].method.as_str(), seen[0].path.as_str()),
            ("PUT", "/backups/panel/user-alice-20260925020000.tar.gz")
        );
        assert_eq!(seen[0].body, std::fs::read(&path).unwrap());
        assert!(seen[0].signature_ok);
    }

    #[tokio::test]
    async fn a_large_archive_goes_up_in_parts_and_is_put_together() {
        let script: Script = Arc::new(|request, _| {
            if request.method == "POST" && request.query == "uploads" {
                (200, vec![], "<InitiateMultipartUploadResult><UploadId>up/1+x</UploadId></InitiateMultipartUploadResult>".into())
            } else if request.method == "PUT" {
                let part = request
                    .query
                    .split('&')
                    .next()
                    .unwrap()
                    .trim_start_matches("partNumber=")
                    .to_string();
                (
                    200,
                    vec![("etag", format!("\"etag-{part}\""))],
                    String::new(),
                )
            } else {
                (
                    200,
                    vec![],
                    "<CompleteMultipartUploadResult><Key>k</Key></CompleteMultipartUploadResult>"
                        .into(),
                )
            }
        });
        let (endpoint, seen) = fake_store(script).await;
        let path = archive("large", 23);
        upload_in_parts(&path, &target(&endpoint, true), 10)
            .await
            .unwrap();
        let seen = seen.lock().unwrap();
        let calls: Vec<(String, String, usize)> = seen
            .iter()
            .map(|s| (s.method.clone(), s.query.clone(), s.body.len()))
            .collect();
        assert_eq!(
            calls[..4],
            [
                ("POST".to_string(), "uploads".to_string(), 0),
                (
                    "PUT".to_string(),
                    "partNumber=1&uploadId=up%2F1%2Bx".to_string(),
                    10
                ),
                (
                    "PUT".to_string(),
                    "partNumber=2&uploadId=up%2F1%2Bx".to_string(),
                    10
                ),
                (
                    "PUT".to_string(),
                    "partNumber=3&uploadId=up%2F1%2Bx".to_string(),
                    3
                ),
            ]
        );
        assert_eq!(
            (calls[4].0.as_str(), calls[4].1.as_str()),
            ("POST", "uploadId=up%2F1%2Bx")
        );
        assert_eq!(calls.len(), 5);
        let parts: Vec<u8> = seen[1..4].iter().flat_map(|s| s.body.clone()).collect();
        assert_eq!(
            parts,
            std::fs::read(&path).unwrap(),
            "the parts are not the file"
        );
        assert_eq!(
            String::from_utf8(seen[4].body.clone()).unwrap(),
            "<CompleteMultipartUpload>\
             <Part><PartNumber>1</PartNumber><ETag>\"etag-1\"</ETag></Part>\
             <Part><PartNumber>2</PartNumber><ETag>\"etag-2\"</ETag></Part>\
             <Part><PartNumber>3</PartNumber><ETag>\"etag-3\"</ETag></Part>\
             </CompleteMultipartUpload>"
        );
        assert!(
            seen.iter().all(|s| s.signature_ok),
            "a request was signed differently from how it was sent"
        );
    }

    #[tokio::test]
    async fn a_refused_part_aborts_the_upload() {
        let script: Script = Arc::new(|request, _| {
            if request.method == "POST" {
                (200, vec![], "<UploadId>u1</UploadId>".into())
            } else if request.query.starts_with("partNumber=2") {
                (
                    403,
                    vec![],
                    "<Error><Code>AccessDenied</Code><Message>No</Message></Error>".into(),
                )
            } else {
                ok()
            }
        });
        let (endpoint, seen) = fake_store(script).await;
        let path = archive("refused", 25);
        let error = upload_in_parts(&path, &target(&endpoint, true), 10)
            .await
            .unwrap_err();
        assert_eq!(error.0, "S3 refused the request: AccessDenied (No)");
        let seen = seen.lock().unwrap();
        let last = seen.last().unwrap();
        assert_eq!(
            (last.method.as_str(), last.query.as_str()),
            ("DELETE", "uploadId=u1")
        );
        // Nothing after the refusal but the abort: part 3 was not sent.
        assert_eq!(seen.len(), 4);
    }

    #[tokio::test]
    async fn an_error_inside_a_completed_upload_is_a_failure() {
        let script: Script = Arc::new(|request, _| {
            if request.method == "POST" && request.query == "uploads" {
                (200, vec![], "<UploadId>u2</UploadId>".into())
            } else if request.method == "POST" {
                (200, vec![], "<?xml version=\"1.0\"?>\n<Error><Code>InternalError</Code><Message>Sorry</Message></Error>".into())
            } else {
                ok()
            }
        });
        let (endpoint, seen) = fake_store(script).await;
        let path = archive("complete", 15);
        let error = upload_in_parts(&path, &target(&endpoint, true), 10)
            .await
            .unwrap_err();
        assert_eq!(error.0, "S3 refused the request: InternalError (Sorry)");
        let seen = seen.lock().unwrap();
        // Three tries at completing, as AWS says to, then the abort.
        let completes = seen
            .iter()
            .filter(|s| s.method == "POST" && s.query == "uploadId=u2")
            .count();
        assert_eq!(completes, 3);
        assert_eq!(seen.last().unwrap().method, "DELETE");
    }

    #[tokio::test]
    async fn a_busy_store_is_tried_again_and_a_refusal_is_not() {
        let script: Script = Arc::new(|_, index| {
            if index == 0 {
                (503, vec![], "<Error><Code>SlowDown</Code></Error>".into())
            } else {
                ok()
            }
        });
        let (endpoint, seen) = fake_store(script).await;
        let path = archive("busy", 5);
        upload_in_parts(&path, &target(&endpoint, true), 16)
            .await
            .unwrap();
        assert_eq!(seen.lock().unwrap().len(), 2);

        let script: Script = Arc::new(|_, _| {
            (
                403,
                vec![],
                "<Error><Code>InvalidAccessKeyId</Code></Error>".into(),
            )
        });
        let (endpoint, seen) = fake_store(script).await;
        let error = upload_in_parts(&path, &target(&endpoint, true), 16)
            .await
            .unwrap_err();
        assert_eq!(error.0, "S3 refused the request: InvalidAccessKeyId");
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_check_writes_and_removes_one_small_object() {
        let (endpoint, seen) = fake_store(Arc::new(|_, _| ok())).await;
        assert!(check(&target(&endpoint, true)).await.unwrap());
        {
            let seen = seen.lock().unwrap();
            let calls: Vec<(&str, &str)> = seen
                .iter()
                .map(|s| (s.method.as_str(), s.path.as_str()))
                .collect();
            assert_eq!(
                calls,
                [
                    ("PUT", "/backups/panel/.snpanel-write-test"),
                    ("DELETE", "/backups/panel/.snpanel-write-test"),
                ]
            );
            assert!(seen.iter().all(|s| s.signature_ok));
        }

        // A key that may write but not delete still passes, and says so.
        let script: Script = Arc::new(|request, _| {
            if request.method == "DELETE" {
                (
                    403,
                    vec![],
                    "<Error><Code>AccessDenied</Code></Error>".into(),
                )
            } else {
                ok()
            }
        });
        let (endpoint, _) = fake_store(script).await;
        assert!(!check(&target(&endpoint, true)).await.unwrap());
    }

    #[tokio::test]
    async fn nothing_listening_is_an_error_that_names_the_host() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let endpoint = endpoint(&format!("http://127.0.0.1:{port}"));
        let error = check(&target(&endpoint, true)).await.unwrap_err();
        assert!(
            error
                .0
                .starts_with(&format!("Cannot reach 127.0.0.1:{port}")),
            "{error}"
        );
        assert!(!error.0.contains("wJalr"));
    }
}
