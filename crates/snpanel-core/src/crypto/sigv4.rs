//! AWS Signature Version 4, for the S3 backup destination.
//!
//! Only what an S3 client needs: a request's canonical form, the string to
//! sign, the signing key and the `Authorization` header. Checked against the
//! worked examples AWS publishes, byte for byte, because a signature that is
//! almost right is a 403 and nothing else.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Who signs, and for what.
pub struct Signer<'a> {
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub region: &'a str,
    pub service: &'a str,
}

/// The parts of a request the signature covers.
pub struct Request<'a> {
    pub method: &'a str,
    /// The path as the request sends it, already percent-encoded.
    pub path: &'a str,
    /// The query parameters, not yet encoded.
    pub query: &'a [(&'a str, &'a str)],
    /// Every header to sign - `host` and `x-amz-date` among them - with
    /// names in any case.
    pub headers: &'a [(&'a str, &'a str)],
    /// The hex SHA-256 of the body.
    pub payload_hash: &'a str,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// RFC 3986 percent-encoding, as SigV4 wants it: every byte but
/// `A-Za-z0-9-._~` as `%XX` in upper case, and `/` left alone in a path.
pub fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        let keep = byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (byte == b'/' && !encode_slash);
        if keep {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The query, each name and value encoded, sorted by name then value.
fn canonical_query(query: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// The headers, lower-cased and sorted, values trimmed with runs of spaces
/// folded to one; and the list of their names.
fn canonical_headers(headers: &[(&str, &str)]) -> (String, String) {
    let mut entries: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| {
            let folded = value.split_whitespace().collect::<Vec<_>>().join(" ");
            (name.to_ascii_lowercase(), folded)
        })
        .collect();
    entries.sort();
    let canonical = entries
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect::<String>();
    let signed = entries
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");
    (canonical, signed)
}

/// The canonical request, and the signed header names.
pub fn canonical_request(request: &Request) -> (String, String) {
    let (headers, signed) = canonical_headers(request.headers);
    let text = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        request.method,
        request.path,
        canonical_query(request.query),
        headers,
        signed,
        request.payload_hash
    );
    (text, signed)
}

/// The key a day's signatures are made with, for one region and service.
pub fn signing_key(secret_key: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac(format!("AWS4{secret_key}").as_bytes(), date);
    let k_region = hmac(&k_date, region);
    let k_service = hmac(&k_region, service);
    hmac(&k_service, "aws4_request")
}

impl Signer<'_> {
    /// The `Authorization` header for `request`, made at `amz_date`
    /// (`YYYYMMDDTHHMMSSZ`, the value of its `x-amz-date` header).
    pub fn authorization(&self, amz_date: &str, request: &Request) -> String {
        let date = &amz_date[..amz_date.len().min(8)];
        let scope = format!("{date}/{}/{}/aws4_request", self.region, self.service);
        let (canonical, signed) = canonical_request(request);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            sha256_hex(canonical.as_bytes())
        );
        let key = signing_key(self.secret_key, date, self.region, self.service);
        let signature = hex(&hmac(&key, &to_sign));
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
            self.access_key
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn signature_of(authorization: &str) -> &str {
        authorization.rsplit("Signature=").next().unwrap()
    }

    /// The IAM example from AWS's "Signature Version 4 signing process":
    /// the canonical request's hash, the derived key and the signature.
    #[test]
    fn the_aws_iam_example() {
        let request = Request {
            method: "GET",
            path: "/",
            query: &[("Action", "ListUsers"), ("Version", "2010-05-08")],
            headers: &[
                (
                    "Content-Type",
                    "application/x-www-form-urlencoded; charset=utf-8",
                ),
                ("Host", "iam.amazonaws.com"),
                ("X-Amz-Date", "20150830T123600Z"),
            ],
            payload_hash: EMPTY,
        };
        let (canonical, signed) = canonical_request(&request);
        assert_eq!(signed, "content-type;host;x-amz-date");
        assert_eq!(
            sha256_hex(canonical.as_bytes()),
            "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
        );
        assert_eq!(
            hex(&signing_key(
                "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                "20150830",
                "us-east-1",
                "iam"
            )),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
        let signer = Signer {
            access_key: "AKIDEXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            service: "iam",
        };
        let authorization = signer.authorization("20150830T123600Z", &request);
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, \
             Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    fn s3() -> Signer<'static> {
        Signer {
            access_key: "AKIAIOSFODNN7EXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            service: "s3",
        }
    }

    /// The S3 documentation's "GET Object" example, with a Range header.
    #[test]
    fn the_s3_get_object_example() {
        let request = Request {
            method: "GET",
            path: "/test.txt",
            query: &[],
            headers: &[
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("Range", "bytes=0-9"),
                ("x-amz-content-sha256", EMPTY),
                ("x-amz-date", "20130524T000000Z"),
            ],
            payload_hash: EMPTY,
        };
        let (canonical, _) = canonical_request(&request);
        assert_eq!(
            sha256_hex(canonical.as_bytes()),
            "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
        );
        assert_eq!(
            signature_of(&s3().authorization("20130524T000000Z", &request)),
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    /// "PUT Object": a body, a `$` in the key, and a storage class header.
    #[test]
    fn the_s3_put_object_example() {
        let body_hash = sha256_hex(b"Welcome to Amazon S3.");
        assert_eq!(
            body_hash,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        let path = format!("/{}", uri_encode("test$file.text", false));
        assert_eq!(path, "/test%24file.text");
        let request = Request {
            method: "PUT",
            path: &path,
            query: &[],
            headers: &[
                ("Date", "Fri, 24 May 2013 00:00:00 GMT"),
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-content-sha256", &body_hash),
                ("x-amz-date", "20130524T000000Z"),
                ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
            ],
            payload_hash: &body_hash,
        };
        assert_eq!(
            signature_of(&s3().authorization("20130524T000000Z", &request)),
            "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
    }

    /// "GET Bucket Lifecycle": a query parameter with no value.
    #[test]
    fn the_s3_lifecycle_example() {
        let request = Request {
            method: "GET",
            path: "/",
            query: &[("lifecycle", "")],
            headers: &[
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-content-sha256", EMPTY),
                ("x-amz-date", "20130524T000000Z"),
            ],
            payload_hash: EMPTY,
        };
        assert_eq!(
            signature_of(&s3().authorization("20130524T000000Z", &request)),
            "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
        );
    }

    /// "Get Bucket (List Objects)": two query parameters, sorted.
    #[test]
    fn the_s3_list_objects_example() {
        let request = Request {
            method: "GET",
            path: "/",
            query: &[("prefix", "J"), ("max-keys", "2")],
            headers: &[
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-content-sha256", EMPTY),
                ("x-amz-date", "20130524T000000Z"),
            ],
            payload_hash: EMPTY,
        };
        assert_eq!(
            signature_of(&s3().authorization("20130524T000000Z", &request)),
            "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
        );
    }

    #[test]
    fn encoding_keeps_only_the_unreserved_characters() {
        assert_eq!(uri_encode("a-b_c.d~e", true), "a-b_c.d~e");
        assert_eq!(uri_encode("a b/c+d=é", true), "a%20b%2Fc%2Bd%3D%C3%A9");
        assert_eq!(
            uri_encode("backups/alice 1.tar.gz", false),
            "backups/alice%201.tar.gz"
        );
    }
}
