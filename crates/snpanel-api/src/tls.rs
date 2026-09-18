//! Per-hostname certificates for the panel port - `core/panel_sni.py`.
//!
//! The panel answers on more than one name: its own `PANEL_DOMAIN`, and any
//! site whose certificate the helper has copied into `/etc/snpanel/sni/<name>/`.
//! Serving one fixed certificate would mean a browser warning on every name but
//! the first, which is exactly the problem this store was written to fix on the
//! Python side.
//!
//! Four behaviours are load-bearing, and each is a line in the Python:
//!
//! 1. **Names come from the certificate, not the directory.** A lineage named
//!    `example.com` usually covers `www.example.com` too, and reading the
//!    subject alternative names is what makes the alias reachable. The
//!    directory name is only a fallback for a certificate that cannot be
//!    parsed.
//! 2. **A wildcard covers exactly one more label.** `*.example.com` matches
//!    `panel.example.com`, but not `a.b.example.com` and not `example.com`
//!    itself. Matching by plain suffix would hand the wrong certificate to a
//!    deeper name.
//! 3. **The directory is re-read on a timer**, so a renewal is picked up
//!    without restarting the panel. Certbot renews at 03:00 and nobody is
//!    watching; a panel that needed a restart would simply start failing.
//! 4. **One bad certificate must not take the panel down.** A file that fails
//!    to parse is logged and skipped, and the previous copy is kept.
//!
//! The lookup itself runs inside the TLS handshake, so every failure path ends
//! at the default certificate rather than at a refused connection.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// Source: `DEFAULT_SNI_DIR`.
pub const DEFAULT_SNI_DIR: &str = "/etc/snpanel/sni";
const CERT_NAME: &str = "fullchain.pem";
const KEY_NAME: &str = "privkey.pem";
/// Source: `RELOAD_INTERVAL`.
const RELOAD_INTERVAL: Duration = Duration::from_secs(30);

/// Source: `normalize_hostname` - lower-case, no root dot, no port.
pub fn normalize_hostname(hostname: &str) -> String {
    let host = hostname.trim().to_lowercase();
    let host = host.trim_end_matches('.');
    if let Some(rest) = host.strip_prefix('[') {
        // `[::1]:2222`
        return match rest.find(']') {
            Some(end) => rest[..end].to_string(),
            None => host.to_string(),
        };
    }
    // One colon is `host:port`; more colons is a bare IPv6 address.
    if host.matches(':').count() == 1 {
        return host.split(':').next().unwrap_or(host).to_string();
    }
    host.to_string()
}

/// What the file looked like when it was read, so an unchanged certificate is
/// not re-parsed on every sweep.
type Stamp = ((u64, u64), (u64, u64));

fn stamp(cert: &Path, key: &Path) -> Stamp {
    let one = |p: &Path| {
        std::fs::metadata(p)
            .map(|m| {
                use std::os::unix::fs::MetadataExt;
                (m.mtime() as u64, m.size())
            })
            .unwrap_or((0, 0))
    };
    (one(cert), one(key))
}

struct Entry {
    stamp: Stamp,
    hostnames: Vec<String>,
    key: Arc<CertifiedKey>,
}

#[derive(Default)]
struct Index {
    entries: HashMap<String, Entry>,
    by_hostname: HashMap<String, Arc<CertifiedKey>>,
    /// `(".example.com", key)` for `*.example.com`.
    wildcards: Vec<(String, Arc<CertifiedKey>)>,
    checked_at: Option<Instant>,
}

pub struct SniStore {
    directory: PathBuf,
    /// `PANEL_SSL_CERT` - used for any name without one of its own.
    default: Option<Arc<CertifiedKey>>,
    index: Mutex<Index>,
}

impl SniStore {
    pub fn new(directory: impl Into<PathBuf>, default: Option<Arc<CertifiedKey>>) -> Self {
        let store = Self {
            directory: directory.into(),
            default,
            index: Mutex::new(Index::default()),
        };
        store.refresh(true);
        store
    }

    /// Every hostname the panel can be opened on with its own certificate.
    pub fn hostnames(&self) -> Vec<String> {
        self.refresh(false);
        let index = self.index.lock().expect("sni index");
        let mut names: Vec<String> = index.by_hostname.keys().cloned().collect();
        names.extend(index.wildcards.iter().map(|(s, _)| format!("*{s}")));
        names.sort();
        names.dedup();
        names
    }

    fn refresh(&self, force: bool) {
        let mut index = self.index.lock().expect("sni index");
        let now = Instant::now();
        if !force {
            if let Some(checked) = index.checked_at {
                if now.duration_since(checked) < RELOAD_INTERVAL {
                    return;
                }
            }
        }
        index.checked_at = Some(now);

        let Ok(children) = std::fs::read_dir(&self.directory) else {
            // No directory is not an error: an install with no extra
            // certificates serves the default one for everything.
            return;
        };

        let mut names: Vec<(String, PathBuf, PathBuf)> = Vec::new();
        for child in children.flatten() {
            let path = child.path();
            if !path.is_dir() {
                continue;
            }
            let cert = path.join(CERT_NAME);
            let key = path.join(KEY_NAME);
            if cert.is_file() && key.is_file() {
                let name = child.file_name().to_string_lossy().into_owned();
                names.push((name, cert, key));
            }
        }
        names.sort();

        let mut entries: HashMap<String, Entry> = HashMap::new();
        for (name, cert_path, key_path) in names {
            let current_stamp = stamp(&cert_path, &key_path);
            if let Some(existing) = index.entries.get(&name) {
                if existing.stamp == current_stamp {
                    entries.insert(
                        name,
                        Entry {
                            stamp: existing.stamp,
                            hostnames: existing.hostnames.clone(),
                            key: existing.key.clone(),
                        },
                    );
                    continue;
                }
            }
            match load_certified_key(&cert_path, &key_path) {
                Ok((key, hostnames)) => {
                    let hostnames = if hostnames.is_empty() {
                        vec![normalize_hostname(&name)]
                    } else {
                        hostnames
                    };
                    tracing::info!(name = %name, "panel certificate loaded");
                    entries.insert(
                        name,
                        Entry {
                            stamp: current_stamp,
                            hostnames,
                            key,
                        },
                    );
                }
                Err(e) => {
                    // One unreadable certificate must not take the panel down.
                    tracing::warn!(name = %name, "ignoring the certificate: {e}");
                    if let Some(existing) = index.entries.remove(&name) {
                        entries.insert(name, existing);
                    }
                }
            }
        }

        let mut by_hostname: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
        let mut wildcards: Vec<(String, Arc<CertifiedKey>)> = Vec::new();
        for entry in entries.values() {
            for hostname in &entry.hostnames {
                if let Some(suffix) = hostname.strip_prefix('*') {
                    wildcards.push((suffix.to_string(), entry.key.clone()));
                } else {
                    // `setdefault`: the first certificate claiming a name wins,
                    // and the directory is walked in sorted order, so which one
                    // that is does not change between restarts.
                    by_hostname
                        .entry(hostname.clone())
                        .or_insert_with(|| entry.key.clone());
                }
            }
        }

        index.entries = entries;
        index.by_hostname = by_hostname;
        index.wildcards = wildcards;
    }

    fn lookup(&self, hostname: &str) -> Option<Arc<CertifiedKey>> {
        let host = normalize_hostname(hostname);
        if host.is_empty() {
            return None;
        }
        self.refresh(false);
        let index = self.index.lock().expect("sni index");
        if let Some(key) = index.by_hostname.get(&host) {
            return Some(key.clone());
        }
        for (suffix, key) in &index.wildcards {
            // One label only: *.example.com matches panel.example.com but not
            // a.b.example.com, and not example.com itself.
            if let Some(label) = host.strip_suffix(suffix.as_str()) {
                if !label.is_empty() && !label.contains('.') {
                    return Some(key.clone());
                }
            }
        }
        None
    }
}

impl std::fmt::Debug for SniStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniStore")
            .field("directory", &self.directory)
            .finish()
    }
}

impl ResolvesServerCert for SniStore {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match hello.server_name() {
            Some(name) => self.lookup(name).or_else(|| self.default.clone()),
            // No SNI at all - an IP address in the URL bar, or an old client.
            None => self.default.clone(),
        }
    }
}

/// Read a PEM chain and key into something rustls can serve, and pull the
/// hostnames out of the leaf.
pub fn load_certified_key(
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<(Arc<CertifiedKey>, Vec<String>)> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_slice()).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("{} holds no certificate", cert_path.display());
    }

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_slice())?
        .ok_or_else(|| anyhow::anyhow!("{} holds no private key", key_path.display()))?;

    let hostnames = certificate_hostnames(&certs[0]);
    let signing_key = any_supported_type(&key)?;
    Ok((Arc::new(CertifiedKey::new(certs, signing_key)), hostnames))
}

/// Source: `certificate_hostnames` - every DNS name in the SAN extension.
fn certificate_hostnames(cert: &CertificateDer<'_>) -> Vec<String> {
    use x509_parser::prelude::*;

    let Ok((_, parsed)) = X509Certificate::from_der(cert.as_ref()) else {
        return Vec::new();
    };
    let Ok(Some(san)) = parsed.subject_alternative_name() else {
        return Vec::new();
    };
    san.value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => {
                let normalised = normalize_hostname(dns);
                (!normalised.is_empty()).then_some(normalised)
            }
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostnames_are_normalised_the_way_python_normalises_them() {
        assert_eq!(normalize_hostname("Example.COM"), "example.com");
        // The root dot is stripped: SNI may carry it, Host headers do not.
        assert_eq!(normalize_hostname("example.com."), "example.com");
        // A port comes off.
        assert_eq!(normalize_hostname("example.com:2222"), "example.com");
        // A bracketed IPv6 address loses its brackets and port.
        assert_eq!(normalize_hostname("[::1]:2222"), "::1");
        // A bare IPv6 address has more than one colon and is left whole.
        assert_eq!(normalize_hostname("2001:db8::1"), "2001:db8::1");
        assert_eq!(normalize_hostname("  "), "");
    }

    fn store_with(wildcards: Vec<(&str, u8)>, exact: Vec<(&str, u8)>) -> SniStore {
        // A store with fabricated index contents: building real certificates
        // in a unit test would test OpenSSL, not the matching rules, and the
        // matching rules are where the bugs are.
        let store = SniStore {
            directory: PathBuf::from("/nonexistent"),
            default: None,
            index: Mutex::new(Index::default()),
        };
        {
            let mut index = store.index.lock().unwrap();
            // Far in the future, so lookup() never tries to re-read the
            // directory and wipe what the test just put here.
            index.checked_at = Some(Instant::now());
            for (name, id) in exact {
                index.by_hostname.insert(name.to_string(), fake_key(id));
            }
            for (suffix, id) in wildcards {
                index.wildcards.push((suffix.to_string(), fake_key(id)));
            }
        }
        store
    }

    /// A `CertifiedKey` that is never actually used for a handshake - only
    /// identified, by the byte in its certificate.
    fn fake_key(id: u8) -> Arc<CertifiedKey> {
        #[derive(Debug)]
        struct NoSign;
        impl rustls::sign::SigningKey for NoSign {
            fn choose_scheme(
                &self,
                _offered: &[rustls::SignatureScheme],
            ) -> Option<Box<dyn rustls::sign::Signer>> {
                None
            }
            fn algorithm(&self) -> rustls::SignatureAlgorithm {
                rustls::SignatureAlgorithm::ED25519
            }
        }
        Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(vec![id])],
            Arc::new(NoSign),
        ))
    }

    fn id_of(key: &Arc<CertifiedKey>) -> u8 {
        key.cert[0].as_ref()[0]
    }

    #[test]
    fn an_exact_hostname_wins() {
        let store = store_with(vec![(".example.com", 2)], vec![("panel.example.com", 1)]);
        assert_eq!(id_of(&store.lookup("panel.example.com").unwrap()), 1);
    }

    #[test]
    fn a_wildcard_covers_exactly_one_more_label() {
        let store = store_with(vec![(".example.com", 2)], vec![]);
        // One label: matches.
        assert_eq!(id_of(&store.lookup("panel.example.com").unwrap()), 2);
        // Two labels: does not. A plain suffix check would wrongly match here
        // and serve a certificate the browser rejects.
        assert!(store.lookup("a.b.example.com").is_none());
        // The bare domain is not covered by *.example.com either.
        assert!(store.lookup("example.com").is_none());
    }

    #[test]
    fn a_port_and_a_trailing_dot_do_not_prevent_a_match() {
        let store = store_with(vec![], vec![("panel.example.com", 1)]);
        assert!(store.lookup("panel.example.com:2222").is_some());
        assert!(store.lookup("PANEL.example.com.").is_some());
    }

    #[test]
    fn an_unknown_hostname_has_no_certificate_of_its_own() {
        let store = store_with(vec![], vec![("panel.example.com", 1)]);
        assert!(store.lookup("elsewhere.example.org").is_none());
        assert!(store.lookup("").is_none());
    }

    #[test]
    fn a_missing_directory_is_not_an_error() {
        // An install with no extra certificates serves the default for
        // everything rather than failing to start.
        let store = SniStore::new("/nonexistent/sni/dir", None);
        assert!(store.hostnames().is_empty());
        assert!(store.lookup("anything.example.com").is_none());
    }
}
