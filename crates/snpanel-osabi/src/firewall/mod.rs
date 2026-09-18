//! Firewall backends.
//!
//! Plan §6.3. `rules.tsv` is the source of truth (C13) and every apply
//! rebuilds the whole ruleset from it, which is precisely what makes swapping
//! the backend safe: there is no state hiding in the running firewall.

pub mod nft;
pub mod rules;

pub use rules::{Action, FirewallRuleset, FirewallState, Protocol, Rule};

/// What a backend has to be able to do.
pub trait FirewallBackend: Send + Sync {
    /// Render the ruleset to whatever this backend loads. Returned as a string
    /// so it can be inspected, diffed and tested without touching the kernel.
    fn render(&self, ruleset: &FirewallRuleset) -> String;

    /// The argv that loads the rendered text. Never a shell string.
    fn load_argv(&self, path: &str) -> Vec<String>;

    /// Is the tooling present on this box?
    fn is_available(&self) -> bool;

    fn name(&self) -> &'static str;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NftablesBackend;

impl FirewallBackend for NftablesBackend {
    fn render(&self, ruleset: &FirewallRuleset) -> String {
        nft::render(ruleset)
    }

    fn load_argv(&self, path: &str) -> Vec<String> {
        // `nft -f` is atomic: the whole file loads or none of it does.
        vec!["nft".into(), "-f".into(), path.into()]
    }

    fn is_available(&self) -> bool {
        which("nft").is_some()
    }

    fn name(&self) -> &'static str {
        "nftables"
    }
}

/// Detect whether a box still carries the legacy iptables/ipset state, so the
/// migration path in plan §6.3 knows there is something to clean up.
///
/// Note this only *detects*. The migration reads `rules.tsv`, never
/// `iptables-save`, so a half-broken legacy chain cannot corrupt the result.
pub fn legacy_iptables_present() -> bool {
    which("ipset").is_some() && which("iptables").is_some()
}

fn which(binary: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(binary))
        .find(|p| p.is_file())
        // nft and ipset live in sbin, which is not always on a non-root PATH.
        .or_else(|| {
            ["/usr/sbin", "/sbin", "/usr/local/sbin"]
                .iter()
                .map(|dir| std::path::Path::new(dir).join(binary))
                .find(|p| p.is_file())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_loads_atomically_from_a_file() {
        let argv = NftablesBackend.load_argv("/run/snpanel/ruleset.nft");
        assert_eq!(argv, vec!["nft", "-f", "/run/snpanel/ruleset.nft"]);
        assert_eq!(NftablesBackend.name(), "nftables");
    }

    #[test]
    fn the_backend_renders_through_the_trait() {
        let rs = FirewallRuleset::default();
        let out = FirewallBackend::render(&NftablesBackend, &rs);
        assert!(out.contains("table inet snpanel"));
    }
}
