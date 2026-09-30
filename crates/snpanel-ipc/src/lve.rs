//! CloudLinux LVE limits, as the panel sets them.
//!
//! The helper hands these to `lvectl` / `cloudlinux-limits`, so the ranges are
//! checked here, at the protocol boundary: a request with a limit outside them
//! cannot be built, and never reaches a command line.

use serde::{Deserialize, Serialize};

/// One LVE's limits. `0` means "unlimited" for the counters that support it
/// (entry processes, processes, IO, IOPS); CPU and memory always have a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LveLimits {
    /// CPU, in percent of one core (100 = one core).
    pub speed_percent: u32,
    /// Physical memory, in MB.
    pub pmem_mb: u32,
    /// Entry processes: concurrent requests into the LVE (0 = unlimited).
    pub ep: u32,
    /// Processes (0 = unlimited).
    pub nproc: u32,
    /// Disk IO, in KB/s (0 = unlimited).
    pub io_kbps: u32,
    /// IO operations per second (0 = unlimited).
    pub iops: u32,
}

/// The accepted range of each limit. Wide enough for any real server, narrow
/// enough that a typo (an extra zero, a unit in the wrong field) is refused.
pub const SPEED_PERCENT: (u32, u32) = (1, 12_800);
pub const PMEM_MB: (u32, u32) = (64, 1_048_576);
pub const EP: (u32, u32) = (0, 10_000);
pub const NPROC: (u32, u32) = (0, 100_000);
pub const IO_KBPS: (u32, u32) = (0, 10_485_760);
pub const IOPS: (u32, u32) = (0, 1_000_000);

impl LveLimits {
    /// Every field inside its range, or the first one that is not.
    pub fn validate(&self) -> Result<(), String> {
        let check = |name: &str, value: u32, (min, max): (u32, u32)| {
            if (min..=max).contains(&value) {
                Ok(())
            } else {
                Err(format!(
                    "{name} must be between {min} and {max}, got {value}"
                ))
            }
        };
        check("speed_percent", self.speed_percent, SPEED_PERCENT)?;
        check("pmem_mb", self.pmem_mb, PMEM_MB)?;
        check("ep", self.ep, EP)?;
        check("nproc", self.nproc, NPROC)?;
        check("io_kbps", self.io_kbps, IO_KBPS)?;
        check("iops", self.iops, IOPS)
    }

    /// The `--name=value` flags `lvectl set` and `cloudlinux-limits set`
    /// both accept, in that order.
    pub fn flags(&self) -> Vec<String> {
        vec![
            format!("--speed={}%", self.speed_percent),
            format!("--pmem={}M", self.pmem_mb),
            format!("--maxEntryProcs={}", self.ep),
            format!("--nproc={}", self.nproc),
            format!("--io={}", self.io_kbps),
            format!("--iops={}", self.iops),
        ]
    }
}

/// Which web server answers the public 80/443 on a Hosting Edition server
/// with LiteSpeed: LiteSpeed itself, or the Apache standby it fails over to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebServer {
    Lsws,
    Apache,
}

impl WebServer {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "lsws" => Ok(Self::Lsws),
            "apache" => Ok(Self::Apache),
            other => Err(format!("unknown web server {other:?} (lsws or apache)")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lsws => "lsws",
            Self::Apache => "apache",
        }
    }
}

/// A hosting package's name as CloudLinux knows it: the panel package's own
/// name, which is what the CPAPI `packages` and `users` scripts report and
/// what `lvectl package-set` keys its limits by.
///
/// The panel allows any printable name up to 100 characters. What is refused
/// here is what would change the meaning of an `lvectl` command line: an
/// empty name, a leading dash, control characters, surrounding whitespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LvePackageName(String);

impl LvePackageName {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let ok = !raw.is_empty()
            && raw.chars().count() <= 100
            && raw.trim() == raw
            && !raw.starts_with('-')
            && !raw.chars().any(char::is_control);
        if ok {
            Ok(Self(raw.to_string()))
        } else {
            Err(format!("invalid package name: {raw:?}"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LvePackageName {
    type Error = String;
    fn try_from(raw: String) -> Result<Self, String> {
        Self::parse(&raw)
    }
}

impl From<LvePackageName> for String {
    fn from(name: LvePackageName) -> String {
        name.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_names_are_the_panels_but_never_flags() {
        for ok in ["Starter", "Gói Pro & <x>", "Business Plus", "a"] {
            assert_eq!(LvePackageName::parse(ok).unwrap().as_str(), ok);
        }
        let long = "x".repeat(101);
        for bad in [
            "",
            "-rf",
            " Starter",
            "Starter ",
            "a\nb",
            "a\tb",
            long.as_str(),
        ] {
            assert!(LvePackageName::parse(bad).is_err(), "{bad:?}");
        }
        assert!(serde_json::from_str::<LvePackageName>(r#""--speed=1%""#).is_err());
    }

    fn defaults() -> LveLimits {
        // CloudLinux's own out-of-the-box default LVE.
        LveLimits {
            speed_percent: 100,
            pmem_mb: 1024,
            ep: 20,
            nproc: 100,
            io_kbps: 1024,
            iops: 1024,
        }
    }

    #[test]
    fn cloudlinux_defaults_are_valid_and_render_as_lvectl_flags() {
        let l = defaults();
        assert_eq!(l.validate(), Ok(()));
        assert_eq!(
            l.flags(),
            [
                "--speed=100%",
                "--pmem=1024M",
                "--maxEntryProcs=20",
                "--nproc=100",
                "--io=1024",
                "--iops=1024"
            ]
        );
    }

    #[test]
    fn out_of_range_limits_are_refused_by_name() {
        type Case = (fn(&mut LveLimits), &'static str);
        let cases: [Case; 4] = [
            (|l| l.speed_percent = 0, "speed_percent"),
            (|l| l.pmem_mb = 32, "pmem_mb"),
            (|l| l.ep = 10_001, "ep"),
            (|l| l.iops = 2_000_000, "iops"),
        ];
        for (break_it, field) in cases {
            let mut l = defaults();
            break_it(&mut l);
            let err = l.validate().unwrap_err();
            assert!(err.starts_with(field), "{err}");
        }
    }

    #[test]
    fn zero_is_unlimited_where_cloudlinux_allows_it() {
        let l = LveLimits {
            ep: 0,
            nproc: 0,
            io_kbps: 0,
            iops: 0,
            ..defaults()
        };
        assert_eq!(l.validate(), Ok(()));
    }

    #[test]
    fn unknown_fields_are_refused_on_the_wire() {
        let json = r#"{"speed_percent":100,"pmem_mb":1024,"ep":20,"nproc":100,"io_kbps":1024,"iops":1024,"vmem":1}"#;
        assert!(serde_json::from_str::<LveLimits>(json).is_err());
    }
}
