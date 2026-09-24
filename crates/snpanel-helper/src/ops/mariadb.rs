//! `ops::mariadb` - sizing MariaDB to the machine.
//!
//! Source: `calculate_mariadb_tuning`, `write_mariadb_tuning`,
//! `ensure_mariadb_slow_log` and the `mariadb-retune` arm.
//!
//! Runs from `snpanel-autotune.service`, not from the panel. The shape worth
//! carrying over is the **order**: the configuration is written, then
//! `mariadbd --help --verbose` parses it, and only then is the service
//! restarted. The bash runs under `set -e`, so a file MariaDB cannot parse
//! aborts before the restart - which is the difference between a box with
//! ignored tuning and a box whose database does not come back.
//!
//! The tiers below are the bash's and are not derived from anything: they are
//! what the panel has shipped, so a box that upgrades must come out with the
//! same numbers it had.

use snpanel_ipc::{HelperErrorKind, HelperResponse};

use crate::exec;

/// Source: `MARIADB_TUNING_CONF`.
///
/// The bash hard-codes the Debian path and so does this. On the RHEL family
/// MariaDB reads `/etc/my.cnf.d`, so the file lands where nothing reads it and
/// the tuning has never applied there. Writing it to the right directory
/// would start applying tuning to EL boxes that have run without it, which is
/// a change in behaviour and not this port's to make.
pub const TUNING_CONF: &str = "/etc/mysql/mariadb.conf.d/90-snpanel-tuning.cnf";

const SLOW_LOG_DIR: &str = "/var/log/mysql";
const SLOW_LOG_FILE: &str = "/var/log/mysql/snpanel-slow.log";

/// What ends up in the `[mysqld]` block, in MiB where the name says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuning {
    pub buffer_pool_mb: u64,
    pub log_file_mb: u64,
    pub max_connections: u64,
    pub thread_cache: u64,
    pub table_open_cache: u64,
    pub tmp_mb: u64,
    pub packet_mb: u64,
    pub io_capacity: u64,
    pub open_files_limit: u64,
}

/// The administrator's overrides, as strings.
///
/// Source: `mariadb_tuning_value`, which returns whatever the environment or
/// the `.env` holds without interpreting it. They stay strings here because
/// the size ones carry a unit (`512M`, `2G`) that `megabytes` resolves and the
/// count ones do not.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub buffer_pool_size: Option<String>,
    pub max_connections: Option<String>,
    pub thread_cache_size: Option<String>,
    pub table_open_cache: Option<String>,
    pub tmp_table_size: Option<String>,
    pub max_allowed_packet: Option<String>,
    pub log_file_size: Option<String>,
    pub io_capacity: Option<String>,
    pub open_files_limit: Option<String>,
}

/// Source: `positive_int_or_default`.
///
/// Anything that is not a run of digits becomes the default, and the result is
/// then clamped. Note that it clamps rather than refuses: an administrator who
/// asks for 10000 connections gets 1000, not an error at restart time.
fn positive_int_or_default(value: Option<&str>, default: u64, min: u64, max: u64) -> u64 {
    let mut v = value
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default);
    // The floor and the ceiling are applied in sequence, not as a `clamp`,
    // because the bash applies them in sequence and they can cross: on a
    // machine under 214MB the buffer pool's 60% ceiling falls below its
    // 128MB floor, and the bash lets the ceiling win. `u64::clamp` panics on
    // `min > max`, so the obvious spelling turns a box the bash merely tunes
    // badly into a helper that aborts.
    if v < min {
        v = min;
    }
    if v > max {
        v = max;
    }
    v
}

/// Source: `mariadb_megabytes` - `^([0-9]+)([KkMmGg]?)$`.
///
/// Kilobytes round **up**: `1025K` is 2M, not 1M. The bash writes
/// `(number + 1023) / 1024` and the rounding is deliberate, because rounding a
/// buffer pool down to zero would be a configuration MariaDB refuses.
fn megabytes(value: Option<&str>, default: u64) -> u64 {
    let Some(v) = value.filter(|v| !v.is_empty()) else {
        return default;
    };
    let (digits, unit) = match v.as_bytes().last() {
        Some(b) if b.is_ascii_digit() => (v, b'M'),
        Some(b @ (b'K' | b'k' | b'M' | b'm' | b'G' | b'g')) => (&v[..v.len() - 1], *b),
        _ => return default,
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return default;
    }
    let Ok(n) = digits.parse::<u64>() else {
        return default;
    };
    match unit {
        b'K' | b'k' => n.div_ceil(1024),
        b'G' | b'g' => n.saturating_mul(1024),
        _ => n,
    }
}

/// The per-tier starting point, before any override.
///
/// Source: the `if (( total_mb <= … ))` ladder of `calculate_mariadb_tuning`.
struct Tier {
    buffer_percent: u64,
    max_connections: u64,
    thread_cache: u64,
    table_open_cache: u64,
    tmp_mb: u64,
    packet_mb: u64,
}

fn tier(total_mb: u64) -> Tier {
    if total_mb <= 1024 {
        Tier {
            buffer_percent: 22,
            max_connections: 35,
            thread_cache: 16,
            table_open_cache: 512,
            tmp_mb: 32,
            packet_mb: 64,
        }
    } else if total_mb <= 2048 {
        Tier {
            buffer_percent: 25,
            max_connections: 50,
            thread_cache: 24,
            table_open_cache: 512,
            tmp_mb: 48,
            packet_mb: 64,
        }
    } else if total_mb <= 4096 {
        Tier {
            buffer_percent: 28,
            max_connections: 80,
            thread_cache: 32,
            table_open_cache: 1024,
            tmp_mb: 64,
            packet_mb: 96,
        }
    } else if total_mb <= 8192 {
        Tier {
            buffer_percent: 32,
            max_connections: 120,
            thread_cache: 48,
            table_open_cache: 1024,
            tmp_mb: 96,
            packet_mb: 128,
        }
    } else {
        Tier {
            buffer_percent: 36,
            max_connections: 180,
            thread_cache: 64,
            table_open_cache: 2048,
            tmp_mb: 128,
            packet_mb: 128,
        }
    }
}

/// Source: `calculate_mariadb_tuning`.
pub fn calculate(total_mb: u64, cpu_count: u64, o: &Overrides) -> Tuning {
    let t = tier(total_mb);

    // `(( buffer_default >= 128 )) || buffer_default=128`, then
    // `(( buffer_default <= total_mb * 45 / 100 )) || buffer_default=…`.
    // Both are only a starting point: the clamp below re-applies a 128 floor,
    // so on the machines this ladder covers the two orders agree. The order
    // is the bash's because there is no reason for it not to be.
    let mut buffer_default = total_mb * t.buffer_percent / 100;
    if buffer_default < 128 {
        buffer_default = 128;
    }
    if buffer_default > total_mb * 45 / 100 {
        buffer_default = total_mb * 45 / 100;
    }
    let buffer_mb = megabytes(o.buffer_pool_size.as_deref(), buffer_default);
    let buffer_mb = positive_int_or_default(
        Some(&buffer_mb.to_string()),
        buffer_default,
        128,
        total_mb * 60 / 100,
    );

    let max_connections =
        positive_int_or_default(o.max_connections.as_deref(), t.max_connections, 20, 1000);
    let thread_cache =
        positive_int_or_default(o.thread_cache_size.as_deref(), t.thread_cache, 8, 256);
    let table_open_cache = positive_int_or_default(
        o.table_open_cache.as_deref(),
        t.table_open_cache,
        256,
        65535,
    );

    // The bash passes `64` as the default of this second call rather than the
    // tier value. It is unreachable - `megabytes` has already returned a
    // number - and it is kept so the two implementations read alike.
    let tmp_mb = megabytes(o.tmp_table_size.as_deref(), t.tmp_mb);
    let tmp_mb = positive_int_or_default(Some(&tmp_mb.to_string()), 64, 16, 512);
    let packet_mb = megabytes(o.max_allowed_packet.as_deref(), t.packet_mb);
    let packet_mb = positive_int_or_default(Some(&packet_mb.to_string()), 64, 16, 512);

    // Sized from the buffer pool *after* its overrides, so raising the pool
    // raises the redo log with it.
    let log_default = buffer_mb / 4;
    let log_file_mb = megabytes(o.log_file_size.as_deref(), log_default);
    let log_file_mb =
        positive_int_or_default(Some(&log_file_mb.to_string()), log_default, 64, 1024);

    let io_default = cpu_count * 200;
    let io_capacity = positive_int_or_default(o.io_capacity.as_deref(), io_default, 200, 4000);

    // Every open table costs two descriptors, every connection one, and 512
    // is the headroom for everything that is not a table or a client.
    let files_default = table_open_cache * 2 + max_connections + 512;
    let open_files_limit =
        positive_int_or_default(o.open_files_limit.as_deref(), files_default, 2048, 200_000);

    Tuning {
        buffer_pool_mb: buffer_mb,
        log_file_mb,
        max_connections,
        thread_cache,
        table_open_cache,
        tmp_mb,
        packet_mb,
        io_capacity,
        open_files_limit,
    }
}

/// Source: the here-document of `write_mariadb_tuning`, byte for byte.
pub fn tuning_file(t: &Tuning) -> String {
    format!(
        "# SNPanel auto-tunes MariaDB for small and medium VPS plans.\n\
         # Optional overrides in /opt/snpanel/backend/.env: SNPANEL_MARIADB_BUFFER_POOL_SIZE,\n\
         # SNPANEL_MARIADB_MAX_CONNECTIONS, SNPANEL_MARIADB_THREAD_CACHE_SIZE,\n\
         # SNPANEL_MARIADB_TABLE_OPEN_CACHE, SNPANEL_MARIADB_TMP_TABLE_SIZE,\n\
         # SNPANEL_MARIADB_MAX_ALLOWED_PACKET, SNPANEL_MARIADB_LOG_FILE_SIZE,\n\
         # SNPANEL_MARIADB_IO_CAPACITY, SNPANEL_MARIADB_OPEN_FILES_LIMIT.\n\
         [mysqld]\n\
         innodb_buffer_pool_size = {buffer}M\n\
         innodb_log_file_size = {log}M\n\
         innodb_flush_log_at_trx_commit = 2\n\
         innodb_flush_method = O_DIRECT\n\
         innodb_io_capacity = {io}\n\
         max_connections = {conns}\n\
         thread_cache_size = {threads}\n\
         table_open_cache = {toc}\n\
         tmp_table_size = {tmp}M\n\
         max_heap_table_size = {tmp}M\n\
         max_allowed_packet = {packet}M\n\
         skip_name_resolve = 1\n\
         slow_query_log = 1\n\
         slow_query_log_file = {slow}\n\
         long_query_time = 2\n\
         \n\
         [server]\n\
         open_files_limit = {files}\n",
        buffer = t.buffer_pool_mb,
        log = t.log_file_mb,
        io = t.io_capacity,
        conns = t.max_connections,
        threads = t.thread_cache,
        toc = t.table_open_cache,
        tmp = t.tmp_mb,
        packet = t.packet_mb,
        slow = SLOW_LOG_FILE,
        files = t.open_files_limit,
    )
}

/// The overrides, from the environment and then the panel's `.env`.
///
/// Source: `mariadb_tuning_value`. The environment wins, which is how an
/// operator tries a value without editing a file the updater rewrites.
pub fn overrides() -> Overrides {
    let dotenv = std::fs::read_to_string(super::panel::ENV_FILE)
        .map(|text| snpanel_core::config::parse_dotenv(&text))
        .unwrap_or_default();
    let get = |key: &str| -> Option<String> {
        std::env::var(key)
            .ok()
            .or_else(|| dotenv.get(key).cloned())
            .filter(|v| !v.is_empty())
    };
    Overrides {
        buffer_pool_size: get("SNPANEL_MARIADB_BUFFER_POOL_SIZE"),
        max_connections: get("SNPANEL_MARIADB_MAX_CONNECTIONS"),
        thread_cache_size: get("SNPANEL_MARIADB_THREAD_CACHE_SIZE"),
        table_open_cache: get("SNPANEL_MARIADB_TABLE_OPEN_CACHE"),
        tmp_table_size: get("SNPANEL_MARIADB_TMP_TABLE_SIZE"),
        max_allowed_packet: get("SNPANEL_MARIADB_MAX_ALLOWED_PACKET"),
        log_file_size: get("SNPANEL_MARIADB_LOG_FILE_SIZE"),
        io_capacity: get("SNPANEL_MARIADB_IO_CAPACITY"),
        open_files_limit: get("SNPANEL_MARIADB_OPEN_FILES_LIMIT"),
    }
}

/// Source: `ensure_mariadb_slow_log`.
///
/// The group is `adm` where that group exists and `mysql` otherwise, and the
/// directory is 0750: the slow query log carries the text of every slow
/// statement, which on this box includes queries with data in them.
fn ensure_slow_log() {
    let group = if exec::run(&["getent", "group", "adm"]).is_ok_and(|o| o.ok()) {
        "adm"
    } else {
        "mysql"
    };
    let owner = format!("mysql:{group}");
    let _ = exec::run(&[
        "install",
        "-d",
        "-o",
        "mysql",
        "-g",
        group,
        "-m",
        "0750",
        SLOW_LOG_DIR,
    ]);
    // `touch` - an existing log keeps its contents.
    if !std::path::Path::new(SLOW_LOG_FILE).exists() {
        let _ = std::fs::write(SLOW_LOG_FILE, b"");
    }
    let _ = exec::run(&["chown", &owner, SLOW_LOG_FILE]);
    let _ = exec::run(&["chmod", "0640", SLOW_LOG_FILE]);
}

/// `mariadb-retune`.
pub fn retune() -> HelperResponse {
    let tuning = calculate(
        super::php::total_memory_mb(),
        super::php::cpu_count(),
        &overrides(),
    );

    let dir = match std::path::Path::new(TUNING_CONF).parent() {
        Some(dir) => dir,
        None => {
            return HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("{TUNING_CONF} has no parent directory"),
            )
        }
    };
    let _ = exec::run(&[
        "install",
        "-d",
        "-o",
        "root",
        "-g",
        "root",
        "-m",
        "0755",
        &dir.to_string_lossy(),
    ]);
    if let Err(e) = std::fs::write(TUNING_CONF, tuning_file(&tuning)) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {TUNING_CONF}: {e}"),
        );
    }
    ensure_slow_log();

    // `mariadbd --help --verbose >/dev/null` under `set -e`. MariaDB parses
    // every configuration file to answer it, so a file it will not accept
    // fails here - before the restart, while the old settings are still what
    // the running server has.
    let parsed = exec::run(&["mariadbd", "--help", "--verbose"]);
    if !matches!(&parsed, Ok(o) if o.ok()) {
        return exec::respond("mariadbd --help --verbose", parsed);
    }

    let restart = exec::run(&["systemctl", "restart", "mariadb"]);
    if !matches!(&restart, Ok(o) if o.ok()) {
        return exec::respond("systemctl restart mariadb", restart);
    }

    HelperResponse::with_stdout(format!(
        "Retuned MariaDB: innodb_buffer_pool_size={}M, max_connections={}, table_open_cache={}.\n",
        tuning.buffer_pool_mb, tuning.max_connections, tuning.table_open_cache
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the bash's own `calculate_mariadb_tuning` produces.
    ///
    /// Generated by running the four functions this port replaces -
    /// `positive_int_or_default`, `mariadb_tuning_value`,
    /// `mariadb_megabytes` and `calculate_mariadb_tuning`, lifted out of
    /// `snpanel-helper.sh` unedited - over every tier boundary, four machine
    /// widths and every override one at a time.
    ///
    /// Columns: override, total_mb, cpus, then the nine values in the order
    /// the bash assigns them.
    const GOLDEN: &str = include_str!("mariadb-tuning.tsv");

    fn overrides_from(spec: &str) -> Overrides {
        let mut o = Overrides::default();
        if spec.is_empty() {
            return o;
        }
        let (key, value) = spec.split_once('=').expect("KEY=VALUE");
        let value = Some(value.to_string());
        match key {
            "SNPANEL_MARIADB_BUFFER_POOL_SIZE" => o.buffer_pool_size = value,
            "SNPANEL_MARIADB_MAX_CONNECTIONS" => o.max_connections = value,
            "SNPANEL_MARIADB_THREAD_CACHE_SIZE" => o.thread_cache_size = value,
            "SNPANEL_MARIADB_TABLE_OPEN_CACHE" => o.table_open_cache = value,
            "SNPANEL_MARIADB_TMP_TABLE_SIZE" => o.tmp_table_size = value,
            "SNPANEL_MARIADB_MAX_ALLOWED_PACKET" => o.max_allowed_packet = value,
            "SNPANEL_MARIADB_LOG_FILE_SIZE" => o.log_file_size = value,
            "SNPANEL_MARIADB_IO_CAPACITY" => o.io_capacity = value,
            "SNPANEL_MARIADB_OPEN_FILES_LIMIT" => o.open_files_limit = value,
            other => panic!("unknown override in the fixture: {other}"),
        }
        o
    }

    #[test]
    fn the_tuning_matches_the_bash_it_replaces() {
        let mut rows = 0;
        for line in GOLDEN.lines().filter(|l| !l.trim().is_empty()) {
            let f: Vec<&str> = line.split('\t').collect();
            assert_eq!(f.len(), 12, "malformed fixture row: {line:?}");
            let total: u64 = f[1].parse().unwrap();
            let cpus: u64 = f[2].parse().unwrap();
            let got = calculate(total, cpus, &overrides_from(f[0]));
            let want = [
                f[3].to_string(),
                f[4].to_string(),
                f[5].to_string(),
                f[6].to_string(),
                f[7].to_string(),
                f[8].to_string(),
                f[9].to_string(),
                f[10].to_string(),
                f[11].to_string(),
            ];
            let mine = [
                format!("{}M", got.buffer_pool_mb),
                format!("{}M", got.log_file_mb),
                got.max_connections.to_string(),
                got.thread_cache.to_string(),
                got.table_open_cache.to_string(),
                format!("{}M", got.tmp_mb),
                format!("{}M", got.packet_mb),
                got.io_capacity.to_string(),
                got.open_files_limit.to_string(),
            ];
            assert_eq!(mine, want, "row: {line:?}");
            rows += 1;
        }
        // A fixture that stopped loading would make this pass by checking
        // nothing, which is the failure mode a golden test has.
        assert_eq!(rows, 90, "the fixture lost rows");
    }

    #[test]
    fn a_machine_too_small_for_the_floor_gets_the_ceiling() {
        // Under 214MB the buffer pool's 60% ceiling is below its 128MB floor.
        // The bash applies them in sequence and ships the ceiling - 76M on a
        // 128MB box. Spelling this as `u64::clamp(128, 76)` panics, which
        // would abort `mariadb-retune` on a machine the bash tunes fine.
        assert_eq!(calculate(128, 1, &Overrides::default()).buffer_pool_mb, 76);
        assert_eq!(calculate(64, 1, &Overrides::default()).buffer_pool_mb, 38);
        // And the floor still applies once there is room for it.
        assert_eq!(calculate(214, 1, &Overrides::default()).buffer_pool_mb, 128);
        assert_eq!(calculate(213, 1, &Overrides::default()).buffer_pool_mb, 127);
    }

    #[test]
    fn kilobytes_round_up() {
        // `(number + 1023) / 1024`. Rounding down would turn 1025K into 1M,
        // and a buffer pool of 0 is a configuration MariaDB refuses to start
        // with - which is the difference between a tuned box and a dead one.
        assert_eq!(megabytes(Some("1025K"), 9), 2);
        assert_eq!(megabytes(Some("1K"), 9), 1);
        assert_eq!(megabytes(Some("2048K"), 9), 2);
    }

    #[test]
    fn a_size_without_a_unit_is_megabytes() {
        assert_eq!(megabytes(Some("700"), 9), 700);
        assert_eq!(megabytes(Some("700M"), 9), 700);
        assert_eq!(megabytes(Some("2G"), 9), 2048);
    }

    #[test]
    fn anything_unparseable_becomes_the_default() {
        for bad in ["", "nonsense", "12T", "M", "-5", "1 2", "0x10"] {
            assert_eq!(megabytes(Some(bad), 77), 77, "should have rejected {bad:?}");
        }
        assert_eq!(megabytes(None, 77), 77);
    }

    #[test]
    fn an_out_of_range_override_is_clamped_not_refused() {
        // `positive_int_or_default` clamps. An administrator who asks for
        // 99999 connections gets 1000 and a working database, which is what
        // the bash does and is the safer of the two.
        assert_eq!(positive_int_or_default(Some("99999"), 80, 20, 1000), 1000);
        assert_eq!(positive_int_or_default(Some("5"), 80, 20, 1000), 20);
        assert_eq!(positive_int_or_default(Some("abc"), 80, 20, 1000), 80);
        assert_eq!(positive_int_or_default(None, 80, 20, 1000), 80);
    }

    #[test]
    fn the_file_names_the_slow_log_the_helper_creates() {
        // The path in the configuration and the path whose ownership is set
        // have to be the same one, or MariaDB starts and cannot write it.
        let t = calculate(4096, 4, &Overrides::default());
        assert!(tuning_file(&t).contains(&format!("slow_query_log_file = {SLOW_LOG_FILE}")));
    }

    #[test]
    fn the_file_carries_both_sections() {
        let t = calculate(4096, 4, &Overrides::default());
        let text = tuning_file(&t);
        assert!(text.contains("[mysqld]\n"));
        assert!(text.contains("\n[server]\n"));
        // `max_heap_table_size` has to track `tmp_table_size`: MariaDB takes
        // the smaller of the two, so raising one alone does nothing.
        assert!(text.contains(&format!("tmp_table_size = {}M", t.tmp_mb)));
        assert!(text.contains(&format!("max_heap_table_size = {}M", t.tmp_mb)));
    }

    #[test]
    fn every_documented_override_is_one_the_code_reads() {
        // The header lists the names an administrator is told to set. A name
        // in the comment that nothing reads is worse than no comment.
        let text = tuning_file(&calculate(4096, 4, &Overrides::default()));
        let documented: Vec<&str> = text
            .lines()
            .take_while(|l| l.starts_with('#'))
            .flat_map(|l| l.split_whitespace())
            .filter(|w| w.starts_with("SNPANEL_MARIADB_"))
            .map(|w| w.trim_end_matches([',', '.']))
            .collect();
        assert_eq!(documented.len(), 9, "{documented:?}");
        for name in documented {
            let mut o = Overrides::default();
            let spec = format!("{name}=1");
            let (key, _) = spec.split_once('=').unwrap();
            // Setting it must change *something*, which is the only
            // definition of "the code reads it" that cannot go stale.
            let before = calculate(4096, 4, &o);
            match key {
                "SNPANEL_MARIADB_BUFFER_POOL_SIZE" => o.buffer_pool_size = Some("512".into()),
                "SNPANEL_MARIADB_MAX_CONNECTIONS" => o.max_connections = Some("777".into()),
                "SNPANEL_MARIADB_THREAD_CACHE_SIZE" => o.thread_cache_size = Some("99".into()),
                "SNPANEL_MARIADB_TABLE_OPEN_CACHE" => o.table_open_cache = Some("777".into()),
                "SNPANEL_MARIADB_TMP_TABLE_SIZE" => o.tmp_table_size = Some("100".into()),
                "SNPANEL_MARIADB_MAX_ALLOWED_PACKET" => o.max_allowed_packet = Some("100".into()),
                "SNPANEL_MARIADB_LOG_FILE_SIZE" => o.log_file_size = Some("99".into()),
                "SNPANEL_MARIADB_IO_CAPACITY" => o.io_capacity = Some("1234".into()),
                "SNPANEL_MARIADB_OPEN_FILES_LIMIT" => o.open_files_limit = Some("12345".into()),
                other => panic!("documented but not handled: {other}"),
            }
            assert_ne!(before, calculate(4096, 4, &o), "{key} changed nothing");
        }
    }
}
