//! The phases of a SNPanel installation.
//!
//! Source: `installer/install.sh`, whose `main()` is a linear sequence of
//! about twenty-five phases. That sequence is the seam: each phase can move
//! across on its own, the way the API's routers and the helper's verbs did,
//! and the bash keeps running the ones that have not.
//!
//! The rule for what lives here: a phase is split into the part that
//! **decides** what a file should contain and the part that **writes** it.
//! The deciding half is a pure function with a golden fixture taken from the
//! bash running on a real Debian 13; the writing half is a few lines of
//! `std::fs` with nothing to get wrong. An installer is a program that runs
//! once, as root, on a machine nobody is watching — the parts of it that can
//! be tested should be tested somewhere other than that machine.

pub mod backend_env;
pub mod bootstrap;
pub mod ioncube;
pub mod network;
pub mod nginx_conf;
pub mod node;
pub mod packages;
pub mod panel_ssl;
pub mod panel_url;
pub mod panel_user;
pub mod php;
pub mod phpmyadmin;
pub mod pma_control;
pub mod sources;
pub mod systemd_units;
pub mod tools_vhost;
pub mod waf_engine;
