//! `installer/files/snpanelctl`, the rescue menu.
//!
//! A different program from the installer and the updater, and it is reached
//! under different circumstances: an operator runs it over SSH when the
//! panel is not answering, which is exactly when nothing else can be relied
//! on. So its jobs are the ones that must work without the panel — change
//! the admin password, move the panel's URL, repair the firewall, read the
//! logs.

pub mod menu;
pub mod panel_url;
pub mod passwords;
pub mod status;
