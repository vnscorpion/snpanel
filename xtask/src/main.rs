//! `cargo xtask` - build and test automation.
//!
//! Plan §4.1. Kept as a normal binary in the workspace rather than a shell
//! script so it works identically on all four target distributions, which is
//! the same reason the rest of the migration exists.

use std::process::ExitCode;

mod golden;
mod shadow;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let task = args.first().map(String::as_str).unwrap_or("help");

    let result = match task {
        "golden-nginx" => golden::check(&args[1..]),
        "shadow-diff" => shadow::run(&args[1..]),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => {
            eprintln!("xtask: unknown task {other:?}\n");
            print_help();
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn print_help() {
    println!("cargo xtask <task>\n");
    println!("Tasks:");
    println!("  golden-nginx [--verbose]  Render the nginx templates with minijinja and");
    println!("                            compare against the Jinja2 output committed in");
    println!("                            tests/golden/nginx (contract C19).");
    println!();
    println!("  shadow-diff --token T [--rust URL] [--python URL]");
    println!("                            Send the same requests to both implementations");
    println!("                            and report every difference (plan §9.3). Any");
    println!("                            difference is a bug in the Rust side (NT7).");
}
