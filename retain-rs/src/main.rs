#![allow(clippy::too_many_arguments)]

#[macro_use]
extern crate clap;

use clap::App;
use crate::config::Config;

mod commands;
mod server;
mod config;
mod stream;
#[macro_use]
mod macros;

pub fn main() {
    let yaml = load_yaml!("cli.yml");
    let mut app = App::from_yaml(yaml);
    let matches = app.get_matches_mut();

    let subcommand = match matches.subcommand() {
        Some(cmd) => cmd,
        None => {
            let _ = app.print_long_help();
            return;
        }
    };

    // Either start the full backup service, or handle a one-off command
    // Commands either edit the configuration or send a message to the main service
    match subcommand {
        ("start", _args) => {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()

                .build()
                .unwrap()
                .block_on(async {
                    server::serve().await;
                })
        }
        (cmd, args) => {
            commands::process_command(cmd, args);
        },
    }
}

pub fn format_bytes(count: u64) -> String {
    match count {
        n if n < 1000 => {
            format!("{n} bytes")
        }
        n if n < 10u64.pow(6) => {
            format!("{:.2}KB", (n as f64)/10f64.powf(3.))
        },
        n if n < 10u64.pow(9) => {
            format!("{:.2}MB", (n as f64)/10f64.powf(6.))
        },
        n if n < 10u64.pow(12) => {
            format!("{:.2}GB", (n as f64)/10f64.powf(9.))
        },
        n if n < 10u64.pow(15) => {
            format!("{:.2}TB", (n as f64)/10f64.powf(12.))
        },
        _ => {
            format!("{:.2}PB", (count as f64)/10f64.powf(15.))
        },
    }
}