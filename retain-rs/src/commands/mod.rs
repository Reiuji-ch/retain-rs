use std::fmt::{Display, Formatter};
use std::str::FromStr;
use clap::ArgMatches;
use crate::Config;

pub mod auth;
pub mod ipc;
mod rules;

/// Enum of possible commands
///
/// These are IPC messages sent from the client (CLI) to the server (background process)
/// The client constructs the message from user input and the server reacts to it
#[derive(Debug)]
pub enum Command {
    /// Authenticate using the given formatted and base64-encoded key
    Authenticate,
    /// Add a path to RuleManager's includes
    Include,
    /// Add a glob-pattern filter to RuleManager's filters
    Filter,
    /// Remove a path from RuleManager's includes
    Ignore,
    /// Remove a rule from RuleManager's rules
    Unfilter,
    /// Sets the bandwidth limit
    Limit
}

/// A response to a `Command`
///
/// The server-side generates these and the client-side consumes them
#[derive(Debug)]
pub enum Response {
    Ok,
    Err,
}

impl Display for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Command::Authenticate => "Authenticate",
            Command::Include => "Include",
            Command::Filter => "Filter",
            Command::Ignore => "Ignore",
            Command::Unfilter => "Unfilter",
            Command::Limit => "Limit",
        })
    }
}

impl FromStr for Command {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "Authenticate" => Command::Authenticate,
            "Include" => Command::Include,
            "Filter" => Command::Filter,
            "Ignore" => Command::Ignore,
            "Unfilter" => Command::Unfilter,
            "Limit" => Command::Limit,
            _ => return Err(format!("Unknown command {s}")),
        })
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Response::Ok => "Ok",
            Response::Err => "Err",
        })
    }
}

impl FromStr for Response {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, <Response as FromStr>::Err> {
        Ok(match s {
            "Ok" => Response::Ok,
            "Err" => Response::Err,
            _ => return Err(format!("Unknown response {s}")),
        })
    }
}

pub fn process_command(cmd: &str, args: &ArgMatches) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let config = Config::load().expect("Failed to load config");

            // Commands that do not require IPC
            match (cmd, args, config.clone()) {
                ("explain", args, config) => {
                    rules::explain(args, config).await;
                    return;
                }
                ("cost", args, config) => {
                    rules::cost(args, config).await;
                    return;
                }
                ("stats", _, config) => {
                    rules::stats(config).await;
                    return;
                }
                ("includes", _, _) => {
                    rules::list_includes(config).await;
                    return;
                }
                ("filters", _, _) => {
                    rules::list_filters(config).await;
                    return;
                }
                _ => (),
            }

            let mut ipc = match ipc::IPCConnection::connect_to_server().await {
                Ok(conn) => conn,
                Err(err) => {
                    println!("Failed to connect to service: {err}");
                    return;
                }
            };

            // Commands that require IPC
            match (cmd, args, config) {
                ("auth", args, _config) => {
                    auth::handle(args, &mut ipc).await.unwrap();
                },
                ("include", args, _config) => {
                    rules::handle(args, &mut ipc, Command::Include).await.unwrap();
                },
                ("filter", args, _config) => {
                    rules::handle(args, &mut ipc, Command::Filter).await.unwrap();
                },
                ("ignore", args, _config) => {
                    rules::handle(args, &mut ipc, Command::Ignore).await.unwrap();
                },
                ("unfilter", args, _config) => {
                    rules::handle(args, &mut ipc, Command::Unfilter).await.unwrap();
                },
                ("limit", args, _config) => {
                    let amount = match u64::from_str(args.value_of("param").expect("Missing param")) {
                        Ok(n) => {
                            if n * 1000 < 10000 {
                                eprintln!("NOTICE: Configured bandwidth limit of {n} lower than minimum (10KB/s), clamping to 10'000");
                                10000
                            } else {
                                n * 1000
                            }
                        },
                        Err(_err) => {
                            println!("Input must be an integer greater than or equal to 0");
                            return;
                        }
                    };
                    match ipc.send_command(Command::Limit, amount.to_string()).await {
                        Ok((response, message)) => println!("{response}: {message}"),
                        Err(err) => {
                            println!("Communication error: {err:?}");
                        }
                    }
                }
                _ => {
                    unimplemented!()
                }
            }
        })
}