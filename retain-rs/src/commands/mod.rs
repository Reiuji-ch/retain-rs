use crate::stream::nonce_from_u128;
use crate::{retry_forever, Config};
use backblaze_api::api::{b2_authorize_account, b2_download_file_by_name};
use base64::Engine;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use clap::ArgMatches;
use futures_util::StreamExt;
use std::fmt::{Display, Formatter};
use std::ops::Add;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::UNIX_EPOCH;
use tokio::io::AsyncWriteExt;

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
    Limit,
    /// Search the backed up files (only completed uploads) using a glob pattern
    Search,
    /// Restore everything matching a glob pattern to a target path
    Restore,
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
            Command::Search => "Search",
            Command::Restore => "Restore",
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
            "Search" => Command::Search,
            "Restore" => Command::Restore,
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
                ("search", args, _config) => {
                    let search_pattern = args.value_of("param").expect("Missing pattern");
                    match ipc.send_command(Command::Search, search_pattern).await {
                        Ok((response, message)) => {
                            match response {
                                Response::Ok => println!("{message}"),
                                Response::Err => println!("Error: {message}"),
                            }
                        },
                        Err(err) => {
                            println!("Communication error: {err:?}");
                        }
                    }
                },
                ("restore", args, config) => {
                    let search_pattern = args.value_of("pattern").expect("Missing pattern");
                    let target_path = args.value_of("target").unwrap_or("");
                    let overwrite = args.is_present("overwrite");
                    let data = format!("{}\x1e{}", search_pattern, target_path);
                    let download_queue = match ipc.send_command(Command::Restore, data).await {
                        Ok((response, message)) => {
                            match response {
                                Response::Ok => {
                                    if message.is_empty() {
                                        eprintln!("No files matched");
                                        return;
                                    }
                                    let mut queue = Vec::new();
                                    for record in message.split("\x1e") {
                                        let parts: Vec<&str> = record.split("\x1f").collect();
                                        queue.push((PathBuf::from(parts[0]),
                                                    PathBuf::from(parts[1]),
                                                    u128::from_str(parts[2]).unwrap(),
                                                    u128::from_str(parts[3]).unwrap()));
                                    }
                                    queue
                                }
                                Response::Err => {
                                    println!("Error: {message}");
                                    return;
                                },
                            }
                        }
                        Err(err) => {
                            println!("Communication error: {err:?}");
                            return;
                        }
                    };
                    println!("Downloading {} files", download_queue.len());
                    backblaze_api::init();
                    let key = config.get_key().to_string();
                    let enc_key = config.get_encryption_key();
                    let aead = XChaCha20Poly1305::new(&enc_key);
                    let auth = match b2_authorize_account(&key).await {
                        Ok(auth) => {
                            auth
                        }
                        Err(err) => {
                            eprintln!("Failed to authorize: {err:?}");
                            return;
                        }
                    };
                    // TODO: Render _cool_ progress bar in here
                    for (path, target, timestamp, name_nonce) in download_queue {
                        // Check if there is already a file at the target download path
                        // Existing files will only be overwritten if the --overwrite flag is set
                        match target.exists() {
                            true => {
                                match overwrite {
                                    true => {
                                        println!("Restore (overwriting existing) {path:?} -> {target:?}");
                                    }
                                    false => {
                                        println!("Skipping (file exists) {path:?} -> {target:?}");
                                        continue;
                                    }
                                }
                            }
                            false => {
                                println!("Restore {path:?} -> {target:?}");
                            }
                        }
                        let encrypted_filename = match aead.encrypt(&nonce_from_u128(name_nonce), path.to_string_lossy().replace("\\", "/").as_bytes()) {
                            Ok(mut ciphertext) => {
                                let mut name = name_nonce.to_le_bytes().to_vec();
                                name.append(&mut ciphertext);
                                base64::engine::general_purpose::URL_SAFE.encode(name)
                            }
                            Err(err) => {
                                panic!("Encryption failed: {err:?}");
                            }
                        };
                        let mut temp_target = target.clone();
                        temp_target.set_file_name(format!("{}.retain-restore-tmp", temp_target.file_name().unwrap().to_string_lossy()));

                        // We may want to implement some retry logic for large files in case of interruptions
                        // That is, instead of retrying the whole part, make checkpoints every n megabytes
                        retry_forever!([1, 3, 5, 10, 30, 60, 600, 1800, 3600], result, {
                            b2_download_file_by_name(auth.clone(), encrypted_filename.clone()).await
                        }, {
                            let mut stream = crate::stream::decrypt::DecryptingStream::wrap(result.bytes_stream(), &enc_key.clone());
                            let _ = tokio::fs::create_dir_all(target.parent().expect("File with no parent?")).await;
                            let mut file = match tokio::fs::File::create(&temp_target).await {
                                Ok(file) => file,
                                Err(err) => {
                                    eprintln!("Skipping {path:?} - Err: {err:?}");
                                    break;
                                }
                            };

                            // TODO: Improve error handling here
                            // We do not currently stop the loop properly and may leave broken files
                            while let Some(item) = stream.next().await {
                                match item {
                                    Ok(bytes) => file.write_all(&bytes).await.expect("Write failed"),
                                    Err(err) => {
                                        eprintln!("Stream error, aborting restore of {path:?} - {err:?}");
                                        match tokio::fs::remove_file(&temp_target).await {
                                            Ok(_) => (),
                                            Err(err) => {
                                                eprintln!("Failed to remove potentially broken file during restore of {temp_target:?} - {err:?}");
                                            }
                                        }
                                        todo!("Improve this");
                                    },
                                };
                            }

                            // Flush the temp file and move it to the target file
                            file.flush().await.expect("Failed to flush file");
                            std::fs::rename(&temp_target, &target).expect("Failed to move temp file to target");

                            // Try to set the modified time to whatever is stored in B2
                            let modified_time = UNIX_EPOCH.add(Duration::new((timestamp / 1_000).try_into().unwrap(), (timestamp % 1_000).try_into().unwrap()));
                            filetime::set_file_mtime(
                                &target,
                                filetime::FileTime::from_system_time(modified_time)
                            ).expect("Failed to set modified time");
                            break;
                        }, {
                            eprintln!("Failed to download: {result:?}");
                        });
                    }
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
