use std::ops::Deref;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use chacha20poly1305::{Key, XChaCha20Poly1305};
use chacha20poly1305::aead::{Aead, NewAead};
use glob::Pattern;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};

use backblaze_api::api::list_all_file_names;
use backblaze_api::Auth;

use crate::commands::{Command, ipc, Response};
use crate::config::Config;
use crate::{format_bytes, retry_forever};
use crate::server::supervisor::supervise;
use crate::stream::nonce_from_u128;

mod supervisor;
mod enqueuer;
mod upload_large_file;
mod upload_file;
mod resume_large_file;
mod cleaner;

// Type that holds files we know are stored in B2 (file_path, modified_timestamp, name_nonce)
// We need to re-use the same filename to replace files correctly
// Instead of storing the whole encrypted name, we can just store the nonce
// Timestamp is milliseconds since Unix Epoch
type KnownFiles = Arc<Mutex<Vec<(PathBuf, u128, u128)>>>;

/// Starts the main processing loop
pub async fn serve() {
    println!("Server starting");

    backblaze_api::init();

    let config = Config::load().expect("Failed to load config");

    // Bind a port, determined by the OS.
    // Write the port to a file, so other programs knows where to connect
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut portfile_location = std::env::temp_dir();
    portfile_location.push("retain-rs.port");

    // Check if an instance is already running
    // This will panic if there is already a server responding on the port stored in retain-rs.port
    // Not a perfect solution, since 2 processes started at the same time may not see each others port-file
    match ipc::IPCConnection::connect_to_server().await {
        Ok(_) => {
            panic!("An instance of the retain-rs server is already running. Please close all existing instances before starting a new one")
        }
        Err(_err) => {},
    };

    std::fs::write(portfile_location, &addr.port().to_string()).expect("Failed to write portfile");
    println!("Running on: {}", addr);

    let known_files: KnownFiles = Arc::new(Mutex::new(Vec::new()));
    let api_auth: Arc<RwLock<Option<Auth>>> = Arc::new(RwLock::new(None));
    let config: Arc<RwLock<Config>> = Arc::new(RwLock::new(config));
    let _supervisor_handle = tokio::spawn(supervise(api_auth.clone(), config.clone(), known_files.clone()));

    // Main loop: listen for and process commands
    loop {
        match listener.accept().await {
            Ok((mut socket, peer_addr)) => {
                // Reject requests that originate outside the local machine
                if !peer_addr.ip().is_loopback() {
                    eprintln!("Refusing non-local request");
                    let _ = socket.shutdown().await;
                    continue;
                }
                let api_auth = api_auth.clone();
                let config = config.clone();
                let known_files = known_files.clone();
                tokio::spawn(async move {
                    // Perform IPC handshake to ensure we're on the same protocol/version
                    let mut ipc = match ipc::IPCConnection::try_serverside_from(socket).await {
                        Ok(ipc) => ipc,
                        Err(err) => {
                            eprintln!("Failed to connect: {err:?}");
                            return;
                        }
                    };
                    eprintln!("Handshake OK. Awaiting command...");

                    // Keep the connection alive for a while, but return if it takes too long
                    // The client-side will re-attempt the handshake when sending a command if this times out
                    let cmd = ipc.receive_command(Duration::from_secs(5)).await;
                    eprintln!("Command: {:?}", cmd);
                    if let Err(_err) = cmd {
                        return;
                    }
                    let (cmd, data) = cmd.unwrap();

                    // Process command and send responses
                    match cmd {
                        Command::Authenticate => {
                            match backblaze_api::api::b2_authorize_account(&data).await {
                                Ok(auth) => {
                                    let mut config_handle = config.write().await;
                                    config_handle.set_key(&data);
                                    match config_handle.save() {
                                        Ok(_) => {
                                            api_auth.write().await.replace(auth);
                                            let _ = ipc.send_response(Response::Ok, "").await;
                                        }
                                        Err(_) => {
                                            let _ = ipc.send_response(Response::Err, "Failed to save config file").await;
                                        }
                                    }
                                },
                                Err(err) => {
                                    let _ = ipc.send_response(Response::Err, err.to_string()).await;
                                }
                            }
                        }
                        Command::Include => {
                            let success = {
                                let mut cfg = config.write().await;
                                cfg.add_include(Path::new(&data))
                            };
                            match success {
                                Ok(_) => {
                                    let _ = ipc.send_response(Response::Ok, "Added include").await;
                                }
                                Err(msg) => {
                                    let _ = ipc.send_response(Response::Err, msg).await;
                                }
                            }
                        }
                        Command::Filter => {
                            let success = {
                                let mut cfg = config.write().await;
                                cfg.add_filter(data)
                            };
                            match success {
                                Ok(_) => {
                                    let _ = ipc.send_response(Response::Ok, "Added filter").await;
                                }
                                Err(msg) => {
                                    let _ = ipc.send_response(Response::Err, msg).await;
                                }
                            }
                        }
                        Command::Ignore => {
                            let success = {
                                let mut cfg = config.write().await;
                                cfg.remove_include(Path::new(&data))
                            };
                            match success {
                                Ok(removed_count) => {
                                    let _ = ipc.send_response(Response::Ok, format!("Removed {removed_count} includes")).await;
                                }
                                Err(msg) => {
                                    let _ = ipc.send_response(Response::Err, msg).await;
                                }
                            }
                        }
                        Command::Unfilter => {
                            let success = {
                                let mut cfg = config.write().await;
                                cfg.remove_filter(data)
                            };
                            match success {
                                Ok(removed_count) => {
                                    let _ = ipc.send_response(Response::Ok, format!("Removed {removed_count} filters")).await;
                                }
                                Err(msg) => {
                                    let _ = ipc.send_response(Response::Err, msg).await;
                                }
                            }
                        },
                        Command::Limit => {
                            let amount = match u64::from_str(&data) {
                                Ok(n) => n,
                                Err(_err) => {
                                    let _ = ipc.send_response(Response::Err, "Amount must be an integer greater than or equal to 0").await;
                                    return;
                                }
                            };
                            let mut cfg = config.write().await;
                            cfg.set_bandwidth(amount);
                            let _ = cfg.save();
                            let _ = ipc.send_response(Response::Ok, format!("Set limit to {}/s", format_bytes(amount))).await;
                        }
                        Command::Search => {
                            let files = known_files.lock().await;
                            match files.len() {
                                0 => {
                                    let _ = ipc.send_response(Response::Err, format!("Cannot search: list of files have not yet been retrieved (or there are 0 files stored). Try again in a moment.")).await;
                                }
                                _ => {
                                    match Pattern::new(&data) {
                                        Ok(pattern) => {
                                            let mut matched_paths = Vec::new();
                                            for file in files.deref() {
                                                let path_string = file.0.to_string_lossy();
                                                if pattern.matches(&path_string) {
                                                    matched_paths.push(path_string);
                                                }
                                            }
                                            let output = matched_paths.join("\n");
                                            let _ = ipc.send_response(Response::Ok, output).await;
                                        }
                                        Err(_) => {
                                            let _ = ipc.send_response(Response::Err, format!("Invalid glob pattern")).await;
                                        }
                                    }
                                }
                            }
                        }
                        Command::Restore => {
                            let files = known_files.lock().await;
                            if files.len() == 0 {
                                let _ = ipc.send_response(Response::Err, format!("Cannot search: list of files have not yet been retrieved (or there are 0 files stored). Try again in a moment.")).await;
                                return;
                            }
                            let parts: Vec<&str> = data.split("\x1e").collect();
                            let pattern_str = parts[0];
                            let target_str = parts[1];
                            let pattern = match Pattern::new(pattern_str) {
                                Ok(pattern) => pattern,
                                Err(_err) => {
                                    let _ = ipc.send_response(Response::Err, format!("Invalid glob pattern")).await;
                                    return;
                                }
                            };
                            let target = match target_str {
                                "" => None,
                                _ => {
                                    let path = PathBuf::from(target_str);
                                    if !path.is_dir() {
                                        let _ = ipc.send_response(Response::Err, format!("Invalid target directory")).await;
                                        return;
                                    }
                                    Some(path)
                                },
                            };
                            let mut download_queue = Vec::new();
                            for (path, timestamp, nonce) in &*files {
                                if pattern.matches_path(&path) {
                                    download_queue.push((path, timestamp, nonce))
                                }
                            }
                            let download_queue: Vec<(PathBuf, PathBuf, u128 , u128)> = download_queue.into_iter().map(|(path, timestamp, nonce) | {
                                let restore_path = match &target {
                                    None => path.to_path_buf(),
                                    Some(target_root) => {
                                        let mut target_path = target_root.clone();
                                        target_path.push(clean_path(&path));
                                        target_path
                                    }
                                };
                                (path.clone(), restore_path, *timestamp, *nonce)
                            }).collect();

                            let output = download_queue.into_iter().map(|(path, restore_path, timestamp, nonce)| {
                                format!("{}\x1f{}\x1f{}\x1f{}", path.to_string_lossy(), restore_path.to_string_lossy(), timestamp, nonce)
                            }).collect::<Vec<String>>().join("\x1e");
                            let _ = ipc.send_response(Response::Ok, &output).await;
                        }
                    }
                });
            }
            Err(err) => {
                println!("Err: {}", err);
            }
        }
    }
}

/// Retrieves the list of files stored in B2
///
/// This returns a list of (decrypted path, modified ms, name nonce)
async fn get_file_list_from_b2(auth: Arc<RwLock<Option<Auth>>>, key: &Key) -> Vec<(PathBuf, u128, u128)> {
    retry_forever!([5, 60, 300, 600, 3600, 14400], result, {list_all_file_names(auth.clone(), None).await},
        {
            let mut list: Vec<(PathBuf, u128, u128)> = result.into_iter().filter_map(|item| {
                    let nonce = match get_nonce_from_name(&item.file_name) {
                        Some(nonce) => nonce,
                        None => {
                            return None;
                        }
                    };
                    let path = match decrypt_file_name(&item.file_name, key) {
                        Some(path) => path,
                        None => {
                            return None;
                        }
                    };
                    let modified_time = match item.file_info.get("src_last_modified_millis") {
                        Some(t) => {
                            match u128::from_str(t) {
                                Ok(n) => n,
                                Err(_err) => {
                                    eprintln!("Invalid src_last_modified_millis value: {}", t);
                                    return None;
                                }
                            }
                        }
                        None => {
                            eprintln!("No src_last_modified_millis value");
                            return None;
                        }
                    };
                    Some((path, modified_time as u128, nonce))
                }).collect();
                list.sort_by(|e1, e2| e1.0.cmp(&e2.0));
                for i in 1..list.len() {
                    if list[i].0 == list[i-1].0 {
                        eprintln!("Duplicate files on B2 for path {:?}", list[i].0);
                        eprintln!("ID {} - Modified: {}", list[i].2, list[i].1);
                        eprintln!("ID {} - Modified: {}", list[i-1].2, list[i-1].1);
                        // For now, we'll resolve this by panicking
                        // It should be impossible to have multiple files on B2 corresponding to the same file on disk
                        // A file is only uploaded it if does not already exist or it has been modified
                        // If modified, the file is supposed to retain it's name -- If it doesn't it's a bug and we panic
                        // So the only way we can get a new B2 file for the same path is the old file was deleted/hidden
                        // but if it was deleted hidden, there shouldn't be 2 files
                        // Thus, we should only get here in 2 scenarios, spare bugs from Backblaze:
                        // 1. There is a bug in the code that caused a duplicate upload
                        // 2. A hidden file was restored manually
                        // Neither of those should happen, so, we panic
                        // A potential alternative would be to discard all files except the one with most recent 'modified_at'
                        panic!("Unexpected duplicate in B2");
                    }
                }
                return list;
        }, {
            eprintln!("Failed to get file list from B2: {result:?}")
        });
}

pub fn get_nonce_from_name(encoded_name: &str) -> Option<u128> {
    let path_bytes = match base64::decode_config(encoded_name, base64::URL_SAFE) {
        Ok(bytes) => bytes,
        Err(_err) => {
            eprintln!("Invalid base64 in file name: {}", encoded_name);
            return None;
        }
    };
    let nonce_bytes = &path_bytes[0..16];
    let nonce = u128::from_le_bytes(match nonce_bytes.try_into() {
        Ok(bytes) => bytes,
        Err(_err) => {
            eprintln!("Failed to get nonce from: {}", encoded_name);
            return None;
        }
    });
    Some(nonce)
}

pub fn decrypt_file_name(encoded_name: &str, key: &Key) -> Option<PathBuf> {
    let aead = XChaCha20Poly1305::new(key);
    let path_bytes = match base64::decode_config(encoded_name, base64::URL_SAFE) {
        Ok(bytes) => bytes,
        Err(_err) => {
            eprintln!("Invalid base64 in file name: {}", encoded_name);
            return None;
        }
    };
    let nonce_bytes = &path_bytes[0..16];
    let nonce = u128::from_le_bytes(match nonce_bytes.try_into() {
        Ok(bytes) => bytes,
        Err(_err) => {
            eprintln!("Failed to get nonce from: {}", encoded_name);
            return None;
        }
    });
    let nonce = nonce_from_u128(nonce);
    let decrypted_bytes = match aead.decrypt(&nonce, &path_bytes[16..]) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("Failed to decrypt name for: {} ({err:?})", encoded_name);
            return None;
        }
    };
    let path_string = match String::from_utf8(decrypted_bytes) {
        Ok(string) => string,
        Err(err) => {
            eprintln!("Filename does not decrypt to valid utf8: {} ({err:?})", encoded_name);
            return None;
        }
    };
    Some(PathBuf::from(path_string))
}

// 'Clean' a path, converting it to a non-absolute, non-root path
// On Windows, 'C:/Users/MyUser/Downloads' would turn to 'C/Users/MyUser/Downloads'
// On non-Windows, '/home/user/Downloads' would turn to 'home/user/Downloads'
fn clean_path(path: &Path) -> PathBuf {
    match path.components().next().unwrap() {
        Component::Prefix(component) => {
            // Prefixes only exist on Windows. Grab any potential drive letter and remove illegal characters
            // There _MAY_ be some odd behavior non-drive prefixes, but surely nobody will encounter that
            let path_string = format!("{}\\", component.as_os_str().to_string_lossy().replace(&[':','\\','/','*','?','"','?','<','>','|'], ""));
            let mut buf = PathBuf::from(path_string);
            let remainder = make_relative(path);
            buf.push(&remainder);
            buf
        }
        Component::RootDir => {
            make_relative(path)
        }
        Component::CurDir => {
            panic!("Path starts with relative component: {path:?}");
        }
        Component::ParentDir => {
            panic!("Path starts with parent component {path:?}");
        }
        Component::Normal(_) => {
            panic!("Path starts with non-root, non-prefix component {path:?}");
        }
    }
}

// Recursively drops the first component of a path until it is not absolute and has no root
fn make_relative(path: &Path) -> PathBuf {
    let path = match path.is_absolute() {
        true => {
            PathBuf::from_iter(path.components().skip(1))
        }
        false => path.to_path_buf(),
    };
    match path.has_root() {
        true => {
            PathBuf::from_iter(path.components().skip(1))
        }
        false => path.to_path_buf(),
    }
}