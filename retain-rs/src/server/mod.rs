use base64::Engine;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
use glob::Pattern;
use strmap::{PathMap, StrMapConfig};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};

use backblaze_api::api::b2_list_file_names;
use backblaze_api::Auth;

use crate::commands::{ipc, Command, Response};
use crate::config::Config;
use crate::format_bytes;
use crate::server::supervisor::supervise;
use crate::stream::nonce_from_u128;

mod cleaner;
mod enqueuer;
mod resume_large_file;
mod supervisor;
mod upload_file;
mod upload_large_file;

// Type that holds files we know are stored in B2
// This maps a Path to a (modified_timestamp, name_nonce) tuple
// We need to re-use the same encrypted name for the same file to sync correctly
// Instead of storing the whole encrypted name, we can just store the nonce and re-encrypt the path
// Timestamp is milliseconds since Unix Epoch
type KnownFiles = Arc<Mutex<PathMap<(u128, u128)>>>;

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
        Err(_err) => {}
    };

    std::fs::write(portfile_location, &addr.port().to_string()).expect("Failed to write portfile");
    println!("Running on: {}", addr);

    let known_files: KnownFiles = Arc::new(Mutex::new(PathMap::empty()));
    let api_auth: Arc<RwLock<Option<Auth>>> = Arc::new(RwLock::new(None));
    let config: Arc<RwLock<Config>> = Arc::new(RwLock::new(config));
    let _supervisor_handle = tokio::spawn(supervise(
        api_auth.clone(),
        config.clone(),
        known_files.clone(),
    ));

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
                                            let _ = ipc
                                                .send_response(
                                                    Response::Err,
                                                    "Failed to save config file",
                                                )
                                                .await;
                                        }
                                    }
                                }
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
                                    let _ = ipc
                                        .send_response(
                                            Response::Ok,
                                            format!("Removed {removed_count} includes"),
                                        )
                                        .await;
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
                                    let _ = ipc
                                        .send_response(
                                            Response::Ok,
                                            format!("Removed {removed_count} filters"),
                                        )
                                        .await;
                                }
                                Err(msg) => {
                                    let _ = ipc.send_response(Response::Err, msg).await;
                                }
                            }
                        }
                        Command::Limit => {
                            let amount = match u64::from_str(&data) {
                                Ok(n) => n,
                                Err(_err) => {
                                    let _ = ipc
                                        .send_response(
                                            Response::Err,
                                            "Amount must be an integer greater than or equal to 0",
                                        )
                                        .await;
                                    return;
                                }
                            };
                            let mut cfg = config.write().await;
                            cfg.set_bandwidth(amount);
                            let _ = cfg.save();
                            let _ = ipc
                                .send_response(
                                    Response::Ok,
                                    format!("Set limit to {}/s", format_bytes(amount)),
                                )
                                .await;
                        }
                        Command::Search => {
                            let files = known_files.lock().await;
                            match files.len() {
                                0 => {
                                    let _ = ipc.send_response(Response::Err, format!("Cannot search: list of files have not yet been retrieved (or there are 0 files stored). Try again in a moment.")).await;
                                }
                                _ => match Pattern::new(&data) {
                                    Ok(pattern) => {
                                        let mut matched_paths = Vec::new();
                                        let mut last = PathBuf::from_str("").unwrap();
                                        loop {
                                            match files.next(&last) {
                                                Some((path, _)) => {
                                                    if pattern.matches_path(&path) {
                                                        matched_paths.push(
                                                            path.to_string_lossy().to_string(),
                                                        );
                                                    }
                                                    last = path;
                                                }
                                                None => {
                                                    break;
                                                }
                                            }
                                        }
                                        let output = matched_paths.join("\n");
                                        let _ = ipc.send_response(Response::Ok, output).await;
                                    }
                                    Err(_) => {
                                        let _ = ipc
                                            .send_response(
                                                Response::Err,
                                                format!("Invalid glob pattern"),
                                            )
                                            .await;
                                    }
                                },
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
                                    let _ = ipc
                                        .send_response(
                                            Response::Err,
                                            format!("Invalid glob pattern"),
                                        )
                                        .await;
                                    return;
                                }
                            };
                            let target = match target_str {
                                "" => None,
                                _ => {
                                    let path = PathBuf::from(target_str);
                                    if !path.is_dir() {
                                        let _ = ipc
                                            .send_response(
                                                Response::Err,
                                                format!("Invalid target directory"),
                                            )
                                            .await;
                                        return;
                                    }
                                    Some(path)
                                }
                            };
                            let mut download_queue = Vec::new();
                            let mut last = PathBuf::from_str("").unwrap();
                            loop {
                                match files.next(&last) {
                                    Some((path, (timestamp, nonce))) => {
                                        if pattern.matches_path(&path) {
                                            download_queue.push((path.clone(), timestamp, nonce))
                                        }
                                        last = path;
                                    }
                                    None => {
                                        break;
                                    }
                                }
                            }
                            let download_queue: Vec<(PathBuf, PathBuf, u128, u128)> =
                                download_queue
                                    .into_iter()
                                    .map(|(path, timestamp, nonce)| {
                                        let restore_path = match &target {
                                            None => path.to_path_buf(),
                                            Some(target_root) => {
                                                let mut target_path = target_root.clone();
                                                target_path.push(clean_path(&path));
                                                target_path
                                            }
                                        };
                                        (path.clone(), restore_path, *timestamp, *nonce)
                                    })
                                    .collect();

                            let output = download_queue
                                .into_iter()
                                .map(|(path, restore_path, timestamp, nonce)| {
                                    format!(
                                        "{}\x1f{}\x1f{}\x1f{}",
                                        path.to_string_lossy(),
                                        restore_path.to_string_lossy(),
                                        timestamp,
                                        nonce
                                    )
                                })
                                .collect::<Vec<String>>()
                                .join("\x1e");
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
async fn get_file_list_from_b2(
    auth: Arc<RwLock<Option<Auth>>>,
    key: &Key,
) -> PathMap<(u128, u128)> {
    let mut pathmap = PathMap::empty();
    let mut next = None;
    let backoff = [1, 3, 5, 10, 30, 60, 600, 1800, 3600];
    let mut attempts = 0;
    loop {
        match b2_list_file_names(auth.clone(), next.clone()).await {
            Ok(filelist) => {
                let list: Vec<(PathBuf, u128, u128)> = filelist
                    .files
                    .into_iter()
                    .filter_map(|item| {
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
                            Some(t) => match u128::from_str(t) {
                                Ok(n) => n,
                                Err(_err) => {
                                    eprintln!("Invalid src_last_modified_millis value: {}", t);
                                    return None;
                                }
                            },
                            None => {
                                eprintln!("No src_last_modified_millis value");
                                return None;
                            }
                        };
                        Some((path, modified_time as u128, nonce))
                    })
                    .collect();
                let paths: Vec<&Path> = list.iter().map(|elem| elem.0.as_path()).collect();
                pathmap
                    .insert_many(
                        &paths,
                        list.iter().map(|elem| (elem.1, elem.2)).collect(),
                        &StrMapConfig::InMemory,
                    )
                    .unwrap();

                // Check if we're done or what to call with next
                if filelist.next_file_name.is_none() {
                    break;
                } else {
                    next = Some(filelist.next_file_name.unwrap());
                }
            }
            Err(err) => {
                let sleep_for = backoff[attempts];
                eprintln!("b2_list_file_names failed, will retry in {sleep_for}s ({err:?})");
                attempts = (attempts + 1).max(backoff.len() - 1);
                tokio::time::sleep(Duration::from_secs(sleep_for)).await;
            }
        }
    }
    pathmap
}

pub fn get_nonce_from_name(encoded_name: &str) -> Option<u128> {
    let path_bytes = match base64::engine::general_purpose::URL_SAFE.decode(encoded_name) {
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
    let path_bytes = match base64::engine::general_purpose::URL_SAFE.decode(encoded_name) {
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
            eprintln!(
                "Filename does not decrypt to valid utf8: {} ({err:?})",
                encoded_name
            );
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
            let path_string = format!(
                "{}\\",
                component
                    .as_os_str()
                    .to_string_lossy()
                    .replace(&[':', '\\', '/', '*', '?', '"', '?', '<', '>', '|'], "")
            );
            let mut buf = PathBuf::from(path_string);
            let remainder = make_relative(path);
            buf.push(&remainder);
            buf
        }
        Component::RootDir => make_relative(path),
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
        true => PathBuf::from_iter(path.components().skip(1)),
        false => path.to_path_buf(),
    };
    match path.has_root() {
        true => PathBuf::from_iter(path.components().skip(1)),
        false => path.to_path_buf(),
    }
}
