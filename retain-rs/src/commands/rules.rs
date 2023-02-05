use crate::commands::ipc::IPCConnection;
use crate::commands::{Command, Response};
use crate::stream::get_encrypted_size;
use crate::{format_bytes, Config};
use backblaze_api::api::{b2_authorize_account, list_all_file_names};
use clap::ArgMatches;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

pub async fn handle(args: &ArgMatches, ipc: &mut IPCConnection, action: Command) -> Result<(), ()> {
    let arg = args.value_of("param").expect("Parameter missing");
    match ipc.send_command(action, arg).await {
        Ok((response, data)) => match response {
            Response::Ok => {
                println!("Success: {data}");
            }
            Response::Err => {
                println!("Failed to apply: {}", data);
            }
        },
        Err(err) => println!("Communication failure: {:?}", err),
    }

    Ok(())
}

pub async fn explain(args: &ArgMatches, mut config: Config) {
    let param = args.value_of("param").expect("Parameter missing");
    let path = PathBuf::from(param);
    if !path.exists() {
        eprintln!("Note: {param} does not exist");
    }
    // The trailing slash may be significant for filters, so make sure we add it for dirs
    // Excluding a dir can be done with a filter as either "/some/dir*" or "/some/dir/*"
    // but only the second one will match the dir and only the dir, whereas the first one would also
    // match all elements in 'some' that start with 'dir', e.g. "/some/directions.png"
    // To make results for directories more accurate, we add the trailing slash
    let path = match path.is_dir() {
        true => PathBuf::from(format!("{param}/")),
        false => path,
    };
    let rules = config.get_rules();
    let includes = rules.get_includes();
    let filters = rules.get_filters();
    let mut is_included = false;
    for include in includes {
        if path.starts_with(include) {
            eprintln!("Included by rule: {include}");
            is_included = true;
            for filter in filters {
                if filter.matches_path(&path) {
                    eprintln!("...but excluded by filter {filter}");
                }
            }
        }
    }
    if !is_included {
        eprintln!("Not included for consideration");
        for filter in filters {
            if filter.matches_path(&path) {
                eprintln!("...but would be excluded by filter {filter}");
            }
        }
    }
}

pub async fn cost(args: &ArgMatches, mut config: Config) {
    let param = args.value_of("param").expect("Parameter missing");
    let path = PathBuf::from(param);
    if !path.exists() {
        eprintln!("Error: {param} does not exist");
        return;
    }
    // The trailing slash may be significant for filters, so make sure we add it for dirs
    // Excluding a dir can be done with a filter as either "/some/dir*" or "/some/dir/*"
    // but only the second one will match the dir and only the dir, whereas the first one would also
    // match all elements in 'some' that start with 'dir', e.g. "/some/directions.png"
    // To make results for directories more accurate, we add the trailing slash
    let path = match path.is_dir() {
        true => PathBuf::from(format!("{param}/")),
        false => path,
    };

    let (bytes, files) = usage_by_path(&path, &mut config).await;

    println!(
        "Including this path uses {} of storage, spread across {files} files",
        format_bytes(bytes)
    );
    println!(
        "Including this path costs ${:.2} USD/month",
        bytes_to_cost(bytes)
    );
}

/// Computes how much it costs per month to store the given number of bytes
fn bytes_to_cost(count: u64) -> f64 {
    // $0.005/GB/Month + 25% VAT
    0.005 * (count as f64) / 1_000_000_000. * 1.25
}

/// Computes the number of (bytes, files) a given path has, taking filters and overhead into account
async fn usage_by_path<P: AsRef<Path>>(path: P, config: &mut Config) -> (u64, u64) {
    let path = path.as_ref();
    let rules = config.get_rules();
    let mut dirs_to_check = vec![path.to_path_buf()];
    let mut total_included_bytes = 0;
    let mut total_included_files = 0;
    while let Some(path) = dirs_to_check.pop() {
        if path.is_file() {
            if rules.should_upload(&path) {
                total_included_files += 1;
                total_included_bytes +=
                    get_encrypted_size(path.metadata().expect("Failed to stat file").len());
            }
            continue;
        }
        for entry in path.read_dir().expect("Failed to iterate dir") {
            match entry {
                Ok(entry) => {
                    if entry.path().is_dir() {
                        if rules.should_upload(&entry.path()) {
                            dirs_to_check.push(entry.path().to_path_buf());
                        }
                    } else if rules.should_upload(&entry.path()) {
                        total_included_files += 1;
                        total_included_bytes += get_encrypted_size(
                            entry.metadata().expect("Failed to stat file").len(),
                        );
                    }
                }
                Err(err) => {
                    eprintln!("Failed to read sub-dir {err:?}");
                }
            }
        }
    }
    (total_included_bytes, total_included_files)
}

pub async fn stats(mut config: Config) {
    eprintln!("Authenticating with B2...");
    let key = config.get_key().to_string();
    if !key.is_empty() {
        backblaze_api::init();
        let auth = match b2_authorize_account(&key).await {
            Ok(auth) => auth,
            Err(err) => {
                eprintln!("Failed to authorize: {err:?}");
                return;
            }
        };
        let auth_wrapped = Arc::new(RwLock::new(Some(auth)));
        let files = list_all_file_names(auth_wrapped, None)
            .await
            .expect("Failed to list all files");
        let bytes_in_b2 = files.iter().fold(0, |acc, elem| acc + elem.content_length);
        println!(
            "Current actual usage: {}, across {} files",
            format_bytes(bytes_in_b2),
            files.len()
        );
        let cost_estimate = 0.005 * (bytes_in_b2 as f64) / 1_000_000_000. * 1.25;
        println!("Current actual cost: ${:.2} USD/month", cost_estimate);
    } else {
        eprintln!("No B2 API key configured");
    }

    eprintln!("Determining number of and size of files. This may take a minute or two...");
    let mut total_bytes = 0;
    let mut total_files = 0;
    for include in config.get_rules().get_includes() {
        let (bytes, files) = usage_by_path(Path::new(include), &mut config).await;
        total_bytes += bytes;
        total_files += files;
    }

    // The exact usage depends primarily on 2 factors:
    // 1. Data that hasn't been uploaded yet (Causes estimate to be higher than actual)
    // 2. "Hidden" files that haven't been deleted yet (Causes estimate to be lower than actual)
    println!(
        "Estimated total usage: {} across {total_files} files",
        format_bytes(total_bytes)
    );
    // $0.005/GB/Month + 25% VAT
    let cost_estimate = 0.005 * (total_bytes as f64) / 1_000_000_000. * 1.25;
    println!("Estimated total cost: ${:.2} USD/month", cost_estimate);
}

pub async fn list_includes(mut config: Config) {
    println!("List of currently included directories:");
    for include in config.get_rules().get_includes() {
        println!("{include}");
    }
}

pub async fn list_filters(mut config: Config) {
    println!("List of currently active filters:");
    for filter in config.get_rules().get_filters() {
        println!("{}", filter.as_str());
    }
}
