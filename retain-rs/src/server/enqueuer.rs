use crate::config::Config;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::ReadDir;
use tokio::fs::{read_dir, DirEntry};
use tokio::sync::mpsc::Sender;
use tokio::sync::RwLock;
use tokio::time::Instant;

/// Worker that sends files to be uploaded by running the rules defined in the config
pub async fn enqueue_files(config: Arc<RwLock<Config>>, sender: Sender<std::path::PathBuf>) {
    let mut rules = { config.write().await.get_rules() };
    let mut turbo_mode = { config.write().await.is_turbo_mode() };
    // last_recheck and recheck_interval are used to periodically poll for changes to the rules
    let mut last_recheck = Instant::now();
    let recheck_interval = Duration::from_secs(5);
    // We iterate over current_iterator, sending files for upload and adding dirs to dirs_to_check
    // Once current_iterator is done, we set current_iterator to the first element from dirs_to_check
    // This essentially recursively walks the directories
    // Once there are no more dirs_to_check and current_iterator is done, we move to the next 'include' rule
    let mut current_iterator: Option<ReadDir> = None;
    let mut current_include = String::new();
    let mut current_include_idx = 0;
    let mut dirs_to_check: Vec<PathBuf> = Vec::new();
    loop {
        // Sleep a bit to avoid hammering the filesystem
        // If turbo mode is enabled, skip this to scan faster
        if !turbo_mode {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        // Update our rules if it's been too long since we last did it
        if last_recheck.elapsed() > recheck_interval {
            last_recheck = Instant::now();
            let should_refetch = { config.read().await.get_rules_version() > rules.version };
            if should_refetch {
                eprintln!("Reloading rules");
                rules = config.write().await.get_rules();
                turbo_mode = config.write().await.is_turbo_mode();
                // Verify that the current include rule is still valid
                // It must still be in the includes list, and not removed by a filter
                // Note that we don't skip if a _subdirectory_ of an include has been invalidated
                if !(rules.allowed_by_filters(Path::new(&current_include))
                    && rules.get_includes().contains(&current_include))
                {
                    // Current rule is no longer valid, reset tracking
                    eprintln!(
                        "Skipping the rest of current include rule, as it has been invalidated"
                    );
                    current_iterator = None;
                    current_include = "".to_string();
                    dirs_to_check.clear();
                }
            }
        }
        if rules.get_includes().is_empty() {
            // In case there's nothing to upload, sleep a bit to avoid a busy loop
            tokio::time::sleep(Duration::from_millis(1000)).await;
            continue;
        }

        match current_iterator.as_mut() {
            Some(iter) => {
                // Check if it matches against any of the filters in rules
                // If it doesn't, we either:
                // File: send it via sender, s.t. it'll be uploaded
                // Dir: push it to dirs_to_check
                let item: DirEntry = match iter.next_entry().await {
                    Ok(item) => match item {
                        Some(item) => item,
                        None => {
                            current_iterator = None;
                            continue;
                        }
                    },
                    Err(err) => {
                        eprintln!("Error reading entries in {current_include} - {err:?}");
                        current_iterator = None;
                        continue;
                    }
                };
                let path = item.path();
                if !rules.allowed_by_filters(&path) {
                    continue;
                }

                // Note: symlinks are ignored
                if path.is_file() {
                    sender.send(path).await.expect("Upload close rx closed");
                } else if path.is_dir() {
                    dirs_to_check.push(path);
                }
                continue;
            }
            None => {
                match dirs_to_check.pop() {
                    Some(s) => match read_dir(&s).await {
                        Ok(read_dir) => {
                            current_iterator = Some(read_dir);
                        }
                        Err(err) => {
                            eprintln!("Failed to read sub-dir for include {current_include} - {} : {err:?}", s.to_string_lossy());
                            continue;
                        }
                    },
                    None => {
                        current_include = match rules.get_includes().get(current_include_idx) {
                            Some(include) => {
                                current_include_idx += 1;
                                include
                            }
                            None => {
                                // Loop back around to the first include
                                // To ensure we don't queue files that _might_ be currently uploading,
                                // we will wait for the
                                current_include_idx = 0;
                                rules.get_includes().get(current_include_idx).expect(
                                    "get_includes() is non-empty, but has no item at index 0?",
                                )
                            }
                        }
                        .to_string();
                        let path = Path::new(&current_include);
                        if path.is_file() && rules.allowed_by_filters(path) {
                            sender
                                .send(path.to_path_buf())
                                .await
                                .expect("Upload close rx closed");
                            continue;
                        }
                        match read_dir(&current_include).await {
                            Ok(read_dir) => {
                                current_iterator = Some(read_dir);
                            }
                            Err(err) => {
                                eprintln!("Failed to read top-level dir @ include {current_include}: {err:?}");
                                continue;
                            }
                        }
                    }
                }
            }
        }
    }
}
