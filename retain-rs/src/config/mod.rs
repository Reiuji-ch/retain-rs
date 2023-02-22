pub mod rules;

use base64::Engine;
use chacha20poly1305::Key;
use rand::RngCore;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;

use crate::config::rules::RuleManager;
use serde::{Deserialize, Serialize};

// How many nonces to pre-allocate
// When the program starts (or runs out) it allocates this many new nonces
// The `nonce` counter is set to the value it would be at, if we used all of them, and the config is saved
// When the program is closed, it will resume from the save 'nonce' count
// This guarantees we don't re-use nonces, since we won't allow using nonces above the stored counter value
//
// The amount of data we can encrypt per re-allocation (and config file save) is given by:
// BUFFERED_NONCES * BLOCK_SIZE = <n> bytes
// We have 2^128 nonces (technically up to 2^192, if we switch integer types), so go nuts, I guess...
// 2^18 * 8192 is approx. 2.15GB per re-alloc
const BUFFERED_NONCES: u128 = 2u128.pow(18);

#[derive(Debug, Clone, PartialOrd, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    #[serde(skip)]
    path: String,
    auth_key: String,
    bandwidth: u64,
    // 'version' keeps track of how many times the config changed, s.t. each user can re-fetch as needed
    // This is purely for hot-reloading and does not need to be saved as a result
    #[serde(skip)]
    version: u64,
    rules: RuleManager,
    encryption_keystring: String,
    #[serde(skip)]
    encryption_key: Option<Key>,
    // The next nonce to continue from, if the program is restarted
    nonce: u128,
    // How many nonces we can use, before we need to update `nonce` and save the config
    #[serde(skip)]
    available_nonces: u128,
}

impl Config {
    pub fn save(&self) -> Result<(), std::io::Error> {
        if let Some(parent) = Path::new(&self.path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = File::create(&self.path)?;
        let data = serde_json::to_vec(&self).unwrap();
        file.write_all(&data)?;
        file.flush()?;
        Ok(())
    }

    /// Load config from file or return the default config
    pub fn load() -> Result<Self, String> {
        if let Some((mut file, path)) = find_config_file() {
            let mut contents = String::new();
            match file.read_to_string(&mut contents) {
                Ok(_read) => {
                    let mut cfg = match serde_json::from_str::<Config>(&contents) {
                        Ok(cfg) => cfg,
                        Err(err) => {
                            eprintln!("Config file contains invalid data");
                            eprintln!("{err:?}");
                            return Err("Invalid config file structure".to_string());
                        }
                    };
                    cfg.path = path;
                    // Verify the rules make sense
                    cfg.rules.validate()?;
                    // Load encryption key
                    let key = base64::engine::general_purpose::STANDARD
                        .decode(&cfg.encryption_keystring)
                        .expect("Invalid encryption key");
                    let key = Key::clone_from_slice(&key);
                    cfg.encryption_key = Some(key);
                    cfg.available_nonces = 0;
                    Ok(cfg)
                }
                Err(err) => Err(err.to_string()),
            }
        } else {
            // Try to write the config to the first location we can
            for location in get_config_locations() {
                let config = Config {
                    path: location.clone(),
                    ..Default::default()
                };
                // Save the new config. Failing to save is an error,
                // since we won't  be able to store any changes made to it later
                if config.save().is_ok() {
                    return Ok(config);
                }
            }

            // Handle error case where we cannot write the config to any of the directories use
            Err(format!(
                "Failed to write config file: could not write to any of the candidate paths: {:?}",
                get_config_locations()
            ))
        }
    }

    /// Sets key used for b2_authorize_account
    ///
    /// key should be the combined, base64-encoded string
    pub fn set_key(&mut self, key: &str) {
        self.auth_key = key.trim().to_string();
    }

    /// Get the base64-encoded key
    pub fn get_key(&self) -> &str {
        self.auth_key.trim()
    }

    /// Sets the maximum bandwidth usage, in bytes/second
    pub fn set_bandwidth(&mut self, bandwidth: u64) {
        self.bandwidth = bandwidth;
    }

    /// Get the maximum bandwidth, in bytes/second
    pub fn get_bandwidth(&self) -> u64 {
        self.bandwidth
    }

    /// Obtain a copy of the currently in-effect RuleManager
    ///
    /// All held instances of RuleManager needs to be re-fetched when `version` changes
    pub fn get_rules(&mut self) -> RuleManager {
        self.rules.version = self.version;
        self.rules.clone()
    }

    pub fn get_rules_version(&self) -> u64 {
        self.version
    }

    /// Add a new filter to the rules
    pub fn add_filter(&mut self, filter: String) -> Result<(), String> {
        self.rules.add_filter(filter)?;
        self.version += 1;
        self.save().map_err(|err| err.to_string())?;
        Ok(())
    }

    /// Add a new include to the rules
    pub fn add_include(&mut self, path: &Path) -> Result<(), String> {
        self.rules.add_include(path)?;
        self.version += 1;
        self.save().map_err(|err| err.to_string())?;
        Ok(())
    }

    pub fn remove_include(&mut self, path: &Path) -> Result<usize, String> {
        let removed_count = self.rules.remove_include(path)?;
        self.version += 1;
        self.save().map_err(|err| err.to_string())?;
        Ok(removed_count)
    }

    pub fn remove_filter(&mut self, filter: String) -> Result<usize, String> {
        let removed_count = self.rules.remove_filter(filter)?;
        self.version += 1;
        self.save().map_err(|err| err.to_string())?;
        Ok(removed_count)
    }

    pub fn get_encryption_key(&self) -> Key {
        self.encryption_key
            .expect("No encryption key, but load() should guarantee it exists..?")
    }

    // Allocates as many nonces as needed and returns the first nonce to use
    pub fn get_next_nonce(&mut self, required: u128) -> u128 {
        while self.available_nonces < required {
            self.nonce += BUFFERED_NONCES;
            self.available_nonces += BUFFERED_NONCES;
            self.save()
                .expect("Failed to save config during nonce allocation");
        }
        self.available_nonces -= required;
        // The current nonce is easily expressed as `nonce - available_nonces`
        // Since we just subtracted `required` from available, we can find the start nonce like so:
        (self.nonce - self.available_nonces) - required
    }
}

/// Attempt to discover a config file
/// This can be in several locations and may be system dependent
/// If the environment variable RETAIN_CONFIG_NAME is set, it will look for a file with
/// that name instead of the default "retain.conf"
fn find_config_file() -> Option<(File, String)> {
    let search_dirs = get_config_locations();

    for path in search_dirs {
        let file = File::open(&path);
        if let Ok(f) = file {
            return Some((f, path));
        }
    }

    None
}

/// The prioritized order to search in is:
/// 1. Environment Variable "RETAIN_CONFIG_FILE" (including filename)
/// 2. Environment Variable "RETAIN_CONFIG_FILE" (excluding filename)
/// 3. (Windows) AppData/Local/retain-rs/ (Other) $XDG_CONFIG_HOME or $HOME
/// 4. Directory of the executable
fn get_config_locations() -> Vec<String> {
    let mut possible = Vec::new();
    // Environment-based location
    if let Ok(path) = std::env::var("RETAIN_CONFIG_FILE") {
        possible.push(path.clone());
        let path = format!(
            "{path}/{}",
            std::env::var("RETAIN_CONFIG_NAME").unwrap_or_else(|_| "retain.conf".to_string())
        );
        possible.push(path);
    }

    // System config dir
    if let Some(mut path) = dirs::config_dir() {
        path.push("retain-rs");
        path.push(
            std::env::var("RETAIN_CONFIG_NAME").unwrap_or_else(|_| "retain.conf".to_string()),
        );
        let path = path.to_string_lossy().to_string();
        possible.push(path);
    }
    // Executable dir
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(path) = exe_path.parent() {
            let mut path = path.to_owned();
            path.push(
                std::env::var("RETAIN_CONFIG_NAME").unwrap_or_else(|_| "retain.conf".to_string()),
            );
            let path = path.to_string_lossy().to_string();
            possible.push(path);
        }
    }

    possible
}

impl Default for Config {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let keystring = base64::engine::general_purpose::STANDARD.encode(&key);
        let key = Key::from(key);
        Config {
            path: Default::default(),
            auth_key: "".to_string(),
            bandwidth: 0,
            version: 0,
            rules: RuleManager::default(),
            encryption_keystring: keystring,
            encryption_key: Some(key),
            nonce: 0,
            available_nonces: 0,
        }
    }
}
