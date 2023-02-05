//! Module governing the 'rules' implementation -- Used to determine which files to upload and which to skip
//!
//! The `RuleManager` contains 2 things
//! 1. `include` which is the list of paths to consider for uploading
//! 2. `filters` which is a list of glob-patterns
//! That is, `include` defines which files _might_ be uploaded and `filters` determine whether or not they should actually be uploaded.
//! Each item in `include` is an absolute path. Each item in `filters` in a glob-style pattern.
//! We recursively iterate over items defined by `include`. If any of the glob patterns match one of these items, it is _NOT_ uploaded.

use glob::Pattern;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialOrd, PartialEq, Eq)]
pub struct RuleManager {
    // The 'version' of the config at the time this RuleManager was instanced
    #[serde(skip)]
    pub version: u64,
    includes: Vec<String>,
    filters: Vec<String>,
    #[serde(skip)]
    compiled_filters: Vec<Pattern>,
    #[serde(skip)]
    filters_validated: bool,
}

impl RuleManager {
    pub fn validate(&mut self) -> Result<(), String> {
        self.filters_validated = false;
        self.compiled_filters.clear();
        for filter in &self.filters {
            let pattern = Pattern::new(filter);
            match pattern {
                Ok(pattern) => self.compiled_filters.push(pattern),
                Err(_) => return Err(format!("Invalid pattern: {} in rules ", filter)),
            }
        }
        self.compiled_filters.push(
            Pattern::new("*.retain-restore-tmp").expect("Failed to compile internal-use filter"),
        );
        self.filters_validated = true;

        Ok(())
    }

    /// Attempt to add a glob-pattern to the list of filters
    ///
    /// This may fail if `filter` is not a valid glob or an identical filter already exists
    pub fn add_filter(&mut self, filter: String) -> Result<(), String> {
        for existing_filter in &self.filters {
            if &filter == existing_filter {
                return Err("An identical filter already exists".to_string());
            }
        }

        let pattern = glob::Pattern::new(&filter);
        match pattern {
            Ok(pattern) => {
                self.filters.push(filter);
                self.compiled_filters.push(pattern);
            }
            Err(_) => return Err(format!("Invalid pattern: {} in rules ", filter)),
        }
        Ok(())
    }

    /// Attempt to add a new path to be considered for uploading
    ///
    /// This may fail if `path` would already be backed up by an existing rule
    pub fn add_include(&mut self, path: &Path) -> Result<(), String> {
        let mut potentially_included = false;
        let mut errors = Vec::new();
        for include in &self.includes {
            if path.starts_with(include) {
                potentially_included = true;
                errors.push(format!(
                    "`{}` is already covered by `{}`",
                    path.to_string_lossy(),
                    include
                ));
                break;
            }
        }
        for filter in &self.compiled_filters {
            if filter.matches_path(path) {
                potentially_included = true;
                errors.push(format!(
                    "`{}` is ignored by a filter: `{}`",
                    path.to_string_lossy(),
                    filter
                ));
                break;
            }
        }
        for include in &self.includes {
            if Path::new(include).starts_with(path) {
                potentially_included = true;
                errors.push(format!(
                    "Including `{}` would result in including `{}` multiple times",
                    path.to_string_lossy(),
                    include
                ));
                break;
            }
        }

        match potentially_included {
            true => Err(errors.join("\n")),
            false => {
                self.includes.push(path.to_string_lossy().to_string());
                Ok(())
            }
        }
    }

    // Removes includes equal to the supplied one, returning number of removed includes
    pub fn remove_include(&mut self, path: &Path) -> Result<usize, String> {
        let len_before = self.includes.len();
        for i in (0..self.includes.len()).rev() {
            if Path::new(&self.includes[i]).eq(path) {
                self.includes.remove(i);
            }
        }
        let removed_includes = len_before - self.includes.len();
        // It should not be possible to add duplicates, so this should only ever remove 0 or 1 item
        assert!(removed_includes == 0 || removed_includes == 1);
        Ok(removed_includes)
    }

    pub fn get_includes(&self) -> &Vec<String> {
        &self.includes
    }

    pub fn get_filters(&self) -> &Vec<Pattern> {
        if !self.filters_validated {
            panic!("Attempt to use non-validated filters!");
        }
        &self.compiled_filters
    }

    // Removes filter equal to the supplied one, returning number of removed filters
    pub fn remove_filter(&mut self, filter: String) -> Result<usize, String> {
        let len_before = self.filters.len();
        for i in (0..self.filters.len()).rev() {
            if self.filters[i] == filter {
                self.filters.remove(i);
            }
        }
        let len_compiled_before = self.compiled_filters.len();
        for i in (0..self.compiled_filters.len()).rev() {
            if self.compiled_filters[i].as_str() == filter {
                self.compiled_filters.remove(i);
            }
        }
        let removed_filters = len_before - self.filters.len();
        let removed_compiled_filters = len_compiled_before - self.filters.len();
        // It should not be possible to add duplicates, so this should only ever remove 0 or 1 item
        assert!(removed_filters == 0 || removed_filters == 1);
        assert_eq!(removed_filters, removed_compiled_filters);
        Ok(removed_filters)
    }

    pub fn should_upload(&self, path: &Path) -> bool {
        if !self.filters_validated {
            panic!("Attempt to use non-validated filters!");
        }

        for filter in &self.compiled_filters {
            if filter.matches_path(path) {
                return false;
            }
        }
        true
    }
}
