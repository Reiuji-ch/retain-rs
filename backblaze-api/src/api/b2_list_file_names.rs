use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{ApiError, Auth};
use crate::api::b2_upload_file::B2File;

pub async fn b2_list_file_names(auth: Arc<RwLock<Option<Auth>>>, start_file_name: Option<String>) -> Result<FileList, ApiError> {
    crate::make_api_call(auth, Some(start_file_name), |auth,data|{ ListFileNamesData {
        bucket_id: auth.bucket_id.clone(),
        start_file_name: data,
        max_file_count: 1000,
    } }, "b2_list_file_names").await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListFileNamesData {
    pub bucket_id: String,
    pub start_file_name: Option<String>,
    pub max_file_count: u32,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FileList {
    pub files: Vec<B2File>,
    pub next_file_name: Option<String>,
}