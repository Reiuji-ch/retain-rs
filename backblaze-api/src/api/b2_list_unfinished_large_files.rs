use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{ApiError, Auth};
use crate::api::b2_upload_file::B2File;

// Technically paginated in the same way as b2_list_file_names/versions, but...
// There really shouldn't ever be 100+ unfinished large files, so we won't need a list_all helper
pub async fn b2_list_unfinished_large_files(auth: Arc<RwLock<Option<Auth>>>) -> Result<FileListById, ApiError> {
    crate::make_api_call(auth, Some(()), |auth, _data|{
        ListUnfinishedLargeFilesData {
            bucket_id: auth.bucket_id.clone(),
            max_file_count: 100
        }
    }, "b2_list_unfinished_large_files").await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListUnfinishedLargeFilesData {
    pub bucket_id: String,
    pub max_file_count: u16,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FileListById {
    pub files: Vec<B2File>,
    pub next_file_id: Option<String>,
}