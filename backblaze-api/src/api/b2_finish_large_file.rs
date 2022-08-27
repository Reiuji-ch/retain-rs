use std::sync::Arc;

use serde::Serialize;
use tokio::sync::RwLock;

use crate::{ApiError, Auth};
use crate::api::b2_upload_file::B2File;

pub async fn b2_finish_large_file(auth: Arc<RwLock<Option<Auth>>>, file_id: String, part_hashes: Vec<String>) -> Result<B2File, ApiError> {
    crate::make_api_call(auth, Some((file_id, part_hashes)), |_auth, data|{
        FinishLargeFileData {
            file_id: data.0,
            part_sha1_array: data.1,
        }
    }, "b2_finish_large_file").await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FinishLargeFileData {
    pub file_id: String,
    pub part_sha1_array: Vec<String>,
}