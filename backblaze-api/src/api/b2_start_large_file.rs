use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::RwLock;

use crate::{ApiError, Auth};
use crate::api::b2_upload_file::B2File;
use crate::api::FileInfo;

pub async fn b2_start_large_file(auth: Arc<RwLock<Option<Auth>>>, info: FileInfo, start_nonce: u128) -> Result<B2File, ApiError> {
    let mut file_info = HashMap::with_capacity(1);
    file_info.insert("src_last_modified_millis".to_string(), info.modified.to_string());
    file_info.insert("large_file_size".to_string(), info.size.to_string());
    file_info.insert("large_file_nonce".to_string(), start_nonce.to_string());
    let data = TransformerData {
        info,
        file_info
    };
    crate::make_api_call(auth, Some(data), |auth,data|{
        StartLargeFileData {
            bucket_id: auth.bucket_id.clone(),
            file_name: data.info.file_name,
            content_type: "application/octet-stream".to_string(),
            file_info: data.file_info,
        }
    }, "b2_start_large_file").await
}

struct TransformerData {
    pub info: FileInfo,
    pub file_info: HashMap<String, String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartLargeFileData {
    pub bucket_id: String,
    pub file_name: String,
    pub content_type: String,
    pub file_info: HashMap<String, String>,
}