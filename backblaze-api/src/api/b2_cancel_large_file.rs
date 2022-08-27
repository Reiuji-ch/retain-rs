use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{ApiError, Auth};

pub async fn b2_cancel_large_file(auth: Arc<RwLock<Option<Auth>>>, file_id: String,) -> Result<B2CancelledFile, ApiError> {
    crate::make_api_call(auth, Some(file_id), |_auth, data|{
        CancelLargeFileData {
            file_id: data
        }
    }, "b2_cancel_large_file").await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CancelLargeFileData {
    pub file_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct B2CancelledFile {
    pub file_id: String,
    pub file_name: String,
}