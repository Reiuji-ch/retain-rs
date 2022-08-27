use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{ApiError, Auth};

pub async fn b2_get_upload_part_url(auth: Arc<RwLock<Option<Auth>>>, file_id: String) -> Result<UploadPartAuth, ApiError> {
    crate::make_api_call(auth, Some(file_id), |_auth, data|{
        GetUploadPartUrlData {
            file_id: data
        }
    }, "b2_get_upload_part_url").await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GetUploadPartUrlData {
    pub file_id: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UploadPartAuth {
    pub file_id: String,
    pub upload_url: String,
    pub authorization_token: String,
}