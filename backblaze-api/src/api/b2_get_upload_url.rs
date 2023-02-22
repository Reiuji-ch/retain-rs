use crate::{ApiError, Auth};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

pub async fn b2_get_upload_url(auth: Arc<RwLock<Option<Auth>>>) -> Result<UploadAuth, ApiError> {
    // data has to be Some, since we do want a body, but we can get all data needed from the auth
    crate::make_api_call(
        auth,
        Some(()),
        |auth, _| GetUploadUrlData {
            bucket_id: auth.bucket_id.clone(),
        },
        "b2_get_upload_url",
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GetUploadUrlData {
    pub bucket_id: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UploadAuth {
    pub bucket_id: String,
    pub upload_url: String,
    pub authorization_token: String,
}
