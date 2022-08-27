use std::sync::Arc;
use crate::{ApiError, Auth};
use serde::Serialize;
use tokio::sync::RwLock;
use crate::api::b2_upload_file::B2File;

pub async fn b2_hide_file(auth: Arc<RwLock<Option<Auth>>>, file_name: String) -> Result<B2File, ApiError> {
    // data has to be Some, since we do want a body, but we can get all data needed from the auth
    crate::make_api_call(auth, Some(file_name), |auth , data|{ HideFileData {
        bucket_id: auth.bucket_id.clone(),
        file_name: data,
    } }, "b2_hide_file").await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HideFileData {
    pub bucket_id: String,
    pub file_name: String,
}