mod b2_authorize_account;
mod b2_cancel_large_file;
mod b2_download_file_by_name;
mod b2_finish_large_file;
mod b2_get_upload_part_url;
mod b2_get_upload_url;
mod b2_hide_file;
mod b2_list_file_names;
mod b2_list_parts;
mod b2_list_unfinished_large_files;
mod b2_start_large_file;
mod b2_upload_file;
mod b2_upload_part;

use crate::api::b2_upload_file::B2File;
use crate::{ApiError, Auth};
pub use b2_authorize_account::b2_authorize_account;
pub use b2_cancel_large_file::b2_cancel_large_file;
pub use b2_download_file_by_name::b2_download_file_by_name;
pub use b2_finish_large_file::b2_finish_large_file;
pub use b2_get_upload_part_url::b2_get_upload_part_url;
pub use b2_get_upload_part_url::UploadPartAuth;
pub use b2_get_upload_url::b2_get_upload_url;
pub use b2_get_upload_url::UploadAuth;
pub use b2_hide_file::b2_hide_file;
pub use b2_list_file_names::b2_list_file_names;
pub use b2_list_parts::b2_list_parts;
pub use b2_list_unfinished_large_files::b2_list_unfinished_large_files;
pub use b2_start_large_file::b2_start_large_file;
pub use b2_upload_file::b2_upload_file;
pub use b2_upload_file::FileInfo;
pub use b2_upload_part::b2_upload_part;
pub use b2_upload_part::B2Part;
pub use b2_upload_part::PartInfo;
use std::sync::Arc;
use tokio::sync::RwLock;

// Helper to get all files by repeatedly calling b2_list_file_names
pub async fn list_all_file_names(
    auth: Arc<RwLock<Option<Auth>>>,
    start_file_name: Option<String>,
) -> Result<Vec<B2File>, ApiError> {
    let mut files = Vec::with_capacity(4096);
    let mut next_name = start_file_name;
    loop {
        let mut list = b2_list_file_names(auth.clone(), next_name).await?;
        files.append(&mut list.files);
        next_name = list.next_file_name;
        if next_name.is_none() {
            break;
        }
    }
    Ok(files)
}
