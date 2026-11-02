use std::sync::Arc;

use nosy_ca::CertificateAuthority;
use nosy_model::AppInfo;
use nosy_repeater::Repeater;
use nosy_store::Store;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub ca: Arc<CertificateAuthority>,
    pub repeater: Repeater,
    pub info: Arc<AppInfo>,
    /// Hosts accepted in the `Host` header (DNS-rebinding guard). Empty = any.
    pub allowed_hosts: Arc<Vec<String>>,
}
