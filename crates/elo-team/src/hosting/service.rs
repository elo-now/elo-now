//! Compatibility boundary: existing Spaces keep their legacy encrypted profile;
//! newly owner-managed Spaces hold public proofs and an HTTP response signer only.
use super::*;
use elo_core::{
    ids::{AttachmentId, RecordId},
    public_space::{
        AttachmentCleanupTarget, AttachmentStorageUsage, AttachmentTransferGrant,
        PublicSpaceService,
    },
};

pub(super) enum HostedService {
    Legacy(Box<ClientApp>),
    Public(Box<PublicSpaceService>),
}
macro_rules! read_method {
    ($name:ident ($($arg:ident : $ty:ty),*) -> $ret:ty) => {
        pub fn $name(&self, $($arg: $ty),*) -> Result<$ret> {
            match self { Self::Legacy(service) => service.$name($($arg),*), Self::Public(service) => service.$name($($arg),*) }
        }
    };
}
impl HostedService {
    pub fn witnessed_authority(&self) -> Result<Option<elo_core::authority::Authority>> {
        match self {
            Self::Public(service) => service.witnessed_authority(),
            Self::Legacy(_) => Ok(None),
        }
    }
    pub fn witnessed_request_authority(
        &self,
        request: &SpaceRequest,
    ) -> Result<elo_core::authority::Authority> {
        match self {
            Self::Public(service) => service.witnessed_request_authority(request),
            Self::Legacy(_) => Err("Witnessed Space required.".into()),
        }
    }
    pub async fn serve_hosted_witnessed_space(
        &mut self,
        config: &ServiceConfig,
        request: SpaceRequest,
        replica: &ReplicaStore,
        lease: &elo_core::witness::VerifiedFreshness,
    ) -> Result<SpaceResponse> {
        match self {
            Self::Public(service) => {
                service
                    .serve_hosted_witnessed_space(config, request, replica, lease)
                    .await
            }
            Self::Legacy(_) => Err("Witnessed Space required.".into()),
        }
    }
    read_method!(team_scope() -> elo_core::app::team::TeamScope);
    read_method!(set_attachment_storage_available(available: bool) -> ());
    read_method!(bootstrap_space_invitation(address: &SpaceAddress, approval: bool) -> String);
    read_method!(space_access_members() -> Vec<IdentityId>);
    read_method!(space_access_devices() -> Vec<RecordId>);
    read_method!(space_call_device_allowed(identity: IdentityId, credential: RecordId, scope: elo_core::calls::CallScope, head: RecordId) -> bool);
    read_method!(space_reservation_is_unused(now: u64) -> bool);
    read_method!(space_service_statistics() -> Value);
    read_method!(account_membership(config: &ServiceConfig, identity: IdentityId) -> Value);
    read_method!(authorize_space_deletion(config: &ServiceConfig, request: &SpaceRequest) -> Option<DeletionReceipt>);
    read_method!(attachment_mark_missing(id: AttachmentId) -> ());
    read_method!(attachment_upload_complete(token: &str, now: u64) -> ());
    read_method!(attachment_cleanup_complete(id: AttachmentId) -> ());
    read_method!(attachment_backup_inventory() -> Value);
    pub fn attachment_storage_usage(&self) -> Result<AttachmentStorageUsage> {
        match self {
            Self::Public(service) => service.attachment_storage_usage(),
            Self::Legacy(service) => {
                let usage = service.attachment_storage_usage()?;
                Ok(AttachmentStorageUsage {
                    used_bytes: usage.used_bytes,
                    reserved_bytes: usage.reserved_bytes,
                    files: usage.files,
                })
            }
        }
    }
    pub fn attachment_upload_grant(
        &self,
        token: &str,
        now: u64,
    ) -> Result<AttachmentTransferGrant> {
        match self {
            Self::Public(service) => service.attachment_upload_grant(token, now),
            Self::Legacy(service) => {
                let grant = service.attachment_upload_grant(token, now)?;
                Ok(AttachmentTransferGrant {
                    credential: grant.credential,
                    attachment_id: grant.attachment_id,
                    object_id: grant.object_id,
                    encrypted_size: grant.encrypted_size,
                    ciphertext_sha256: grant.ciphertext_sha256,
                })
            }
        }
    }
    pub fn attachment_download_grant(
        &self,
        token: &str,
        now: u64,
    ) -> Result<AttachmentTransferGrant> {
        match self {
            Self::Public(service) => service.attachment_download_grant(token, now),
            Self::Legacy(service) => {
                let grant = service.attachment_download_grant(token, now)?;
                Ok(AttachmentTransferGrant {
                    credential: grant.credential,
                    attachment_id: grant.attachment_id,
                    object_id: grant.object_id,
                    encrypted_size: grant.encrypted_size,
                    ciphertext_sha256: grant.ciphertext_sha256,
                })
            }
        }
    }
    pub fn attachment_all_targets(&self) -> Result<Vec<AttachmentCleanupTarget>> {
        match self {
            Self::Public(service) => service.attachment_all_targets(),
            Self::Legacy(service) => Ok(service
                .attachment_all_targets()?
                .into_iter()
                .map(|target| AttachmentCleanupTarget {
                    attachment_id: target.attachment_id,
                    object_id: target.object_id,
                })
                .collect()),
        }
    }
    pub fn attachment_cleanup_targets(
        &self,
        now: u64,
        limit: usize,
    ) -> Result<Vec<AttachmentCleanupTarget>> {
        match self {
            Self::Public(service) => service.attachment_cleanup_targets(now, limit),
            Self::Legacy(service) => Ok(service
                .attachment_cleanup_targets(now, limit)?
                .into_iter()
                .map(|target| AttachmentCleanupTarget {
                    attachment_id: target.attachment_id,
                    object_id: target.object_id,
                })
                .collect()),
        }
    }
    pub async fn serve_hosted_space(
        &mut self,
        config: &ServiceConfig,
        request: SpaceRequest,
        replica: &ReplicaStore,
    ) -> Result<SpaceResponse> {
        match self {
            Self::Legacy(service) => service.serve_hosted_space(config, request, replica).await,
            Self::Public(service) => service.serve_hosted_space(config, request, replica).await,
        }
    }
    pub fn validate_account_deletion(
        &self,
        config: &ServiceConfig,
        identity: IdentityId,
        evidence: Option<&elo_core::public_space::AdminEvidence>,
    ) -> Result<()> {
        match self {
            Self::Legacy(service) => {
                if service.account_membership(config, identity)?["primary"] == true {
                    return Err("Transfer primary ownership before deleting your account.".into());
                }
                Ok(())
            }
            Self::Public(service) => service.validate_account_deletion(config, identity, evidence),
        }
    }
    pub async fn erase_service_account(
        &mut self,
        config: &ServiceConfig,
        identity: IdentityId,
        evidence: Option<&elo_core::public_space::AdminEvidence>,
    ) -> Result<()> {
        match self {
            Self::Legacy(service) => service.erase_service_account(config, identity).await,
            Self::Public(service) => {
                service
                    .erase_service_account(config, identity, evidence)
                    .await
            }
        }
    }
    pub async fn deliver_team_memberships(&self) -> Result<()> {
        match self {
            Self::Legacy(service) => service.deliver_team_memberships().await,
            Self::Public(service) => service.deliver_team_memberships().await,
        }
    }
    pub async fn close(self) -> Result<()> {
        match self {
            Self::Legacy(service) => service.close().await,
            Self::Public(service) => service.close().await,
        }
    }
}
