#[derive(Debug, thiserror::Error)]
pub enum CoseKeySetError {
    #[error(transparent)]
    CoseKeyError(#[from] crate::CoseKeyError),
    #[error("Duplicate key")]
    DuplicateKey,
    #[error("PrivateKey in KeySet")]
    PrivateKey,
    #[error(transparent)]
    UnknownError(#[from] core::convert::Infallible),
}
