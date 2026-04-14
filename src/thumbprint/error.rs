#[derive(Debug, thiserror::Error)]
pub enum CoseKeyThumbprintError {
    #[error(transparent)]
    CoseKeyError(#[from] crate::CoseKeyError),
    #[error(transparent)]
    CiboriumValueError(#[from] ciborium::value::Error),
    #[error(transparent)]
    CborSerializationError(#[from] ciborium::ser::Error<std::io::Error>),
    #[error("Invalid CoseKey supplied")]
    InvalidCoseKey,
    #[error(transparent)]
    UnknownError(#[from] core::convert::Infallible),
    #[error(transparent)]
    InfallibleCborSerializationError(#[from] ciborium::ser::Error<std::convert::Infallible>),
}
