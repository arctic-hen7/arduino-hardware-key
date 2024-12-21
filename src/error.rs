use cryptosystem::{KeyExchangeCryptosystem, SymmetricCryptosystem};
use thiserror::Error;

/// Errors that can occur when working with a hardware key.
#[derive(Error, Debug)]
pub enum HardwareKeyError {
    #[error("failed to open port at '{port}'")]
    PortOpenFailed {
        port: String,
        #[source]
        source: serialport::Error,
    },
    #[error("failed to clone port")]
    PortCloneFailed(#[source] serialport::Error),
    #[error("failed to read from hardware key")]
    ReadFailed(#[source] std::io::Error),
    #[error("failed to write to hardware key")]
    WriteFailed(#[source] std::io::Error),
    #[error("device supposed to be a hardware key responded with incorrect identifier: '{id}'")]
    BadIdentifier { id: String },
    #[error("slot number {0} is past the maximum number of slots")]
    InvalidSlot(u8),
    #[error("attempted to generate challenge for slot that doesn't contain a key: {0}")]
    NoKeyInSlot(u8),
    #[error("unexpected error from hardware key: {0}")]
    UnknownError(String),
}

/// Errors that can occur in handling a vault.
#[derive(Error, Debug)]
pub enum VaultError<E: KeyExchangeCryptosystem + 'static, K: SymmetricCryptosystem + 'static> {
    #[error("failed to serialize data to bytes")]
    SerFailed(#[source] bincode::Error),
    #[error("failed to deserialize data from bytes")]
    DeserFailed(#[source] bincode::Error),
    #[error("failed to derive recovery key")]
    DeriveRecoverySharedSecretFailed(#[source] E::Error),
    #[error("failed to import recovery key (possible algorithm mismatch?)")]
    ImportRecoverySharedSecretFailed(#[source] K::IoError),
    #[error("failed to encrypt vault key")]
    EncryptVaultKeyFailed(#[source] K::Error),
    #[error("failed to decrypt vault key")]
    DecryptVaultKeyFailed(#[source] K::Error),
    #[error("failed to get response from hardware key")]
    ChallengeFailed(#[from] HardwareKeyError),
    #[error("failed to derive encryption key from passphrase and hardware key response: {0}")]
    DeriveEncryptionKeyFailed(argon2::Error),
    #[error("failed to import derived encryption key (possible algorithm mismatch?)")]
    ImportEncryptionKeyFailed(#[source] K::IoError),
    #[error("failed to import decrypted vault key (possible algorithm mismatch?)")]
    ImportVaultKeyFailed(#[source] K::IoError),
    #[error("failed to encrypt data")]
    EncryptFailed(#[source] K::Error),
    #[error("failed to decrypt data")]
    DecryptFailed(#[source] K::Error),
}
