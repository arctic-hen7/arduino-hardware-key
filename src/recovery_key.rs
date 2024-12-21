use cryptosystem::{CryptoExport, CryptoImport, KeyExchangeCryptosystem, SecretKey};

/// A key for recovering the contents of a [`Vault`] if the passphrase, hardware key, or both are
/// lost or inaccessible. As this bypasses the two-factor encryption of the vault, its bytes should
/// be kept in a secure location.
///
/// This can be imported and exported to/from various formats using [`CryptoImport`] and
/// [`CryptoExport`] from the [`cryptosystem`] crate.
pub struct RecoveryKey<E: KeyExchangeCryptosystem> {
    pub(crate) inner: SecretKey<E>,
}
impl<E: KeyExchangeCryptosystem> CryptoImport for RecoveryKey<E> {
    type Error = E::IoError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: SecretKey::from_bytes(bytes)?,
        })
    }
}
impl<E: KeyExchangeCryptosystem> CryptoExport for RecoveryKey<E> {
    fn to_bytes(&self) -> &[u8] {
        self.inner.to_bytes()
    }
}
