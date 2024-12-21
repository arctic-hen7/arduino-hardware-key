use crate::{error::VaultError, hardware_key::HardwareKey, recovery_key::RecoveryKey};
use argon2::Argon2;
use cryptosystem::{
    Ciphertext, CryptoExport, CryptoImport, KeyExchangeCryptosystem, PublicKey, SecretKey,
    SymmetricCryptosystem, SymmetricKey,
};
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

/// A container for data encrypted with both a passphrase and a hardware key, with a secondary
/// recovery key that can be used in place of both.
pub struct Vault<E: KeyExchangeCryptosystem, K: SymmetricCryptosystem> {
    /// The actual ciphertext of what's in the vault.
    ciphertext: Ciphertext,
    /// The symmetric key used to encrypt the vault's contents, encrypted with a key derived from
    /// the passphrase and hardware key's challenge-response.
    key_by_regular: Ciphertext,
    /// The symmetric key used to encrypt the vault's contents, encrypted with a key derived from
    /// the recovery key using Diffie-Hellman.
    key_by_recovery: Ciphertext,
    /// The challenge to be sent to the hardware key to derive the key that encrypts the vault key.
    challenge: [u8; 32],

    /// An ephemeral public key, regenerated every time we re-encrypt, which is used to derive a
    /// shared secret with the recovery keypair for encrypting the vault key. The corresponding
    /// ephemeral secret key is immediately discarded.
    ephemeral_public_key: PublicKey<E>,
    /// The public key of the recovery keypair, which can be used to derive a shared secret used
    /// for encrypting the vault key.
    ///
    /// This is the only thing that will remain the same between re-encryptions.
    recovery_public_key: PublicKey<E>,

    _phantom: PhantomData<K>,
}
impl<E: KeyExchangeCryptosystem, K: SymmetricCryptosystem> Vault<E, K> {
    /// Creates a new vault containing the given data, encrypted with the given passphrase and
    /// hardware key.
    pub fn new<T: Serialize>(
        data: &T,
        passphrase: &str,
        hkey: &mut HardwareKey,
    ) -> Result<(Self, RecoveryKey<E>), VaultError<E, K>> {
        let data_bytes = bincode::serialize(data).map_err(VaultError::SerFailed)?;
        Self::new_bytes(&data_bytes, passphrase, hkey)
    }

    /// Same as [`Self::new`], but operating on bytes instead of serializable data.
    pub fn new_bytes(
        data: &[u8],
        passphrase: &str,
        hkey: &mut HardwareKey,
    ) -> Result<(Self, RecoveryKey<E>), VaultError<E, K>> {
        // Generate a long-term recovery keypair
        let (recovery_public_key, recovery_secret_key) = SecretKey::generate_keypair();
        // This contains entirely temporary values
        let mut this = Self {
            ciphertext: Ciphertext::from_bytes(&[]).unwrap(),
            key_by_regular: Ciphertext::from_bytes(&[]).unwrap(),
            key_by_recovery: Ciphertext::from_bytes(&[]).unwrap(),
            challenge: [0u8; 32],
            ephemeral_public_key: recovery_public_key.clone(),
            recovery_public_key,
            _phantom: PhantomData,
        };
        this.encrypt_bytes(data, passphrase, hkey)?;
        Ok((
            this,
            RecoveryKey {
                inner: recovery_secret_key,
            },
        ))
    }

    /// Decrypts the contents of this vault, returning the deserialized plaintext.
    ///
    /// This will automatically generate new keys and re-encrypt the vault. You can use
    /// [`Self::decrypt_in_place`] to avoid this.
    pub fn decrypt<T: for<'de> Deserialize<'de>>(
        &mut self,
        passphrase: &str,
        hkey: &mut HardwareKey,
    ) -> Result<T, VaultError<E, K>> {
        let plaintext_bytes = self.decrypt_backend(Decryptor::Normal {
            passphrase: passphrase.to_string(),
            hardware_key: hkey,
        })?;
        self.encrypt_bytes(&plaintext_bytes, passphrase, hkey)?;
        let plaintext = bincode::deserialize(&plaintext_bytes).map_err(VaultError::DeserFailed)?;

        Ok(plaintext)
    }

    /// Same as [`Self::decrypt`], but operating on bytes instead of deserializable data.
    pub fn decrypt_bytes(
        &mut self,
        passphrase: &str,
        hkey: &mut HardwareKey,
    ) -> Result<Vec<u8>, VaultError<E, K>> {
        let plaintext_bytes = self.decrypt_backend(Decryptor::Normal {
            passphrase: passphrase.to_string(),
            hardware_key: hkey,
        })?;
        self.encrypt_bytes(&plaintext_bytes, passphrase, hkey)?;

        Ok(plaintext_bytes)
    }

    /// Decrypts the contents of this vault in-place, returning the deserialized plaintext. This
    /// will avoid re-encrypting the vault with new keys.
    ///
    /// **Warning:** unless you know what you're doing, you should always use [`Self::decrypt`]
    /// instead, as it re-encrypts the vault with new keys. Re-using the same hardware key response
    /// may be insecure.
    pub fn decrypt_in_place<T: for<'de> Deserialize<'de>>(
        &self,
        passphrase: &str,
        hkey: &mut HardwareKey,
    ) -> Result<T, VaultError<E, K>> {
        let plaintext_bytes = self.decrypt_backend(Decryptor::Normal {
            passphrase: passphrase.to_string(),
            hardware_key: hkey,
        })?;
        let plaintext = bincode::deserialize(&plaintext_bytes).map_err(VaultError::DeserFailed)?;

        Ok(plaintext)
    }

    /// Same as [`Self::decrypt_in_place`], but operating on bytes instead of deserializable data.
    pub fn decrypt_bytes_in_place(
        &self,
        passphrase: &str,
        hkey: &mut HardwareKey,
    ) -> Result<Vec<u8>, VaultError<E, K>> {
        let plaintext_bytes = self.decrypt_backend(Decryptor::Normal {
            passphrase: passphrase.to_string(),
            hardware_key: hkey,
        })?;

        Ok(plaintext_bytes)
    }

    /// Recovers the contents of this vault using the given recovery key. This will *not*
    /// re-encrypt the vault, as this is designed to be used when a hardware key is inaccessible.
    /// After a vault has been decrypted like this, it should ideally be discarded and re-created.
    pub fn recover<T: for<'de> Deserialize<'de>>(
        &self,
        recovery_key: RecoveryKey<E>,
    ) -> Result<T, VaultError<E, K>> {
        let plaintext_bytes = self.decrypt_backend(Decryptor::Recovery(recovery_key))?;
        let plaintext = bincode::deserialize(&plaintext_bytes).map_err(VaultError::DeserFailed)?;

        Ok(plaintext)
    }

    /// Same as [`Self::recover`], but operating on bytes instead of deserializable data.
    pub fn recover_bytes(&self, recovery_key: RecoveryKey<E>) -> Result<Vec<u8>, VaultError<E, K>> {
        let plaintext_bytes = self.decrypt_backend(Decryptor::Recovery(recovery_key))?;

        Ok(plaintext_bytes)
    }

    /// Manually encrypts the given data in this vault. This will generate new keys and overwrite
    /// the existing contents of the vault. This can be used to update the inner data, and/or
    /// passphrase, and/or hardware security key.
    pub fn encrypt<T: Serialize>(
        &mut self,
        data: &T,
        passphrase: &str,
        hkey: &mut HardwareKey,
    ) -> Result<(), VaultError<E, K>> {
        let data_bytes = bincode::serialize(data).map_err(VaultError::SerFailed)?;
        self.encrypt_bytes(&data_bytes, passphrase, hkey)
    }

    /// Same as [`Self::encrypt`], but operating on bytes instead of serializable data.
    pub fn encrypt_bytes(
        &mut self,
        data: &[u8],
        passphrase: &str,
        hkey: &mut HardwareKey,
    ) -> Result<(), VaultError<E, K>> {
        // Generate a new vault key
        let vault_key = SymmetricKey::<K>::generate();
        self.ciphertext = vault_key
            .encrypt_bytes(data)
            .map_err(VaultError::EncryptFailed)?;

        // Generate a new challenge and derive the regular key
        self.challenge = OsRng.gen();
        let regular_key = self.derive_regular_key(passphrase, hkey)?;
        self.key_by_regular = regular_key
            .encrypt_bytes(&vault_key.to_bytes())
            .map_err(VaultError::EncryptVaultKeyFailed)?;

        // Generate a new ephemeral keypair and derive the recovery key
        let (ephemeral_public, ephemeral_secret) = SecretKey::generate_keypair();
        self.ephemeral_public_key = ephemeral_public;
        let recovery_symmetric_key = SymmetricKey::<K>::from_bytes(
            &ephemeral_secret
                .generate_shared_secret(&self.recovery_public_key)
                .map_err(VaultError::DeriveRecoverySharedSecretFailed)?
                .to_bytes(),
        )
        .map_err(VaultError::ImportRecoverySharedSecretFailed)?;
        self.key_by_recovery = recovery_symmetric_key
            .encrypt_bytes(&vault_key.to_bytes())
            .map_err(VaultError::EncryptVaultKeyFailed)?;

        Ok(())
    }

    fn decrypt_backend(&self, decryptor: Decryptor<'_, E>) -> Result<Vec<u8>, VaultError<E, K>> {
        let vault_key_bytes = match decryptor {
            Decryptor::Normal {
                passphrase,
                hardware_key: hkey,
            } => {
                // We have a passphrase and hardware key, use the challenge we've recorded to get a
                // response and derive a key from that and the passphrase
                let regular_symmetric_key = self.derive_regular_key(&passphrase, hkey)?;
                regular_symmetric_key
                    .decrypt_bytes(&self.key_by_regular)
                    .map_err(VaultError::DecryptVaultKeyFailed)?
            }
            Decryptor::Recovery(recovery_key) => {
                // We have a recovery key, use it to derive a key for decrypting the vault key
                let recovery_symmetric_key = SymmetricKey::<K>::from_bytes(
                    &recovery_key
                        .inner
                        .generate_shared_secret(&self.ephemeral_public_key)
                        .map_err(VaultError::DeriveRecoverySharedSecretFailed)?
                        .to_bytes(),
                )
                .map_err(VaultError::ImportRecoverySharedSecretFailed)?;
                recovery_symmetric_key
                    .decrypt_bytes(&self.key_by_recovery)
                    .map_err(VaultError::DecryptVaultKeyFailed)?
            }
        };
        let vault_key = SymmetricKey::<K>::from_bytes(&vault_key_bytes)
            .map_err(VaultError::ImportVaultKeyFailed)?;
        vault_key
            .decrypt_bytes(&self.ciphertext)
            .map_err(VaultError::DecryptFailed)
    }

    fn derive_regular_key(
        &self,
        passphrase: &str,
        hkey: &mut HardwareKey,
    ) -> Result<SymmetricKey<K>, VaultError<E, K>> {
        let response = hkey.challenge("test")?;
        let mut regular_symmetric_key_bytes = [0u8; 32];
        Argon2::default()
            .hash_password_into(
                passphrase.as_bytes(),
                response.as_bytes(),
                &mut regular_symmetric_key_bytes,
            )
            .map_err(VaultError::DeriveEncryptionKeyFailed)?;
        SymmetricKey::from_bytes(&regular_symmetric_key_bytes)
            .map_err(VaultError::ImportEncryptionKeyFailed)
    }
}

enum Decryptor<'k, E: KeyExchangeCryptosystem> {
    Normal {
        passphrase: String,
        hardware_key: &'k mut HardwareKey,
    },
    Recovery(RecoveryKey<E>),
}
