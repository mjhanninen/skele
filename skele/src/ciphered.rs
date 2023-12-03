//! # Ciphered serializable container

use aes_gcm::{
  aead::{Aead, AeadCore},
  Aes256Gcm, KeyInit, Nonce,
};
use rand_core::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

use crate::serde_helpers::*;

#[derive(Debug, Error)]
pub enum Error {
  #[error("encryption or decryption operation failed")]
  CipherOpFailed,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Ciphered {
  // We support AES-GCM-256 only.  However, by including the algorithm
  // information in the format it is easier to extend to other algorithms in
  // backwards compatible manner (should we ever want to).
  alg: CipherAlgorithm,
  #[serde(serialize_with = "ser_octets", deserialize_with = "de_octet_array")]
  nonce: [u8; 12],
  #[serde(serialize_with = "ser_octets", deserialize_with = "de_octets")]
  ciphered: Box<[u8]>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
enum CipherAlgorithm {
  #[serde(rename = "AES-GCM-256")]
  #[default]
  AesGcm256,
}

type Aes256GcmNonce = Nonce<<Aes256Gcm as AeadCore>::NonceSize>;

fn aes_gcm(key: &[u8]) -> Aes256Gcm {
  let aes_gcm_key = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(key);
  Aes256Gcm::new(aes_gcm_key)
}

impl Ciphered {
  pub fn cipher<T>(value: T, key: &[u8]) -> Result<Self, Error>
  where
    T: Serialize,
  {
    let mut nonce = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let Ok(serialized_value) = serde_json::to_vec_pretty(&value) else {
      return Err(Error::CipherOpFailed);
    };
    let aes_gcm = aes_gcm(key);
    let aes_gcm_nonce = Aes256GcmNonce::from_slice(&nonce);
    let Ok(ciphered) =
      aes_gcm.encrypt(aes_gcm_nonce, serialized_value.as_ref())
    else {
      return Err(Error::CipherOpFailed);
    };
    Ok(Self {
      alg: CipherAlgorithm::AesGcm256,
      nonce,
      ciphered: ciphered.into(),
    })
  }

  pub fn decipher<T>(&self, key: &[u8]) -> Result<T, Error>
  where
    T: DeserializeOwned,
  {
    let aes_gcm = aes_gcm(key);
    let aes_gcm_nonce = Aes256GcmNonce::from_slice(&self.nonce);
    let Ok(serialized) = aes_gcm.decrypt(aes_gcm_nonce, self.ciphered.as_ref())
    else {
      return Err(Error::CipherOpFailed);
    };
    if let Ok(value) = serde_json::from_slice(serialized.as_slice()) {
      Ok(value)
    } else {
      Err(Error::CipherOpFailed)
    }
  }
}
