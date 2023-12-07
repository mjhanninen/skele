//! # Application state

use std::{
  fs, io,
  path::{Path, PathBuf},
  process,
};

use directories_next::ProjectDirs;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ciphered, kdf, types::Passphrase};

#[derive(Debug, Error)]
pub enum Error {
  #[error("i/o error")]
  Io(#[from] io::Error),
  #[error("cannot resolve state directory")]
  NoStateDir,
  #[error("key derivation operation failed")]
  KdfOpFailed,
  #[error("cipher operation failed")]
  CipherOpFailed,
  #[error("failed to load skeleton key state")]
  LoadingKeyStateFailed,
  #[error("failed to save skeleton key state")]
  SavingKeyStateFailed,
}

impl From<kdf::Error> for Error {
  fn from(err: kdf::Error) -> Self {
    match err {
      kdf::Error::KdfOpFailed => Error::KdfOpFailed,
    }
  }
}

impl From<ciphered::Error> for Error {
  fn from(err: ciphered::Error) -> Self {
    match err {
      ciphered::Error::CipherOpFailed => Error::CipherOpFailed,
    }
  }
}

/// Ensures that the application state directory exists and returns the path
/// to it.
fn ensure_state_dir() -> Result<PathBuf, Error> {
  let project_dirs =
    ProjectDirs::from("com", "mjhanninen", "skele").ok_or(Error::NoStateDir)?;
  let dir = project_dirs.data_local_dir();
  if !dir.exists() {
    fs::create_dir_all(dir)?;
  }
  if dir.is_dir() {
    Ok(dir.to_owned())
  } else {
    Err(Error::NoStateDir)
  }
}

pub struct AppState {
  state_dir: Box<Path>,
}

impl AppState {
  pub fn try_new() -> Result<Self, Error> {
    Ok(Self {
      state_dir: ensure_state_dir()?.into_boxed_path(),
    })
  }

  pub fn init_key_state(
    &self,
    skeleton_key: &Passphrase,
    fingerprint: &str,
  ) -> Result<KeyState, Error> {
    let key_state = KeyState::new(skeleton_key, fingerprint)?;
    self.save_key_state(&key_state)?;
    Ok(key_state)
  }

  pub fn is_known(&self, fingerprint: &str) -> Result<bool, Error> {
    let path = self.key_state_path(fingerprint, false);
    Ok(path.is_file())
  }

  pub fn load_key_state(
    &self,
    skeleton_key: &Passphrase,
    fingerprint: &str,
  ) -> Result<KeyState, Error> {
    let path = self.key_state_path(fingerprint, false);
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(file);
    let Ok(encrypted) = serde_json::from_reader::<_, EncryptedKeyState>(reader)
    else {
      return Err(Error::LoadingKeyStateFailed);
    };
    let state = encrypted.decrypt(skeleton_key)?;
    Ok(state)
  }

  pub fn save_key_state(&self, key_state: &KeyState) -> Result<(), Error> {
    let temp_path = self.key_state_path(&key_state.public.fingerprint, true);
    {
      let encrypted = key_state.encrypt()?;
      let file = fs::File::create(&temp_path)?;
      if serde_json::to_writer_pretty(file, &encrypted).is_err() {
        return Err(Error::SavingKeyStateFailed);
      };
    }
    let final_path = self.key_state_path(&key_state.public.fingerprint, false);
    if fs::rename(&temp_path, final_path).is_err() {
      return Err(Error::SavingKeyStateFailed);
    }
    Ok(())
  }

  fn key_state_path(&self, fingerprint: &str, temporary: bool) -> PathBuf {
    let mut path = PathBuf::from(self.state_dir.as_ref());
    if temporary {
      path.push(format!("{}.json.{}", fingerprint, process::id()));
    } else {
      path.push(format!("{}.json", fingerprint));
    }
    path
  }
}

pub struct KeyState {
  pub key: [u8; 32],
  pub public: PublicKeyState,
  pub secret: SecretKeyState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKeyState {
  pub fingerprint: Box<str>,
  pub kdf: kdf::Kdf,
}

impl PublicKeyState {
  fn new(fingerprint: &str, kdf: kdf::Kdf) -> Self {
    Self {
      fingerprint: fingerprint.into(),
      kdf,
    }
  }
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct SecretKeyState {
  pub credentials: Vec<Credentials>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EncryptedKeyState {
  pub public: PublicKeyState,
  pub secret: ciphered::Ciphered,
}

impl KeyState {
  pub fn new(
    skeleton_key: &Passphrase,
    fingerprint: &str,
  ) -> Result<Self, Error> {
    let kdf = kdf::Kdf::default();
    let key = kdf.derive(skeleton_key)?;
    Ok(Self {
      key,
      public: PublicKeyState::new(fingerprint, kdf),
      secret: SecretKeyState::default(),
    })
  }

  pub fn encrypt(&self) -> Result<EncryptedKeyState, Error> {
    Ok(EncryptedKeyState {
      public: self.public.clone(),
      secret: ciphered::Ciphered::cipher(&self.secret, &self.key)?,
    })
  }

  /// Memorizes the given domain-identity pair.  Returns `true` iff the state
  /// did not know the pair already.
  pub fn touch(&mut self, domain: &str, identity: &str) {
    if let Some(c) =
      self.secret.credentials.iter_mut().find(|c| {
        c.domain.as_ref() == domain && c.identity.as_ref() == identity
      })
    {
      c.count += 1;
    } else {
      self.secret.credentials.push(Credentials {
        domain: domain.into(),
        identity: identity.into(),
        count: 1,
      });
    }
    self.secret.credentials.sort_by_cached_key(|c| c.count);
  }
}

impl EncryptedKeyState {
  pub fn decrypt(self, skeleton_key: &Passphrase) -> Result<KeyState, Error> {
    let key = self.public.kdf.derive(skeleton_key)?;
    Ok(KeyState {
      key,
      public: self.public,
      secret: self.secret.decipher(&key)?,
    })
  }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Credentials {
  pub domain: Box<str>,
  pub identity: Box<str>,
  pub count: u16,
}
