//! # Application state

use std::{
  collections::HashMap,
  fs, io,
  path::{Path, PathBuf},
  result,
};

use directories_next::ProjectDirs;
use thiserror::Error;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
  #[error("io error")]
  Io(#[from] io::Error),
  #[error("cannot resolve state directory")]
  NoStateDir,
}

/// Ensures that the application state directory exists and returns the path
/// to it.
fn ensure_state_dir() -> Result<PathBuf> {
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
  pub fn try_new() -> Result<Self> {
    Ok(Self {
      state_dir: ensure_state_dir()?.into_boxed_path(),
    })
  }

  fn key_state_path(&self, fingerprint: &str) -> PathBuf {
    let mut path = PathBuf::from(self.state_dir.as_ref());
    path.push(format!("{}.keystate", fingerprint));
    path
  }

  pub fn learn_fingerprint(&self, fingerprint: &str) -> Result<()> {
    let path = self.key_state_path(fingerprint);
    let _ = fs::File::create(path)?;
    Ok(())
  }

  pub fn is_known(&self, fingerprint: &str) -> Result<bool> {
    let path = self.key_state_path(fingerprint);
    Ok(path.is_file())
  }
}

#[allow(dead_code)]
pub enum SkeletonKeyState {
  Locked {
    ciphered: Box<str>,
  },
  Unlocked {
    credentials: Vec<Credentials>,
    ciphered: Option<Box<str>>,
  },
}

#[allow(dead_code)]
pub struct Credentials {
  domain: Box<str>,
  identity: Box<str>,
}

#[allow(dead_code)]
pub struct NewState {
  pub fingerprints: HashMap<Box<str>, SkeletonKeyState>,
}
