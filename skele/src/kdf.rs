use rand_core::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::serde_helpers::*;

#[derive(Debug, Error)]
pub enum Error {
  #[error("key derivation operation failed")]
  KdfOpFailed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Kdf {
  #[serde(serialize_with = "ser_alg", deserialize_with = "de_alg")]
  pub alg: argon2::Algorithm,
  #[serde(serialize_with = "ser_ver", deserialize_with = "de_ver")]
  pub ver: argon2::Version,
  pub m_cost: u32,
  pub t_cost: u32,
  pub p_cost: u32,
  #[serde(serialize_with = "ser_octets", deserialize_with = "de_octet_array")]
  pub salt: [u8; 32],
}

impl Default for Kdf {
  fn default() -> Self {
    let mut salt = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut salt);
    Self {
      alg: argon2::Algorithm::Argon2id,
      ver: argon2::Version::V0x13,
      m_cost: argon2::Params::DEFAULT_M_COST,
      t_cost: argon2::Params::DEFAULT_T_COST,
      p_cost: argon2::Params::DEFAULT_P_COST,
      salt,
    }
  }
}

impl Kdf {
  fn argon2(&self) -> Result<argon2::Argon2, Error> {
    if let Ok(params) =
      argon2::Params::new(self.m_cost, self.t_cost, self.p_cost, Some(32))
    {
      Ok(argon2::Argon2::new(self.alg, self.ver, params))
    } else {
      Err(Error::KdfOpFailed)
    }
  }

  pub fn derive(&self, passphrase: &str) -> Result<[u8; 32], Error> {
    let mut key = [0u8; 32];
    if self
      .argon2()?
      .hash_password_into(passphrase.as_bytes(), &self.salt, &mut key)
      .is_ok()
    {
      Ok(key)
    } else {
      Err(Error::KdfOpFailed)
    }
  }
}

fn ser_alg<S>(
  alg: &argon2::Algorithm,
  serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
  S: Serializer,
{
  use argon2::Algorithm::*;
  serializer.serialize_str(match alg {
    Argon2d => "Argon2d",
    Argon2i => "Argon2i",
    Argon2id => "Argon2id",
  })
}

fn de_alg<'de, D>(
  deserializer: D,
) -> std::result::Result<argon2::Algorithm, D::Error>
where
  D: Deserializer<'de>,
{
  use serde::de;

  struct AlgVisitor {}

  impl<'de> de::Visitor<'de> for AlgVisitor {
    type Value = argon2::Algorithm;

    fn expecting(
      &self,
      formatter: &mut std::fmt::Formatter,
    ) -> std::fmt::Result {
      write!(
        formatter,
        "one of \"Argon2d\", \"Argon2i\", or \"Argon2id\""
      )
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
      E: de::Error,
    {
      use argon2::Algorithm::*;
      Ok(match value {
        "Argon2d" => Argon2d,
        "Argon2i" => Argon2i,
        "Argon2id" => Argon2id,
        _ => {
          return Err(de::Error::invalid_value(
            de::Unexpected::Str(value),
            &"one of \"Argon2d\", \"Argon2i\", or \"Argon2id\"",
          ))
        }
      })
    }
  }

  deserializer.deserialize_str(AlgVisitor {})
}

fn ser_ver<S>(
  ver: &argon2::Version,
  serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
  S: Serializer,
{
  use argon2::Version::*;
  serializer.serialize_str(match ver {
    V0x10 => "0x10",
    V0x13 => "0x13",
  })
}

fn de_ver<'de, D>(
  deserializer: D,
) -> std::result::Result<argon2::Version, D::Error>
where
  D: Deserializer<'de>,
{
  use serde::de;

  struct VersionVisitor {}

  impl<'de> de::Visitor<'de> for VersionVisitor {
    type Value = argon2::Version;

    fn expecting(
      &self,
      formatter: &mut std::fmt::Formatter,
    ) -> std::fmt::Result {
      write!(formatter, "one of \"0x10\", or \"0x13\"")
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
      E: de::Error,
    {
      use argon2::Version::*;
      Ok(match value {
        "0x10" => V0x10,
        "0x13" => V0x13,
        _ => {
          return Err(de::Error::invalid_value(
            de::Unexpected::Str(value),
            &"one of \"0x10\", or \"0x13\"",
          ))
        }
      })
    }
  }

  deserializer.deserialize_str(VersionVisitor {})
}
