use base64ct::Encoding;
use serde::{Deserializer, Serializer};

pub fn ser_octets<T, S>(
  octets: T,
  serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
  S: Serializer,
  T: AsRef<[u8]>,
{
  serializer.serialize_str(&base64ct::Base64::encode_string(octets.as_ref()))
}

pub fn de_octets<'de, D>(
  deserializer: D,
) -> std::result::Result<Box<[u8]>, D::Error>
where
  D: Deserializer<'de>,
{
  use serde::de;

  struct OctetsVisitor {}

  impl<'de> de::Visitor<'de> for OctetsVisitor {
    type Value = Box<[u8]>;

    fn expecting(
      &self,
      formatter: &mut std::fmt::Formatter,
    ) -> std::fmt::Result {
      write!(formatter, "a base64 string")
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
      E: de::Error,
    {
      match base64ct::Base64::decode_vec(value) {
        Ok(octets) => Ok(octets.into()),
        Err(base64ct::Error::InvalidEncoding) => Err(E::invalid_value(
          de::Unexpected::Other("invalid base64 string"),
          &self,
        )),
        Err(base64ct::Error::InvalidLength) => Err(E::invalid_value(
          de::Unexpected::Other("base64 string of incorrect length"),
          &self,
        )),
      }
    }
  }

  deserializer.deserialize_str(OctetsVisitor {})
}

pub fn de_octet_array<'de, D, const N: usize>(
  deserializer: D,
) -> std::result::Result<[u8; N], D::Error>
where
  D: Deserializer<'de>,
{
  use std::marker::PhantomData;

  use serde::de;

  struct ArrayVisitor<const N: usize> {
    marker: PhantomData<[u8; N]>,
  }

  impl<'de, const N: usize> de::Visitor<'de> for ArrayVisitor<N> {
    type Value = [u8; N];

    fn expecting(
      &self,
      formatter: &mut std::fmt::Formatter,
    ) -> std::fmt::Result {
      write!(
        formatter,
        "a base64 string representing exactly {} octets",
        N
      )
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<[u8; N], E>
    where
      E: de::Error,
    {
      let mut octets = [0u8; N];
      match base64ct::Base64::decode(value, &mut octets) {
        Ok(_) => Ok(octets),
        Err(base64ct::Error::InvalidEncoding) => Err(E::invalid_value(
          de::Unexpected::Other("invalid base64 string"),
          &self,
        )),
        Err(base64ct::Error::InvalidLength) => Err(E::invalid_value(
          de::Unexpected::Other("base64 string of incorrect length"),
          &self,
        )),
      }
    }
  }

  deserializer.deserialize_str(ArrayVisitor::<N> {
    marker: PhantomData,
  })
}
