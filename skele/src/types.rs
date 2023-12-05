#[derive(Clone)]
#[repr(transparent)]
/// A secret passphrase entered by the user.  Never spill this or mix it with
/// anything else.
pub struct Passphrase(Box<str>);

impl Passphrase {
  pub fn as_str(&self) -> &str {
    &self.0
  }

  pub fn as_bytes(&self) -> &[u8] {
    self.0.as_bytes()
  }
}

impl<T> From<T> for Passphrase
where
  T: Into<Box<str>>,
{
  fn from(value: T) -> Self {
    Self(value.into())
  }
}
