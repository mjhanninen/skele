#[cfg(target_os = "linux")]
mod inner {
  use wl_clipboard_rs::copy::{MimeType, Options, ServeRequests, Source};

  pub fn copy(key: &str) {
    let mut options = Options::new();
    options
      .foreground(true)
      .trim_newline(true)
      .serve_requests(ServeRequests::Only(1));
    options
      .copy(Source::Bytes(key.as_bytes().into()), MimeType::Text)
      .unwrap();
  }
}

#[cfg(target_os = "macos")]
mod inner {

  pub fn copy(key: &str) {
    let mut clipboard = arboard::Clipboard::new().unwrap();
    clipboard.set_text(key).unwrap();
  }
}

pub use inner::*;
