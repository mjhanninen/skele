use std::io;

use requestty::{prompt_one, ExpandItem, OnEsc, Question};
use requestty_utils::{answer, Answer};
use rustybones::*;

fn main() {
  run().unwrap()
}

fn run() -> io::Result<()> {
  out::show_notice()?;
  let mut app_state = app_st::load_app_state().unwrap_or(app_st::State::new());
  while let Some(skeleton_key) = ask_skeleton_key(&app_state)? {
    let key_source = KeySource::new(&skeleton_key);
    let fingerprint = format_key(&key_source.fingerprint(), 8);
    app_state.learn_fingerprint(&fingerprint);
    app_st::save_app_state(&app_state).unwrap_or_else(|_| {
      println!("Warning: Failed to save application state\n");
    });
    if !domain_identity_loop(&key_source)? {
      break;
    }
  }
  Ok(())
}

fn ask_skeleton_key(state: &app_st::State) -> io::Result<Option<String>> {
  loop {
    let key = match answer::<String>(prompt_one(
      Question::password("key")
        .message("Skeleton key")
        .mask('*')
        .on_esc(OnEsc::Terminate),
    ))? {
      Answer::Value(value) => value,
      _ => return Ok(None),
    };

    if key.is_empty() {
      out::warn("No key", "exiting")?;
      return Ok(None);
    }

    let key_source = KeySource::new(&key);
    let fingerprint = format_key(&key_source.fingerprint(), 8);
    if state.is_known(&fingerprint) {
      out::show_known_key_message(&fingerprint)?;
      return Ok(Some(key));
    }

    out::show_new_key_warning(&fingerprint)?;

    let should_confirm = match answer::<bool>(prompt_one(
      Question::confirm("should_confirm")
        .message("Do you want to confirm the key by re-entering it")
        .on_esc(OnEsc::Terminate),
    ))? {
      Answer::Value(v) => v,
      Answer::Interrupted => return Ok(None),
      _ => false,
    };

    if !should_confirm {
      continue;
    }

    let maybe_confirmation = match answer::<String>(prompt_one(
      Question::password("confirmation")
        .message("Re-enter key")
        .mask('*')
        .validate_on_key(|confirmation, _| key.starts_with(confirmation))
        .validate(|confirmation, _| {
          if key == confirmation {
            Ok(())
          } else if key.starts_with(confirmation) {
            Err("The confirmation is too short".to_owned())
          } else if confirmation.starts_with(&key) {
            Err("The confirmation is too long".to_owned())
          } else {
            Err("The confirmation does not match the key".to_owned())
          }
        })
        .on_esc(OnEsc::Terminate),
    ))? {
      Answer::Value(v) => Some(v),
      Answer::Aborted => None,
      _ => return Ok(None),
    };

    if let Some(confirmation) = maybe_confirmation {
      assert!(key == confirmation);
      out::info("Key confirmed", "adding the key to the keyring")?;
      return Ok(Some(key));
    }
  }
}

fn domain_identity_loop(key_source: &KeySource) -> io::Result<bool> {
  loop {
    let domain = match answer::<String>(prompt_one(
      Question::input("domain")
        .message("Domain")
        .validate_on_key(|input, _| !input.is_empty() && input.trim() == input)
        .validate(|input, _| {
          if input.trim() != input {
            Err("Domain cannot have leading or trailing whitespace".to_owned())
          } else if input.is_empty() {
            Err("Domain cannot be empty".to_owned())
          } else {
            Ok(())
          }
        })
        .on_esc(OnEsc::Terminate),
    ))? {
      Answer::Value(v) => v,
      Answer::Aborted => return Ok(true),
      _ => return Ok(false),
    };

    let identity = match answer::<String>(prompt_one(
      Question::input("identity")
        .message("Identity")
        .validate_on_key(|input, _| !input.is_empty() && input.trim() == input)
        .validate(|input, _| {
          if input.trim() != input {
            Err(
              "Identity cannot have leading or trailing whitespace".to_owned(),
            )
          } else if input.is_empty() {
            Err("Identity cannot be empty".to_owned())
          } else {
            Ok(())
          }
        })
        .on_esc(OnEsc::Terminate),
    ))? {
      Answer::Value(v) => v,
      Answer::Aborted => continue,
      _ => return Ok(false),
    };

    assert!(!identity.is_empty());

    enum Action {
      CopyToClipboard,
      Reveal,
    }

    let action = match answer::<ExpandItem>(prompt_one(
      Question::expand("action")
        .message("Action")
        .choices([('c', "Copy to clipboard"), ('r', "Reveal")])
        .default('c')
        .on_esc(OnEsc::Terminate),
    ))? {
      Answer::Value(ExpandItem { key, .. }) => match key {
        'c' => Action::CopyToClipboard,
        'r' => Action::Reveal,
        _ => unreachable!(),
      },
      Answer::Aborted => continue,
      _ => return Ok(false),
    };

    match action {
      Action::CopyToClipboard => {
        if let Some(key) = key_source.keys(&domain, &identity).next() {
          clipboard::copy(&format_key(&key, 4));
        } else {
          unreachable!()
        }
      }
      Action::Reveal => {
        for (ix, key) in key_source.keys(&domain, &identity).take(5).enumerate()
        {
          out::show_key(ix, &format_key(&key, 4))?;
        }
      }
    }
  }
}

//
// Output helpers
//

mod out {

  use std::io::{self, stdout};

  use crossterm::{
    style::{
      Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor,
    },
    ExecutableCommand,
  };

  pub fn blurp(
    color: Color,
    symbol: char,
    heading: &str,
    message: &str,
  ) -> io::Result<()> {
    stdout()
      .execute(SetForegroundColor(color))?
      .execute(Print(symbol))?
      .execute(ResetColor)?
      .execute(Print(" "))?
      .execute(SetAttribute(Attribute::Bold))?
      .execute(Print(format!("{}:", heading)))?
      .execute(SetAttribute(Attribute::Reset))?
      .execute(Print(format!(" {}\n", message)))?;
    Ok(())
  }

  pub fn info(heading: &str, message: &str) -> io::Result<()> {
    blurp(Color::Green, '|', heading, message)
  }

  pub fn warn(heading: &str, message: &str) -> io::Result<()> {
    blurp(Color::Yellow, '|', heading, message)
  }

  pub fn show_new_key_warning(fingerprint: &str) -> io::Result<()> {
    stdout()
      .execute(SetForegroundColor(Color::Yellow))?
      .execute(Print('|'))?
      .execute(ResetColor)?
      .execute(Print(" "))?
      .execute(SetAttribute(Attribute::Bold))?
      .execute(Print("New key:"))?
      .execute(SetAttribute(Attribute::Reset))?
      .execute(Print(" with unknown fingerprint "))?
      .execute(SetAttribute(Attribute::Bold))?
      .execute(Print(fingerprint))?
      .execute(SetAttribute(Attribute::Reset))?
      .execute(Print("\n"))?;
    Ok(())
  }

  pub fn show_known_key_message(fingerprint: &str) -> io::Result<()> {
    stdout()
      .execute(SetForegroundColor(Color::Green))?
      .execute(Print('|'))?
      .execute(ResetColor)?
      .execute(Print(" "))?
      .execute(SetAttribute(Attribute::Bold))?
      .execute(Print("Known key:"))?
      .execute(SetAttribute(Attribute::Reset))?
      .execute(Print(" with fingerprint "))?
      .execute(SetAttribute(Attribute::Bold))?
      .execute(Print(fingerprint))?
      .execute(SetAttribute(Attribute::Reset))?
      .execute(Print("\n"))?;
    Ok(())
  }

  pub fn show_key(ix: usize, key: &str) -> io::Result<()> {
    stdout()
      .execute(SetForegroundColor(Color::Green))?
      .execute(Print('|'))?
      .execute(ResetColor)?
      .execute(Print(" "))?
      .execute(SetAttribute(Attribute::Bold))?
      .execute(Print(format!("{}:", ix)))?
      .execute(SetAttribute(Attribute::Reset))?
      .execute(Print(format!(" {}\n", key)))?;
    Ok(())
  }

  pub fn show_notice() -> io::Result<()> {
    info("Skele", &format!("version {}", env!("CARGO_PKG_VERSION")))
  }
}

//
// Clipboard helpers
//

#[cfg(target_os = "linux")]
mod clipboard {
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
mod clipboard {

  pub fn copy(key: &str) {
    let mut clipboard = arboard::Clipboard::new().unwrap();
    clipboard.set_text(key).unwrap();
  }
}

//
// Application state
//

mod app_st {

  use std::{
    collections::HashSet,
    env,
    fs::{self, File},
    path::PathBuf,
    result,
  };

  // We pretty much ignore all errors. However we want to use `try!` so we need
  // a result type that too ignores all errors.
  pub type Result<T> = result::Result<T, ()>;

  pub fn dot_dir(create: bool) -> Option<PathBuf> {
    // XXX(soija) TODO: Replace `home_dir` with something else
    #[allow(deprecated)]
    env::home_dir().and_then(|mut path| {
      path.push(".skele");
      if path.exists() {
        if path.is_dir() {
          Some(path)
        } else {
          // This is an odd situation. Maybe the user should be notified about
          // it.
          None
        }
      } else if create {
        // Failing to create a dot directory is inconvenient but not something
        // that would make us halt the program. As we're not going to react in
        // any way just swallow the error.
        fs::create_dir(&path).ok().and(Some(path))
      } else {
        None
      }
    })
  }

  fn ensure_dot_dir() -> Result<()> {
    dot_dir(true).map(|_| ()).ok_or(())
  }

  #[derive(Debug)]
  pub struct State {
    pub fingerprints: HashSet<String>,
  }

  impl State {
    pub fn new() -> Self {
      State {
        fingerprints: HashSet::new(),
      }
    }

    pub fn learn_fingerprint(&mut self, fingerprint: &str) {
      self.fingerprints.insert(fingerprint.to_owned());
    }

    pub fn is_known(&self, fingerprint: &str) -> bool {
      self.fingerprints.contains(fingerprint)
    }
  }

  use serde::{
    de::{MapAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
  };

  impl Serialize for State {
    fn serialize<S>(&self, serializer: S) -> result::Result<S::Ok, S::Error>
    where
      S: Serializer,
    {
      let mut map_state =
        serializer.serialize_map(Some(self.fingerprints.len()))?;
      for k in &self.fingerprints {
        map_state.serialize_entry(k, "")?;
      }
      map_state.end()
    }
  }

  struct StateVisitor;

  impl<'de> Visitor<'de> for StateVisitor {
    type Value = State;
    fn expecting(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
      fmt.write_str("a map with string values")
    }
    fn visit_map<M: MapAccess<'de>>(
      self,
      mut access: M,
    ) -> result::Result<Self::Value, M::Error> {
      let mut fingerprints = HashSet::new();
      while let Some((k, _)) = access.next_entry::<String, String>()? {
        fingerprints.insert(k);
      }
      Ok(State { fingerprints })
    }
  }

  impl<'de> Deserialize<'de> for State {
    fn deserialize<D>(deserializer: D) -> result::Result<Self, D::Error>
    where
      D: Deserializer<'de>,
    {
      deserializer.deserialize_map(StateVisitor)
    }
  }

  fn state_file_path(decoration: Option<String>) -> Option<PathBuf> {
    dot_dir(false).map(|mut path| {
      let filename = match decoration {
        Some(ref decoration) => format!("state.{}.json", decoration),
        None => "state.json".to_owned(),
      };
      path.push(filename);
      path
    })
  }

  use serde_json::{de, ser};

  fn load_app_state_(path: &PathBuf) -> Result<State> {
    let state_file = File::open(path).or(Err(()))?;
    de::from_reader(state_file).or(Err(()))
  }

  pub fn load_app_state() -> Option<State> {
    state_file_path(None)
      .and_then(|path| if path.is_file() { Some(path) } else { None })
      .and_then(|path| load_app_state_(&path).ok())
  }

  pub fn save_app_state(state: &State) -> Result<()> {
    ensure_dot_dir()?;
    let temp_path =
      state_file_path(Some(format!("{}", std::process::id()))).ok_or(())?;
    let mut temp_file = File::create(&temp_path).or(Err(()))?;
    ser::to_writer(&mut temp_file, state).or(Err(()))?;
    let path = state_file_path(None).ok_or(())?;
    fs::rename(&temp_path, path).or(Err(()))?;
    Ok(())
  }
}

mod requestty_utils {

  use std::{convert::TryFrom, io};

  pub enum Answer<T> {
    Value(T),
    Interrupted,
    Eof,
    Aborted,
  }

  impl From<requestty::Answer> for Answer<String> {
    fn from(answer: requestty::Answer) -> Self {
      if let Ok(value) = answer.try_into_string() {
        Answer::Value(value)
      } else {
        panic!("illegal answer type");
      }
    }
  }

  impl From<requestty::Answer> for Answer<bool> {
    fn from(answer: requestty::Answer) -> Self {
      if let Ok(value) = answer.try_into_bool() {
        Answer::Value(value)
      } else {
        panic!("illegal answer type");
      }
    }
  }

  impl From<requestty::Answer> for Answer<requestty::ExpandItem> {
    fn from(answer: requestty::Answer) -> Self {
      if let requestty::Answer::ExpandItem(value) = answer {
        Answer::Value(value)
      } else {
        panic!("illegal answer type");
      }
    }
  }

  impl<T> TryFrom<requestty::Result<requestty::Answer>> for Answer<T>
  where
    Answer<T>: From<requestty::Answer>,
  {
    type Error = io::Error;

    fn try_from(
      value: requestty::Result<requestty::Answer>,
    ) -> io::Result<Self> {
      use requestty::ErrorKind::*;
      match value {
        Ok(answer) => Ok(answer.into()),
        Err(IoError(err)) => Err(err),
        Err(Interrupted) => Ok(Answer::Interrupted),
        Err(Eof) => Ok(Answer::Eof),
        Err(Aborted) => Ok(Answer::Aborted),
      }
    }
  }

  pub fn answer<T>(
    result: requestty::Result<requestty::Answer>,
  ) -> io::Result<Answer<T>>
  where
    Answer<T>: TryFrom<requestty::Result<requestty::Answer>, Error = io::Error>,
  {
    result.try_into()
  }
}
