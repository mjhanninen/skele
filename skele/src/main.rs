use std::cmp::Ordering;

use requestty::{prompt_one, ExpandItem, OnEsc, Question};
use requestty_utils::{answer, Answer};
use rustybones::*;

mod ciphered;
mod clipboard;
mod kdf;
mod serde_helpers;
mod state;
mod types;

use types::Passphrase;

// XXX(soija) Not a great name but will do for now.
struct KeyContainer {
  skeleton_key: Passphrase,
  #[allow(dead_code)]
  state: state::KeyState,
}

impl KeyContainer {
  pub fn new(skeleton_key: Passphrase, state: state::KeyState) -> Self {
    Self {
      skeleton_key,
      state,
    }
  }

  pub fn key_source(&self) -> KeySource {
    KeySource::new(self.skeleton_key.as_str())
  }
}

fn main() {
  run().unwrap()
}

fn run() -> anyhow::Result<()> {
  out::show_notice()?;
  let app_state = state::AppState::try_new()?;
  while let Some(mut key_container) = ask_skeleton_key(&app_state)? {
    if !domain_identity_loop(&app_state, &mut key_container)? {
      break;
    }
  }
  Ok(())
}

fn ask_skeleton_key(
  state: &state::AppState,
) -> Result<Option<KeyContainer>, state::Error> {
  loop {
    let skeleton_key_str = match answer::<String>(prompt_one(
      Question::password("key")
        .message("Skeleton key")
        .mask('*')
        .on_esc(OnEsc::Terminate),
    ))? {
      Answer::Value(value) => value,
      _ => return Ok(None),
    };

    if skeleton_key_str.is_empty() {
      out::warn("No key", "exiting")?;
      return Ok(None);
    }

    let skeleton_key: Passphrase = skeleton_key_str.into();

    let key_source = KeySource::new(skeleton_key.as_str());
    let fingerprint = format_key(&key_source.fingerprint(), 8);
    if state.is_known(&fingerprint)? {
      let key_state = state.load_key_state(&skeleton_key, &fingerprint)?;
      out::show_known_key_message(&fingerprint)?;
      return Ok(Some(KeyContainer::new(skeleton_key, key_state)));
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
        .validate_on_key(|confirmation, _| {
          skeleton_key.as_str().starts_with(confirmation)
        })
        .validate(|confirmation, _| {
          if skeleton_key.as_str() == confirmation {
            Ok(())
          } else if skeleton_key.as_str().starts_with(confirmation) {
            Err("The confirmation is too short".to_owned())
          } else if confirmation.starts_with(skeleton_key.as_str()) {
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
      assert!(skeleton_key.as_str() == confirmation);
      out::info("Key confirmed", "adding the key to the keyring")?;
      let key_state = state.init_key_state(&skeleton_key, &fingerprint)?;
      return Ok(Some(KeyContainer::new(skeleton_key, key_state)));
    }
  }
}

use requestty::question::completions;

fn domain_identity_loop(
  app_state: &state::AppState,
  key_container: &mut KeyContainer,
) -> Result<bool, state::Error> {
  loop {
    // This limits the scope of borrowing the credentials from the key state.

    let domain = match answer::<String>(prompt_one(
      Question::input("domain")
        .message("Domain")
        .validate_on_key(|input, _| !input.is_empty() && input.trim() == input)
        .validate(|input, _| {
          if input.trim() != input {
            Err("Domain cannot have leading or trailing whitespace".to_owned())
          } else if input.is_empty() {
            Err("Domain cannot be empty (press Esc to close key)".to_owned())
          } else {
            Ok(())
          }
        })
        .auto_complete(|partial, _| {
          struct Candidate {
            domain: Box<str>,
            total_count: u16,
          }
          let mut candidates = Vec::<Candidate>::new();
          for credentials in key_container.state.secret.credentials.iter() {
            if credentials.domain.starts_with(&partial) {
              if let Some(candidate) = candidates
                .iter_mut()
                .find(|candidate| candidate.domain == credentials.domain)
              {
                candidate.total_count += credentials.count;
              } else {
                candidates.push(Candidate {
                  domain: credentials.domain.clone(),
                  total_count: credentials.count,
                });
              }
            }
          }
          if !candidates.is_empty() {
            candidates.sort_by(|l, r| {
              // primary factor = descending in total count
              // secondary factor = ascending in domain
              match r.total_count.cmp(&l.total_count) {
                Ordering::Equal => l.domain.as_ref().cmp(&r.domain),
                ordering => ordering,
              }
            });
            return candidates
              .into_iter()
              .map(|candidate| candidate.domain.to_string())
              .collect();
          }
          completions![partial]
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
        .auto_complete(|partial, _| {
          struct Candidate {
            identity: Box<str>,
            count: u16,
          }
          let mut candidates = key_container
            .state
            .secret
            .credentials
            .iter()
            .filter_map(|credentials| {
              if credentials.domain.as_ref() == domain
                && credentials.identity.starts_with(&partial)
              {
                Some(Candidate {
                  identity: credentials.identity.clone(),
                  count: credentials.count,
                })
              } else {
                None
              }
            })
            .collect::<Vec<_>>();
          if !candidates.is_empty() {
            candidates.sort_by(|l, r| match r.count.cmp(&l.count) {
              // primary ordering = descending in count
              // secondary ordering = ascending in identity
              Ordering::Equal => l.identity.as_ref().cmp(&r.identity),
              ordering => ordering,
            });
            return candidates
              .into_iter()
              .map(|candidate| candidate.identity.to_string())
              .collect();
          }
          completions![partial]
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

    key_container.state.touch(&domain, &identity);
    app_state.save_key_state(&key_container.state)?;

    // XXX(soija) TOOD: Get rid of this legacy key source.
    let key_source = key_container.key_source();
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
