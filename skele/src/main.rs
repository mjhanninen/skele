use rustybones::*;
use std::io;

fn ask(prompt: &str, echo: bool) -> String {
    let mut t = term::stdout().unwrap();
    t.fg(term::color::YELLOW).unwrap();
    writeln!(t, "{}", prompt).unwrap();
    t.fg(term::color::WHITE).unwrap();
    write!(t, "> ").unwrap();
    t.flush().unwrap();
    if echo {
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer).unwrap();
        // Discard newline
        buffer.pop();
        buffer
    } else {
        let result = rpassword::read_password()
            .or_else(|err| match err.kind() {
                io::ErrorKind::UnexpectedEof => Ok("".to_owned()),
                _ => Err(err),
            })
            .unwrap();
        if !result.is_empty() {
            // `rpassword` echoes the newline character. Therefore we
            // need to do a bit of trickery in order to display the
            // placeholder for entered text.
            t.cursor_up().unwrap();
            t.carriage_return().unwrap();
            t.delete_line().unwrap();
            writeln!(t, "> [secret]").unwrap();
        }
        result
    }
}

fn alert(message: &str) {
    let mut t = term::stdout().unwrap();
    t.fg(term::color::RED).unwrap();
    write!(t, "Error: ").unwrap();
    t.fg(term::color::WHITE).unwrap();
    write!(t, "{}", message).unwrap();
    writeln!(t).unwrap();
}

mod app_st {

    use std::collections::HashSet;
    use std::env;
    use std::fs::{self, File};
    use std::path::PathBuf;
    use std::result;

    // We pretty much ignore all errors. However we want to use `try!` so we
    // need a result type that too ignores all errors.
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
                    // This is an odd situation. Maybe the user should be
                    // notified about it.
                    None
                }
            } else if create {
                // Failing to create a dot directory is inconvenient but not
                // something that would make us halt the program. As we're not
                // going to react in any way just swallow the error.
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

    use serde::de::{MapAccess, Visitor};
    use serde::ser::SerializeMap;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl Serialize for State {
        fn serialize<S>(&self, serializer: S) -> result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut map_state = serializer.serialize_map(Some(self.fingerprints.len()))?;
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
        let temp_path = state_file_path(Some(format!("{}", std::process::id()))).ok_or(())?;
        let mut temp_file = File::create(&temp_path).or(Err(()))?;
        ser::to_writer(&mut temp_file, state).or(Err(()))?;
        let path = state_file_path(None).ok_or(())?;
        fs::rename(&temp_path, path).or(Err(()))?;
        Ok(())
    }
}

fn ask_skeleton_key(state: &mut app_st::State) -> Option<String> {
    loop {
        let key = ask("Skeleton key?", false);
        if key.is_empty() {
            return None;
        }
        let key_source = KeySource::new(&key);
        let fingerprint = format_key(&key_source.fingerprint(), 8);
        if state.is_known(&fingerprint) {
            return Some(key);
        }
        let confirmation = ask("Please re-enter the skeleton key to confirm", false);
        if key == confirmation {
            return Some(key);
        }
        alert("The confirmation didn't match the key. Please try again.");
    }
}

fn show_fingerprint(key_source: &KeySource) {
    let fingerprint = format_key(&key_source.fingerprint(), 8);
    let mut t = term::stdout().unwrap();
    t.fg(term::color::GREEN).unwrap();
    write!(t, "Confirmed: ").unwrap();
    t.reset().unwrap();
    write!(t, "The fingerprint of the skeleton key is ").unwrap();
    t.attr(term::Attr::Bold).unwrap();
    write!(t, "{}", fingerprint).unwrap();
    t.reset().unwrap();
    writeln!(t).unwrap();
}

fn show_key(ix: usize, key: &str) {
    let mut t = term::stdout().unwrap();
    t.fg(term::color::GREEN).unwrap();
    write!(t, "{}:", ix + 1).unwrap();
    t.reset().unwrap();
    writeln!(t, " {}", key).unwrap();
}

fn show_notice() {
    println!("Skele, version {}", env!("CARGO_PKG_VERSION"));
}

fn main() {
    show_notice();
    let mut app_state = app_st::load_app_state().unwrap_or(app_st::State::new());
    if let Some(skeleton_key) = ask_skeleton_key(&mut app_state) {
        let key_source = KeySource::new(&skeleton_key);
        let fingerprint = format_key(&key_source.fingerprint(), 8);
        app_state.learn_fingerprint(&fingerprint);
        app_st::save_app_state(&app_state).unwrap_or_else(|_| {
            println!("Warning: Failed to save application state\n");
        });
        show_fingerprint(&key_source);
        loop {
            let domain = ask("Domain?", true);
            if domain.is_empty() {
                break;
            }
            let identity = ask("Identity?", true);
            if identity.is_empty() {
                break;
            }
            for (ix, key) in key_source.keys(&domain, &identity).take(5).enumerate() {
                show_key(ix, &format_key(&key, 4));
            }
        }
    }
}
