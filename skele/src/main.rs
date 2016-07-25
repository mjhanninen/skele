extern crate rpassword;
extern crate rustybones;
extern crate term;

use std::io;
use rustybones::*;

fn ask(prompt: &str, echo: bool) -> String {
    let mut t = term::stdout().unwrap();
    t.fg(term::color::YELLOW).unwrap();
    t.write(prompt.as_bytes()).unwrap();
    t.write("\n".as_bytes()).unwrap();
    t.fg(term::color::WHITE).unwrap();
    t.write("> ".as_bytes()).unwrap();
    t.flush().unwrap();
    let output = if echo {
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer).unwrap();
        // Discard newline
        buffer.pop();
        buffer
    } else {
        let result = rpassword::read_password()
            .or_else(|err| {
                match err.kind() {
                    io::ErrorKind::UnexpectedEof => Ok("".to_owned()),
                    _ => Err(err),
                }
            })
            .unwrap();
        if !result.is_empty() {
            // `rpassword` echoes the newline character. Therefore we
            // need to do a bit of trickery in order to display the
            // placeholder for entered text.
            t.cursor_up().unwrap();
            t.carriage_return().unwrap();
            t.delete_line().unwrap();
            t.write("> [secret]\n".as_bytes()).unwrap();
        }
        result
    };
    output
}

fn alert(message: &str) {
    let mut t = term::stdout().unwrap();
    t.fg(term::color::RED).unwrap();
    t.write("Error: ".as_bytes()).unwrap();
    t.fg(term::color::WHITE).unwrap();
    t.write(message.as_bytes()).unwrap();
    t.write("\n".as_bytes()).unwrap();
}

fn ask_skeleton_key() -> Option<String> {
    loop {
        let key = ask("Skeleton key?", false);
        if key.is_empty() {
            return None;
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
    t.write("Confirmed: ".as_bytes()).unwrap();
    t.reset().unwrap();
    t.write("The fingerprint of the skeleton key is ".as_bytes()).unwrap();
    t.attr(term::Attr::Bold).unwrap();
    t.write(fingerprint.as_bytes()).unwrap();
    t.reset().unwrap();
    t.write("\n".as_bytes()).unwrap();
}

fn show_key(ix: usize, key: &str) {
    let mut t = term::stdout().unwrap();
    t.fg(term::color::GREEN).unwrap();
    t.write(format!("{}: ", ix + 1).as_bytes()).unwrap();
    t.reset().unwrap();
    t.write(key.as_bytes()).unwrap();
    t.write("\n".as_bytes()).unwrap();
}

fn show_notice() {
    println!("Skele, version {}", env!("CARGO_PKG_VERSION"));
}

fn main() {
    show_notice();
    match ask_skeleton_key() {
        Some(skeleton_key) => {
            let key_source = KeySource::new(&skeleton_key);
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
        None => (),
    }
}
