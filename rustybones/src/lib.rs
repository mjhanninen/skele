// #![no_std]

extern crate crypto;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::vec::Vec;
// use std::slice::SliceConcatExt;

pub const PREPARED_SKELETON_KEY_SIZE: usize = 32;

pub fn prepare_skeleton_key(plain_text: &str, prepared_key: &mut [u8]) -> Result<(), ()> {
    if prepared_key.len() != PREPARED_SKELETON_KEY_SIZE {
        Err(())
    } else {
        let mut hasher = Sha256::new();
        hasher.input_str(plain_text);
        hasher.result(prepared_key);
        Ok(())
    }
}

pub struct KeySource {
    sk: [u8; 32],
}

pub struct KeyIter<'a> {
    sk: &'a [u8; 32],
    hash: [u8; 32],
    hasher: Sha256,
}

const FINGERPRINT_SALT: [u8; 32] = [0x15, 0x01, 0x8a, 0x3e, 0x8e, 0x79, 0x28, 0x71, 0x43, 0x70,
                                    0xf7, 0x51, 0x1c, 0x3b, 0xd5, 0xce, 0x85, 0x2b, 0x6f, 0x91,
                                    0x52, 0xc2, 0xb9, 0xab, 0xdb, 0x99, 0xaa, 0xd7, 0x9f, 0xc5,
                                    0x51, 0x20];

impl KeySource {
    pub fn new(key: &str) -> Self {
        let mut key_source = KeySource { sk: [0u8; 32] };
        prepare_skeleton_key(&key, &mut key_source.sk).unwrap();
        key_source
    }

    pub fn keys(&self, domain: &str, identity: &str) -> KeyIter {
        KeyIter::new(&self.sk, domain, identity)
    }

    pub fn fingerprint(&self) -> Vec<u8> {
        let mut buffer = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.input(&self.sk);
        hasher.input(&FINGERPRINT_SALT);
        hasher.result(&mut buffer);
        buffer[..5].to_owned()
    }
}

impl Drop for KeySource {
    fn drop(&mut self) {
        self.sk = [0u8; 32];
    }
}

impl<'a> KeyIter<'a> {
    pub fn new(sk: &'a [u8; 32], domain: &str, identity: &str) -> Self {
        let mut key_iter = KeyIter {
            sk: sk,
            hash: [0u8; 32],
            hasher: Sha256::new(),
        };
        {
            let h = &mut key_iter.hasher;
            h.input(sk);
            h.input_str(domain);
            h.input_str(identity);
            // For some reason the hasher is designed so that it cannot
            // be used once the digest has been extracted. We code
            // around this by taking a clone.
            h.clone().result(&mut key_iter.hash);
        }
        key_iter
    }
}

impl<'a> Drop for KeyIter<'a> {
    fn drop(&mut self) {
        self.hash = [0u8; 32];
    }
}

impl<'a> Iterator for KeyIter<'a> {
    type Item = Vec<u8>;
    #[allow(unused_assignments)]
    fn next(&mut self) -> Option<Self::Item> {
        // Get the first 80 bits as the generated key. I would have
        // preferred to use SHA-512/80 but the library (PyCrypto)
        // used in the original implementation didn't neither support
        // SHA-512/t directly nor allow setting the initial hash value
        // in which case I could have implemented the algorithm myself.
        // Now I'm stuck with this choice.
        let item = self.hash[0..10].to_vec();
        let h = &mut self.hasher;
        h.input(self.sk);
        h.input(&self.hash);
        h.clone().result(&mut self.hash);
        Some(item)
    }
}

pub mod base32 {
    fn output_size(input_size: usize) -> usize {
        8 * ((input_size + 4) / 5)
    }

	#[allow(unused_parens)]
	#[cfg_attr(rustfmt, rustfmt_skip)]
    fn encode_block(q: &[u8], r: &mut [u8]) {
        assert!(q.len() == 5);
        assert!(r.len() == 8);
		r[0] =  (q[0] >> 3);
		r[1] = ((q[0] & 0b00000111) << 2) + (q[1] >> 6);
		r[2] =  (q[1] & 0b00111110) >> 1;
		r[3] = ((q[1] & 0b00000001) << 4) + (q[2] >> 4);
		r[4] = ((q[2] & 0b00001111) << 1) + (q[3] >> 7);
		r[5] =  (q[3] & 0b01111100) >> 2;
		r[6] = ((q[3] & 0b00000011) << 3) + (q[4] >> 5);
		r[7] =  (q[4] & 0b00011111);
    }

    pub fn encode(input: &[u8], output: &mut [u8]) {
        assert!(input.len() % 5 == 0);
        assert!(output.len() == output_size(input.len()));
        let n = input.len() / 5;
        for i in 0..n {
            encode_block(&input[i * 5..(i + 1) * 5], &mut output[i * 8..(i + 1) * 8]);
        }
    }

    // abcdefghjkmnpqrstvwxyz
    const CROCKFORD_TRANSLATION_TABLE: [u8; 32] = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                                   0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
                                                   0x67, 0x68, 0x6a, 0x6b, 0x6d, 0x6e, 0x70, 0x71,
                                                   0x72, 0x73, 0x74, 0x76, 0x77, 0x78, 0x79, 0x7a];

    pub fn crockford(input: &[u8], output: &mut [u8]) {
        assert!(input.len() == output.len());
        for i in 0..input.len() {
            if input[i] < 32 {
                output[i] = CROCKFORD_TRANSLATION_TABLE[input[i] as usize];
            } else {
                panic!("input not Base-32 encoded");
            }
        }
    }

    pub fn to_crockford(input: &[u8]) -> String {
        let mut buffer = vec![0u8; input.len()];
        crockford(input, &mut buffer);
        String::from_utf8(buffer).unwrap()
    }
}

pub struct SplitGroups<'a> {
    string: &'a str,
    start: usize,
    group_size: usize,
    finished: bool,
}

pub fn split_groups(string: &str, group_size: usize) -> SplitGroups {
    if string.len() > 0 && group_size > 0 {
        SplitGroups {
            string: string,
            start: 0,
            group_size: group_size,
            finished: false,
        }
    } else {
        SplitGroups {
            string: "",
            start: 0,
            group_size: 0,
            finished: true,
        }
    }
}

impl<'a> Iterator for SplitGroups<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<&'a str> {
        if self.finished {
            return None;
        }
        let mut end = self.start + self.group_size;
        if end >= self.string.len() {
            end = self.string.len();
            self.finished = true;
        }
        let item = &self.string[self.start..end];
        self.start = end;
        Some(item)
    }
}

pub fn upcase_first(string: &str) -> String {
    let mut result = String::with_capacity(string.len());
    let mut did_convert = false;
    for c in string.chars() {
        if c.is_lowercase() && !did_convert {
            did_convert = true;
            for u in c.to_uppercase() {
                result.push(u);
            }
        } else {
            result.push(c);
        }
    }
    result
}

pub fn to_canonical(input: &str) -> String {
    split_groups(input, 4).map(upcase_first).collect::<Vec<String>>().join("-")
}

pub fn format_key(key: &[u8], group_size: usize) -> String {
    assert!(group_size > 0);
    let n = (key.len() / 5) * 8;
    let mut b32_key = vec![0u8; n];
    base32::encode(&key, &mut b32_key);
    let key_str = base32::to_crockford(&b32_key);
    let key_str =
        split_groups(&key_str, group_size).map(upcase_first).collect::<Vec<String>>().join("-");
    key_str
}

#[cfg(test)]
mod tests {

	#[cfg_attr(rustfmt, rustfmt_skip)]
    use ::{prepare_skeleton_key, PREPARED_SKELETON_KEY_SIZE, KeySource, KeyIter, base32, to_canonical};

    #[test]
    fn it_works() {
        let mut key = [0u8; PREPARED_SKELETON_KEY_SIZE];
        let rc = prepare_skeleton_key("\"Mom\" is \"äiti\" in Finnish", &mut key);
        assert!(rc == Ok(()));
        let correct = [0x17, 0xa8, 0xea, 0x56, 0x34, 0xad, 0x5e, 0x06, 0x0f, 0xac, 0xab, 0x88,
                       0x44, 0x3a, 0xf9, 0x81, 0x1d, 0x5d, 0x5a, 0x94, 0x77, 0x42, 0x7f, 0x53,
                       0x3d, 0xa9, 0x93, 0xdb, 0x82, 0xad, 0x93, 0x4c];
        assert!(key == correct);
    }

    #[test]
    fn test_key_generation() {
        let key_source = KeySource::new("secret skeleton passphrase");
        let mut key_iter = key_source.keys("domain", "identity");
        let key = key_iter.next().unwrap();
        let mut base32_key = [0u8; 16];
        base32::encode(&key, &mut base32_key);
        let key_str = base32::to_crockford(&base32_key);
        assert_eq!(key_str, "5wscx2mzcsnc4vgc");
        let key_str_2 = to_canonical(&key_str);
        assert_eq!(key_str_2, "5Wsc-X2mz-Csnc-4Vgc");
    }
}
