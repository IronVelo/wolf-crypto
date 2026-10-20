//! NIST CAVP known-answer tests for AES Key Wrap (SP 800-38F KW-AE and KW-AD).
//!
//! The vectors are the forward-cipher KW files of the official CAVP KWVS set, committed under
//! `tests/vectors/kw/` (see `tests/README.org` for their provenance). The inverse-cipher (`_inv`)
//! and KWP files are not used, as neither is offered by the API.

use std::fs;
use wolf_crypto::aes::kw::{Kek, Kek128, Kek192, Kek256, Wrapped};

macro_rules! vector {
    ($path:literal) => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/kw/", $path)
    };
}

/// A test case: the plaintext length of its section (in bits) and its `key = value` pairs.
struct Case {
    plaintext_bits: usize,
    count: String,
    fields: Vec<(String, String)>
}

impl Case {
    fn get(&self, key: &str) -> Option<&str> {
        self.fields.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    fn hex(&self, key: &str) -> Vec<u8> {
        let raw = self.get(key)
            .unwrap_or_else(|| panic!("missing `{key}` in COUNT = {}", self.count));
        hex::decode(raw).unwrap()
    }

    /// Whether the case expects the unwrap to fail (`FAIL` instead of `P`).
    fn fails(&self) -> bool {
        self.fields.iter().any(|(k, _)| k == "FAIL")
    }
}

/// Parse a KWVS file into its cases.
///
/// `[PLAINTEXT LENGTH = n]` lines start a section, cases are runs of `key = value` lines (or a
/// bare `FAIL`) separated by blank lines, `#` lines are comments.
fn parse(path: &str) -> Vec<Case> {
    let raw = fs::read_to_string(path).unwrap();
    let mut cases = Vec::new();
    let mut plaintext_bits = 0;
    let mut fields: Vec<(String, String)> = Vec::new();

    let mut flush = |bits: usize, fields: &mut Vec<(String, String)>| {
        if !fields.is_empty() {
            let count = fields.iter()
                .find(|(k, _)| k == "COUNT")
                .map(|(_, v)| v.clone())
                .expect("case without COUNT");
            cases.push(Case { plaintext_bits: bits, count, fields: core::mem::take(fields) });
        }
    };

    for line in raw.lines().map(str::trim) {
        if line.starts_with('#') { continue }
        if line.is_empty() {
            flush(plaintext_bits, &mut fields);
            continue
        }
        if let Some(section) = line.strip_prefix('[') {
            flush(plaintext_bits, &mut fields);
            let len = section.trim_end_matches(']')
                .strip_prefix("PLAINTEXT LENGTH = ")
                .expect("unexpected section");
            plaintext_bits = len.trim().parse().unwrap();
            continue
        }
        match line.split_once('=') {
            Some((k, v)) => fields.push((k.trim().to_owned(), v.trim().to_owned())),
            None => fields.push((line.to_owned(), String::new()))
        }
    }
    flush(plaintext_bits, &mut fields);

    cases
}

/// Wrap `p` under `kek`, for a plaintext length only known at run time.
fn wrap<const N: usize>(kek: &Kek<N>, p: &[u8]) -> Vec<u8> {
    macro_rules! by_len {
        ($($len:literal),*) => {
            match p.len() {
                $($len => kek.wrap::<$len>(p.try_into().unwrap()).unwrap().as_slice().to_vec(),)*
                other => panic!("no test dispatch for a {other} byte plaintext")
            }
        };
    }
    by_len!(16, 24, 32, 40, 512)
}

/// Unwrap `c` under `kek`, `None` if the integrity check fails.
fn unwrap<const N: usize>(kek: &Kek<N>, c: &[u8]) -> Option<Vec<u8>> {
    macro_rules! by_len {
        ($($len:literal),*) => {
            match c.len() - 8 {
                $($len => {
                    let wrapped = Wrapped::<$len>::try_from(c).unwrap();
                    kek.unwrap(&wrapped).ok().map(|key| key.as_slice().to_vec())
                },)*
                other => panic!("no test dispatch for a {other} byte plaintext")
            }
        };
    }
    by_len!(16, 24, 32, 40, 512)
}

/// The plaintext lengths (in bits) of every KWVS file, 100 cases each.
const LENGTHS: [usize; 5] = [128, 256, 192, 320, 4096];

fn check_sections(cases: &[Case]) {
    for bits in LENGTHS {
        assert_eq!(
            cases.iter().filter(|c| c.plaintext_bits == bits).count(), 100,
            "expected 100 cases with a {bits} bit plaintext"
        );
    }
    assert_eq!(cases.len(), 500);
}

macro_rules! kw_tests {
    ($($ae:ident, $ad:ident, $kek:ident, $ae_file:literal, $ad_file:literal;)*) => {$(
        #[test]
        fn $ae() {
            let cases = parse(vector!($ae_file));
            check_sections(&cases);

            for case in &cases {
                let kek = $kek::new(case.hex("K").try_into().unwrap());
                let p = case.hex("P");
                assert_eq!(p.len() * 8, case.plaintext_bits);

                assert_eq!(
                    wrap(&kek, &p), case.hex("C"),
                    "KW-AE mismatch at [PLAINTEXT LENGTH = {}] COUNT = {}",
                    case.plaintext_bits, case.count
                );
            }
        }

        #[test]
        fn $ad() {
            let cases = parse(vector!($ad_file));
            check_sections(&cases);

            let mut failures = 0;
            for case in &cases {
                let kek = $kek::new(case.hex("K").try_into().unwrap());
                let c = case.hex("C");
                let res = unwrap(&kek, &c);

                if case.fails() {
                    failures += 1;
                    assert!(
                        res.is_none(),
                        "KW-AD accepted an invalid ciphertext at [PLAINTEXT LENGTH = {}] \
                         COUNT = {}", case.plaintext_bits, case.count
                    );
                } else {
                    assert_eq!(
                        res.as_deref(), Some(case.hex("P").as_slice()),
                        "KW-AD mismatch at [PLAINTEXT LENGTH = {}] COUNT = {}",
                        case.plaintext_bits, case.count
                    );
                }
            }

            // "Should FAIL 20 times per 100 trials" (KWVS Readme)
            assert_eq!(failures, 100);
        }
    )*};
}

kw_tests! {
    kw_ae_128, kw_ad_128, Kek128, "KW_AE_128.txt", "KW_AD_128.txt";
    kw_ae_192, kw_ad_192, Kek192, "KW_AE_192.txt", "KW_AD_192.txt";
    kw_ae_256, kw_ad_256, Kek256, "KW_AE_256.txt", "KW_AD_256.txt";
}
