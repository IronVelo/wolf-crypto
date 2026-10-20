//! NIST CAVP known-answer tests for the Hash_DRBG (SHA-256) mechanism behind `random::Rng`.
//!
//! The vectors are the `[SHA-256]` sections without personalization string and additional input
//! of the official DRBGVS `no_reseed` and `pr_false` sets, committed under `tests/vectors/drbg/`
//! (see `tests/README.org` for their provenance).

use std::fs;
use wolf_crypto::random::kat::{hash_drbg_sha256, OUTPUT_SIZE};

macro_rules! vector {
    ($path:literal) => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/drbg/", $path)
    };
}

/// A test case: the `[...]` parameters of its section and its `key = value` pairs.
struct Case {
    params: Vec<String>,
    fields: Vec<(String, String)>
}

impl Case {
    fn get(&self, key: &str) -> &str {
        self.fields.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("missing `{key}` in {:?}", self.params))
    }

    fn hex(&self, key: &str) -> Vec<u8> {
        hex::decode(self.get(key)).unwrap()
    }

    fn count(&self) -> &str {
        self.get("COUNT")
    }

    /// The value of every `key` field, in order (DRBGVS repeats `AdditionalInput`).
    fn all<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.fields.iter().filter(move |(k, _)| k == key).map(|(_, v)| v.as_str())
    }
}

/// Parse a DRBGVS response file into its cases.
///
/// A run of `[...]` lines sets the parameters of the following cases, cases are runs of
/// `key = value` lines separated by blank lines, `#` lines are comments.
fn parse(path: &str) -> Vec<Case> {
    let raw = fs::read_to_string(path).unwrap();
    let mut cases = Vec::new();
    let mut params: Vec<String> = Vec::new();
    let mut in_params = false;
    let mut fields: Vec<(String, String)> = Vec::new();

    let mut flush = |params: &[String], fields: &mut Vec<(String, String)>| {
        if !fields.is_empty() {
            cases.push(Case { params: params.to_vec(), fields: core::mem::take(fields) });
        }
    };

    for line in raw.lines().map(str::trim) {
        if line.starts_with('#') { continue }
        if line.is_empty() {
            flush(&params, &mut fields);
            in_params = false;
            continue
        }
        if let Some(param) = line.strip_prefix('[') {
            flush(&params, &mut fields);
            if !in_params {
                params.clear();
                in_params = true;
            }
            params.push(param.trim_end_matches(']').to_owned());
            continue
        }
        in_params = false;
        let (k, v) = line.split_once('=').expect("malformed line");
        fields.push((k.trim().to_owned(), v.trim().to_owned()));
    }
    flush(&params, &mut fields);

    cases
}

/// Check that every case is in a section we can run: SHA-256, 256 bit entropy, 128 bit nonce,
/// no personalization string or additional input, 1024 returned bits.
fn check_params(case: &Case) {
    for expected in [
        "SHA-256",
        "PredictionResistance = False",
        "EntropyInputLen = 256",
        "NonceLen = 128",
        "PersonalizationStringLen = 0",
        "AdditionalInputLen = 0",
        "ReturnedBitsLen = 1024",
    ] {
        assert!(
            case.params.iter().any(|p| p == expected),
            "COUNT = {}: missing [{expected}] in {:?}", case.count(), case.params
        );
    }
    assert!(case.get("PersonalizationString").is_empty());
    assert!(case.all("AdditionalInput").all(str::is_empty));
}

#[test]
fn hash_drbg_sha256_no_reseed() {
    let cases = parse(vector!("Hash_DRBG_no_reseed.rsp"));
    assert_eq!(cases.len(), 60);

    for case in &cases {
        check_params(case);
        let out = hash_drbg_sha256(&case.hex("EntropyInput"), &case.hex("Nonce"), None).unwrap();

        assert_eq!(out.len(), OUTPUT_SIZE);
        assert_eq!(
            out.as_slice(), case.hex("ReturnedBits").as_slice(),
            "no_reseed mismatch at COUNT = {} in {:?}", case.count(), case.params
        );
    }
}

#[test]
fn hash_drbg_sha256_reseed() {
    let cases = parse(vector!("Hash_DRBG_pr_false.rsp"));
    assert_eq!(cases.len(), 60);

    for case in &cases {
        check_params(case);
        assert!(case.get("AdditionalInputReseed").is_empty());

        let out = hash_drbg_sha256(
            &case.hex("EntropyInput"),
            &case.hex("Nonce"),
            Some(&case.hex("EntropyInputReseed"))
        ).unwrap();

        assert_eq!(
            out.as_slice(), case.hex("ReturnedBits").as_slice(),
            "pr_false mismatch at COUNT = {} in {:?}", case.count(), case.params
        );
    }
}
