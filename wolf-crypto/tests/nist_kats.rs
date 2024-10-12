pub mod common;
use common::{
    load::load_tests,
    files::{
        SHA3_224_BYTE_FILES,
        SHA3_256_BYTE_FILES,
        SHA3_384_BYTE_FILES,
        SHA3_512_BYTE_FILES,

        SHA1_BYTE_FILES,
        SHA224_BYTE_FILES,
        SHA256_BYTE_FILES,
        SHA384_BYTE_FILES,
        SHA512_BYTE_FILES,
        SHA512_224_BYTE_FILES,
        SHA512_256_BYTE_FILES
    }
};

use wolf_crypto::hash::{
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,

    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256
};

#[cfg(feature = "allow-non-fips")]
use wolf_crypto::hash::Sha;

use crate::common::kat::{is_short_kat, is_long_kat, KnownTest};
use std::fs;

macro_rules! make_kat {
    ($files:ident with sz: $sz:literal, hasher: $hasher:ty, tk: $tk:ident) => {{
        let test_data = $files
            .iter()
            .find(|(name, _)| $tk(name))
            .unwrap();

        let bytes = fs::read(test_data.1).unwrap();

        let mut test = KnownTest::new(bytes.as_slice())
            .start::<{1 << 14}>();

        let mut hasher = <$hasher>::new().unwrap();

        while let Some((input, expected)) = test.next_item_sized::<$sz>() {
            hasher.try_update(input.as_slice()).unwrap();
            let out = hasher.try_finalize().unwrap();
            assert_eq!(out, expected);
        }
    }};
}

#[test]
fn nist_sha3_224_short_kat() {
    load_tests().unwrap();
    make_kat! { SHA3_224_BYTE_FILES with
        sz: 28,
        hasher: Sha3_224,
        tk: is_short_kat
    }
}

#[test]
fn nist_sha3_224_long_kat() {
    load_tests().unwrap();
    make_kat! { SHA3_224_BYTE_FILES with
        sz: 28,
        hasher: Sha3_224,
        tk: is_long_kat
    }
}

#[test]
fn nist_sha3_256_short_kat() {
    load_tests().unwrap();
    make_kat! { SHA3_256_BYTE_FILES with
        sz: 32,
        hasher: Sha3_256,
        tk: is_short_kat
    }
}

#[test]
fn nist_sha3_256_long_kat() {
    load_tests().unwrap();
    make_kat! { SHA3_256_BYTE_FILES with
        sz: 32,
        hasher: Sha3_256,
        tk: is_long_kat
    }
}

#[test]
fn nist_sha3_384_short_kat() {
    load_tests().unwrap();
    make_kat! { SHA3_384_BYTE_FILES with
        sz: 48,
        hasher: Sha3_384,
        tk: is_short_kat
    }
}

#[test]
fn nist_sha3_384_long_kat() {
    load_tests().unwrap();
    make_kat! { SHA3_384_BYTE_FILES with
        sz: 48,
        hasher: Sha3_384,
        tk: is_long_kat
    }
}

#[test]
fn nist_sha3_512_short_kat() {
    load_tests().unwrap();
    make_kat! { SHA3_512_BYTE_FILES with
        sz: 64,
        hasher: Sha3_512,
        tk: is_short_kat
    }
}

#[test]
fn nist_sha3_512_long_kat() {
    load_tests().unwrap();
    make_kat! { SHA3_512_BYTE_FILES with
        sz: 64,
        hasher: Sha3_512,
        tk: is_long_kat
    }
}

#[cfg(feature = "allow-non-fips")]
#[test]
fn nist_sha1_short_kat() {
    load_tests().unwrap();
    make_kat! { SHA1_BYTE_FILES with
        sz: 20,
        hasher: Sha,
        tk: is_short_kat
    }
}

#[cfg(feature = "allow-non-fips")]
#[test]
fn nist_sha1_long_kat() {
    load_tests().unwrap();
    make_kat! { SHA1_BYTE_FILES with
        sz: 20,
        hasher: Sha,
        tk: is_long_kat
    }
}

#[test]
fn nist_sha224_short_kat() {
    load_tests().unwrap();
    make_kat! { SHA224_BYTE_FILES with
        sz: 28,
        hasher: Sha224,
        tk: is_short_kat
    }
}

#[test]
fn nist_sha224_long_kat() {
    load_tests().unwrap();
    make_kat! { SHA224_BYTE_FILES with
        sz: 28,
        hasher: Sha224,
        tk: is_long_kat
    }
}

#[test]
fn nist_sha256_short_kat() {
    load_tests().unwrap();
    make_kat! { SHA256_BYTE_FILES with
        sz: 32,
        hasher: Sha256,
        tk: is_short_kat
    }
}

#[test]
fn nist_sha256_long_kat() {
    load_tests().unwrap();
    make_kat! { SHA256_BYTE_FILES with
        sz: 32,
        hasher: Sha256,
        tk: is_long_kat
    }
}

#[test]
fn nist_sha384_short_kat() {
    load_tests().unwrap();
    make_kat! { SHA384_BYTE_FILES with
        sz: 48,
        hasher: Sha384,
        tk: is_short_kat
    }
}

#[test]
fn nist_sha384_long_kat() {
    load_tests().unwrap();
    make_kat! { SHA384_BYTE_FILES with
        sz: 48,
        hasher: Sha384,
        tk: is_long_kat
    }
}

#[test]
fn nist_sha512_short_kat() {
    load_tests().unwrap();
    make_kat! { SHA512_BYTE_FILES with
        sz: 64,
        hasher: Sha512,
        tk: is_short_kat
    }
}

#[test]
fn nist_sha512_long_kat() {
    load_tests().unwrap();
    make_kat! { SHA512_BYTE_FILES with
        sz: 64,
        hasher: Sha512,
        tk: is_long_kat
    }
}

#[test]
fn nist_sha512_224_short_kat() {
    load_tests().unwrap();
    make_kat! { SHA512_224_BYTE_FILES with
        sz: 28,
        hasher: Sha512_224,
        tk: is_short_kat
    }
}

#[test]
fn nist_sha512_224_long_kat() {
    load_tests().unwrap();
    make_kat! { SHA512_224_BYTE_FILES with
        sz: 28,
        hasher: Sha512_224,
        tk: is_long_kat
    }
}

#[test]
fn nist_sha512_256_short_kat() {
    load_tests().unwrap();
    make_kat! { SHA512_256_BYTE_FILES with
        sz: 32,
        hasher: Sha512_256,
        tk: is_short_kat
    }
}

#[test]
fn nist_sha512_256_long_kat() {
    load_tests().unwrap();
    make_kat! { SHA512_256_BYTE_FILES with
        sz: 32,
        hasher: Sha512_256,
        tk: is_long_kat
    }
}