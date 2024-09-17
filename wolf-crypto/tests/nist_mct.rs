#[macro_use]
pub mod common;

use common::{
    load::load_tests,
    files::{
        SHA3_224_BIT_FILES,
        SHA3_256_BIT_FILES,
        SHA3_384_BIT_FILES,
        SHA3_512_BIT_FILES,

        SHA1_BIT_FILES,
        SHA224_BIT_FILES,
        SHA256_BIT_FILES,
        SHA384_BIT_FILES,
        SHA512_BIT_FILES,
        SHA512_224_BIT_FILES,
        SHA512_256_BIT_FILES
    }
};

use wolf_crypto::hash::{
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,

    Sha,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256
};

#[test]
fn sha3_224_nist_mct() {
    load_tests().unwrap();
    make_mc_test! {
        SHA3_224_BIT_FILES with
        sz: 28,
        hasher: Sha3_224,
        cases: 100
    }
}

#[test]
fn sha3_256_nist_mct() {
    load_tests().unwrap();
    make_mc_test! {
        SHA3_256_BIT_FILES with
        sz: 32,
        hasher: Sha3_256,
        cases: 100
    }
}

#[test]
fn sha3_384_nist_mct() {
    load_tests().unwrap();
    make_mc_test! {
        SHA3_384_BIT_FILES with
        sz: 48,
        hasher: Sha3_384,
        cases: 100
    }
}

#[test]
fn sha3_512_nist_mct() {
    load_tests().unwrap();
    make_mc_test! {
        SHA3_512_BIT_FILES with
        sz: 64,
        hasher: Sha3_512,
        cases: 100
    }
}

#[test]
fn sha1_nist_mct() {
    load_tests().unwrap();
    make_md_mct! {
        SHA1_BIT_FILES with
        sz: 20,
        hasher: Sha
    }
}

#[test]
fn sha224_nist_mct() {
    load_tests().unwrap();
    make_md_mct! {
        SHA224_BIT_FILES with
        sz: 28,
        hasher: Sha224
    }
}

#[test]
fn sha256_nist_mct() {
    load_tests().unwrap();
    make_md_mct! {
        SHA256_BIT_FILES with
        sz: 32,
        hasher: Sha256,
        align_64: true
    }
}

#[test]
fn sha384_nist_mct() {
    load_tests().unwrap();
    make_md_mct! {
        SHA384_BIT_FILES with
        sz: 48,
        hasher: Sha384,
        align_64: true
    }
}

#[test]
fn sha512_nist_mct() {
    load_tests().unwrap();
    make_md_mct! {
        SHA512_BIT_FILES with
        sz: 64,
        hasher: Sha512,
        align_64: true
    }
}

#[test]
fn sha512_224_nist_mct() {
    load_tests().unwrap();
    make_md_mct! {
        SHA512_224_BIT_FILES with
        sz: 28,
        hasher: Sha512_224,
    }
}

#[test]
fn sha512_256_nist_mct() {
    load_tests().unwrap();
    make_md_mct! {
        SHA512_256_BIT_FILES with
        sz: 32,
        hasher: Sha512_256,
        align_64: true
    }
}

