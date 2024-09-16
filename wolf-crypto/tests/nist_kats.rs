#[macro_use]
pub mod common;
use common::load::{
    load_tests,
    SHA3_224_BIT_FILES,
    SHA3_256_BIT_FILES,
    SHA3_384_BIT_FILES,
    SHA3_512_BIT_FILES,
};

use std::fs;
use wolf_crypto::hash::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

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