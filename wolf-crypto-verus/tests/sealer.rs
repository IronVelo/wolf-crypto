//! Runtime tests of the verified layer in a normal (non-Verus) build.
//!
//! Outside Verus the ghost capabilities are erased; unverified callers obtain
//! them with `Tracked::assume_new()`, which is exactly the trust a verified
//! caller avoids. The executable discipline (counter, reservation, limit,
//! zeroization) is what these tests exercise.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use vstd::prelude::Tracked;
use wolf_crypto_verus::{CounterSealer, Gcm, OpenError, SealError, ConfigError};

const KEY: [u8; 32] = [0x42; 32];
const PREFIX: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

fn sealer(start: u64, reserved: u64, limit: u64) -> CounterSealer {
    let mut key = KEY;
    let (gcm, ledger) = Gcm::resume(&mut key, &PREFIX, start).unwrap();
    assert_eq!(key, [0u8; 32], "caller key buffer is zeroized");
    CounterSealer::resume(gcm, ledger, PREFIX, start, reserved, limit, Tracked::assume_new()).unwrap()
}

fn expected_nonce(c: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&PREFIX);
    n[4..].copy_from_slice(&c.to_be_bytes());
    n
}

#[test]
fn nonces_are_prefix_and_big_endian_counter() {
    let mut s = sealer(0x0102_0304_0506_0708, u64::MAX, u64::MAX);
    let pt = *b"attack at dawn";
    let mut ct = [0u8; 14];
    let (n1, _) = s.seal(b"hdr", &pt, &mut ct).unwrap();
    let (n2, _) = s.seal(b"hdr", &pt, &mut ct).unwrap();
    assert_eq!(n1, expected_nonce(0x0102_0304_0506_0708));
    assert_eq!(n2, expected_nonce(0x0102_0304_0506_0709));
}

#[test]
fn matches_rustcrypto_and_round_trips() {
    let mut s = sealer(7, 100, 1000);
    let pt = b"the quick brown fox jumps over the lazy dog";
    let aad = b"associated";
    let mut ct = [0u8; 43];
    let (nonce, tag) = s.seal(aad, pt, &mut ct).unwrap();

    let reference = aes_gcm::Aes256Gcm::new_from_slice(&KEY).unwrap();
    let expected = reference
        .encrypt((&nonce).into(), Payload { msg: pt, aad })
        .unwrap();
    assert_eq!(&expected[..43], &ct[..]);
    assert_eq!(&expected[43..], &tag[..]);

    let mut out = [0u8; 43];
    s.open(&nonce, aad, &ct, &tag, &mut out).unwrap();
    assert_eq!(&out, pt);
}

#[test]
fn failed_open_zeroizes_output() {
    let mut s = sealer(0, 10, 10);
    let pt = [0x55u8; 32];
    let mut ct = [0u8; 32];
    let (nonce, mut tag) = s.seal(&[], &pt, &mut ct).unwrap();
    tag[0] ^= 1;
    let mut out = [0xffu8; 32];
    assert_eq!(s.open(&nonce, &[], &ct, &tag, &mut out), Err(OpenError::Rejected));
    assert_eq!(out, [0u8; 32]);

    let mut short = [0xffu8; 31];
    assert_eq!(s.open(&nonce, &[], &ct, &tag, &mut short), Err(OpenError::InvalidLength));
    assert_eq!(short, [0u8; 31]);
}

#[test]
fn reservation_and_exhaustion() {
    let mut s = sealer(0, 2, 3);
    let mut ct = [0u8; 1];
    assert!(s.seal(&[], &[1], &mut ct).is_ok());
    assert!(s.seal(&[], &[1], &mut ct).is_ok());
    assert_eq!(s.seal(&[], &[1], &mut ct), Err(SealError::NeedsReservation));
    assert_eq!(s.extend_reservation(4, Tracked::assume_new()), Err(ConfigError::InvalidBounds));
    assert_eq!(s.extend_reservation(1, Tracked::assume_new()), Err(ConfigError::InvalidBounds));
    s.extend_reservation(3, Tracked::assume_new()).unwrap();
    let (n, _) = s.seal(&[], &[1], &mut ct).unwrap();
    assert_eq!(n, expected_nonce(2));
    assert_eq!(s.seal(&[], &[1], &mut ct), Err(SealError::Exhausted));
    assert_eq!(s.seal(&[], &[1], &mut ct), Err(SealError::Exhausted));
}

#[test]
fn counter_never_wraps_at_u64_max() {
    let mut s = sealer(u64::MAX - 1, u64::MAX, u64::MAX);
    let mut ct = [0u8; 1];
    let (n, _) = s.seal(&[], &[1], &mut ct).unwrap();
    assert_eq!(n, expected_nonce(u64::MAX - 1));
    assert_eq!(s.seal(&[], &[1], &mut ct), Err(SealError::Exhausted));
}

#[test]
fn invalid_lengths_consume_no_nonce() {
    let mut s = sealer(5, 10, 10);
    let mut ct = [0u8; 2];
    assert_eq!(s.seal(&[], &[1, 2, 3], &mut ct), Err(SealError::InvalidLength));
    let (n, _) = s.seal(&[], &[1, 2], &mut ct).unwrap();
    assert_eq!(n, expected_nonce(5));
}

#[test]
fn bad_bounds_are_rejected() {
    let mut key = KEY;
    let (gcm, ledger) = Gcm::resume(&mut key, &PREFIX, 10).unwrap();
    assert!(matches!(
        CounterSealer::resume(gcm, ledger, PREFIX, 10, 9, 20, Tracked::assume_new()),
        Err(ConfigError::InvalidBounds)
    ));
}

#[test]
fn generated_keys_seal_and_open() {
    let (gcm, ledger) = Gcm::generate().unwrap();
    let mut s = CounterSealer::new(gcm, ledger, PREFIX, 0, 16, 16, Tracked::assume_new()).unwrap();
    let pt = [9u8; 64];
    let mut ct = [0u8; 64];
    let (nonce, tag) = s.seal(b"a", &pt, &mut ct).unwrap();
    assert_eq!(nonce, expected_nonce(0));
    let mut out = [0u8; 64];
    s.open(&nonce, b"a", &ct, &tag, &mut out).unwrap();
    assert_eq!(out, pt);
}
