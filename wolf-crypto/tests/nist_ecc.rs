//! NIST CAVP known-answer tests for ECDSA (FIPS 186-4 SigVer, SigGen, PKV) and the ECC CDH
//! primitive (SP 800-56A, KAS ECC CDH component).
//!
//! The vectors are the P-256 / P-384 subsets of the official CAVP files, committed under
//! `tests/vectors/` (see `tests/README.org` for their provenance). Only the hash matching the
//! curve is tested (SHA-256 with P-256, SHA-384 with P-384), as the API does not allow signing
//! or verifying digests of another size.

use std::fs;
use wolf_crypto::ecc::{ByteArray, Curve, PrivateKey, PublicKey, Signature, P256, P384};
use wolf_crypto::hash::{Sha256, Sha384};
use wolf_crypto::random::Rng;

macro_rules! vector {
    ($path:literal) => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/", $path)
    };
}

const SIG_VER: &str = vector!("ecdsa/SigVer.rsp");
const SIG_GEN: &str = vector!("ecdsa/SigGen.txt");
const PKV: &str = vector!("ecdsa/PKV.rsp");
const CDH: &str = vector!("ecccdh/KAS_ECC_CDH_PrimitiveTest.txt");

/// A test case: the section it is in (e.g. `P-256,SHA-256`) and its `key = value` pairs.
struct Case {
    section: String,
    fields: Vec<(String, String)>
}

impl Case {
    fn get(&self, key: &str) -> &str {
        self.fields.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("missing `{key}` in [{}]", self.section))
    }

    fn hex(&self, key: &str) -> Vec<u8> {
        let raw = self.get(key);
        // some out of range coordinates have an odd number of digits
        if raw.len() % 2 == 1 {
            hex::decode(format!("0{raw}")).unwrap()
        } else {
            hex::decode(raw).unwrap()
        }
    }

    /// The value left-padded to `size` bytes, `None` if it is longer.
    fn padded(&self, key: &str, size: usize) -> Option<Vec<u8>> {
        let mut raw = self.hex(key);
        while raw.len() > size && raw[0] == 0 { raw.remove(0); }
        if raw.len() > size { return None }
        let mut out = vec![0u8; size - raw.len()];
        out.extend_from_slice(&raw);
        Some(out)
    }

    fn passes(&self) -> bool {
        match self.get("Result").as_bytes()[0] {
            b'P' => true,
            b'F' => false,
            _ => panic!("malformed Result in [{}]", self.section)
        }
    }
}

/// Parse a CAVP response file into its cases.
///
/// Cases are runs of `key = value` lines separated by blank lines, `[...]` lines start a new
/// section, `#` lines are comments.
fn parse(path: &str) -> Vec<Case> {
    let raw = fs::read_to_string(path).unwrap();
    let mut cases = Vec::new();
    let mut section = String::new();
    let mut fields: Vec<(String, String)> = Vec::new();

    let mut flush = |section: &str, fields: &mut Vec<(String, String)>| {
        if !fields.is_empty() {
            cases.push(Case { section: section.to_owned(), fields: core::mem::take(fields) });
        }
    };

    for line in raw.lines().map(str::trim) {
        if line.starts_with('#') {
            continue;
        } else if line.is_empty() {
            flush(&section, &mut fields);
        } else if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            flush(&section, &mut fields);
            section = name.to_owned();
        } else if let Some((k, v)) = line.split_once('=') {
            fields.push((k.trim().to_owned(), v.trim().to_owned()));
        } else {
            panic!("unexpected line in {path}: {line}");
        }
    }
    flush(&section, &mut fields);

    cases
}

fn sec1<C: Curve>(case: &Case, x: &str, y: &str) -> Option<C::Sec1Point> {
    let x = case.padded(x, C::SIZE)?;
    let y = case.padded(y, C::SIZE)?;
    let mut point = C::Sec1Point::zeroes();
    point.as_mut()[0] = 0x04;
    point.as_mut()[1..=C::SIZE].copy_from_slice(&x);
    point.as_mut()[1 + C::SIZE..].copy_from_slice(&y);
    Some(point)
}

fn signature<C: Curve>(case: &Case) -> Signature<C> {
    let mut raw = case.padded("R", C::SIZE).unwrap();
    raw.extend_from_slice(&case.padded("S", C::SIZE).unwrap());
    Signature::<C>::try_from(raw.as_slice()).unwrap()
}

fn digest<C: Curve>(msg: &[u8]) -> C::Digest {
    let mut out = C::Digest::zeroes();
    match C::SIZE {
        32 => {
            let mut h = Sha256::new().unwrap();
            assert!(h.try_update(msg).is_ok());
            out.as_mut().copy_from_slice(&h.try_finalize().unwrap());
        },
        48 => {
            let mut h = Sha384::new().unwrap();
            assert!(h.try_update(msg).is_ok());
            out.as_mut().copy_from_slice(&h.try_finalize().unwrap());
        },
        _ => unreachable!()
    }
    out
}

fn sig_ver<C: Curve>(section: &str) -> usize {
    let mut count = 0;
    for case in parse(SIG_VER).iter().filter(|c| c.section == section) {
        let msg = case.hex("Msg");
        let expected = case.passes();

        let verified = match sec1::<C>(case, "Qx", "Qy").map(|p| PublicKey::<C>::from_sec1(&p)) {
            Some(Ok(public)) => {
                let sig = signature::<C>(case);
                let by_digest = public.verify_digest(&digest::<C>(&msg), &sig).is_ok();
                let by_msg = public.verify(&msg, &sig).is_ok();
                assert_eq!(by_digest, by_msg);
                by_digest
            },
            // "Q changed" cases may produce an invalid public key, which cannot verify anything.
            _ => false
        };

        assert_eq!(verified, expected, "SigVer [{section}] case {count}: {}", case.get("Result"));
        count += 1;
    }
    count
}

fn sig_gen<C: Curve>(section: &str) -> usize {
    let mut rng = Rng::new().unwrap();
    let mut count = 0;

    for case in parse(SIG_GEN).iter().filter(|c| c.section == section) {
        let msg = case.hex("Msg");

        // the private key must derive the expected public key
        let mut d = C::Scalar::zeroes();
        d.as_mut().copy_from_slice(&case.padded("d", C::SIZE).unwrap());
        let key = PrivateKey::<C>::from_bytes(&d, &mut rng).unwrap();
        let q = sec1::<C>(case, "Qx", "Qy").unwrap();
        assert_eq!(key.public_key().unwrap().to_sec1().unwrap().as_ref(), q.as_ref());

        // the published signature verifies, and only for its message
        let public = PublicKey::<C>::from_sec1(&q).unwrap();
        let sig = signature::<C>(case);
        assert!(public.verify(&msg, &sig).is_ok(), "SigGen [{section}] case {count}");

        let mut tampered = msg.clone();
        tampered[0] ^= 1;
        assert!(public.verify(&tampered, &sig).is_err());

        // and DER encoding roundtrips
        let der = sig.to_der().unwrap();
        assert_eq!(Signature::<C>::from_der(der.as_ref()).unwrap(), sig);

        count += 1;
    }
    count
}

fn pkv<C: Curve>(section: &str) -> usize {
    let mut count = 0;
    for case in parse(PKV).iter().filter(|c| c.section == section) {
        let valid = sec1::<C>(case, "Qx", "Qy")
            .is_some_and(|p| PublicKey::<C>::from_sec1(&p).is_ok());
        assert_eq!(valid, case.passes(), "PKV [{section}] case {count}: {}", case.get("Result"));
        count += 1;
    }
    count
}

fn cdh<C: Curve>(section: &str) -> usize {
    let mut rng = Rng::new().unwrap();
    let mut count = 0;

    for case in parse(CDH).iter().filter(|c| c.section == section) {
        let mut d = C::Scalar::zeroes();
        d.as_mut().copy_from_slice(&case.padded("dIUT", C::SIZE).unwrap());
        let mut ours = PrivateKey::<C>::from_bytes(&d, &mut rng).unwrap();

        let q_iut = sec1::<C>(case, "QIUTx", "QIUTy").unwrap();
        assert_eq!(ours.public_key().unwrap().to_sec1().unwrap().as_ref(), q_iut.as_ref());

        let peer = PublicKey::<C>::from_sec1(&sec1::<C>(case, "QCAVSx", "QCAVSy").unwrap())
            .unwrap();
        let z = ours.diffie_hellman(&peer, &mut rng).unwrap();

        assert_eq!(
            z.as_bytes().as_ref(), case.padded("ZIUT", C::SIZE).unwrap().as_slice(),
            "CDH [{section}] COUNT = {}", case.get("COUNT")
        );
        count += 1;
    }
    count
}

#[test]
fn ecdsa_sig_ver_p256_sha256() {
    assert_eq!(sig_ver::<P256>("P-256,SHA-256"), 15);
}

#[test]
fn ecdsa_sig_ver_p384_sha384() {
    assert_eq!(sig_ver::<P384>("P-384,SHA-384"), 15);
}

#[test]
fn ecdsa_sig_gen_p256_sha256() {
    assert_eq!(sig_gen::<P256>("P-256,SHA-256"), 15);
}

#[test]
fn ecdsa_sig_gen_p384_sha384() {
    assert_eq!(sig_gen::<P384>("P-384,SHA-384"), 15);
}

#[test]
fn ecdsa_pkv_p256() {
    assert_eq!(pkv::<P256>("P-256"), 12);
}

#[test]
fn ecdsa_pkv_p384() {
    assert_eq!(pkv::<P384>("P-384"), 12);
}

#[test]
fn ecc_cdh_p256() {
    assert_eq!(cdh::<P256>("P-256"), 25);
}

#[test]
fn ecc_cdh_p384() {
    assert_eq!(cdh::<P384>("P-384"), 25);
}
