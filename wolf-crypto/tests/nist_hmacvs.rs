pub mod common;

use common::{
    load::load_tests,
    files::{
        HMACVS_FILES
    },
    hmacvs::{Algo, Case, Harness, ErrKind}
};

use std::fs;

use wolf_crypto::mac::hmac::{
    Hmac,
    algo::InsecureKey,
    Sha, Sha224, Sha256, Sha384, Sha512
};


#[test]
#[cfg_attr(not(feature = "allow-non-fips"), ignore)] // CAVP uses keys which are not FIPS compliant
fn hmacvs() {
    load_tests().unwrap();

    let test_data = HMACVS_FILES.first().unwrap();
    let bytes = fs::read(test_data.1).unwrap();

    let mut test = Harness::new(bytes.as_slice());

    loop {
        match test.next_case() {
            Ok(Case { algo, key, msg, tag }) => match algo {
                Algo::Sha1 => {
                    let mut hmac = Hmac::<Sha>::new(
                        InsecureKey::new(key.as_slice()).unwrap()
                    );
                    hmac.update(msg.as_slice()).unwrap();
                    let digest = hmac.finalize().into_inner();
                    assert_eq!(&digest[..tag.len()], tag.as_slice());
                },
                Algo::Sha224 => {
                    let mut hmac = Hmac::<Sha224>::new(
                        InsecureKey::new(key.as_slice()).unwrap()
                    );
                    hmac.update(msg.as_slice()).unwrap();
                    let digest = hmac.finalize().into_inner();
                    assert_eq!(&digest[..tag.len()], tag.as_slice());
                },
                Algo::Sha256 => {
                    let mut hmac = Hmac::<Sha256>::new(
                        InsecureKey::new(key.as_slice()).unwrap()
                    );
                    hmac.update(msg.as_slice()).unwrap();
                    let digest = hmac.finalize().into_inner();
                    assert_eq!(&digest[..tag.len()], tag.as_slice());
                },
                Algo::Sha384 => {
                    let mut hmac = Hmac::<Sha384>::new(
                        InsecureKey::new(key.as_slice()).unwrap()
                    );
                    hmac.update(msg.as_slice()).unwrap();
                    let digest = hmac.finalize().into_inner();
                    assert_eq!(&digest[..tag.len()], tag.as_slice());
                },
                Algo::Sha512 => {
                    let mut hmac = Hmac::<Sha512>::new(
                        InsecureKey::new(key.as_slice()).unwrap()
                    );
                    hmac.update(msg.as_slice()).unwrap();
                    let digest = hmac.finalize().into_inner();
                    assert_eq!(&digest[..tag.len()], tag.as_slice());
                }
            },
            Err((ErrKind::Term, _msg, _)) => {
                test.assert_complete();
                break;
            },
            Err((ErrKind::Unexpected, msg, count)) => {
                panic!("[UNEXPECTED ERROR @ count: {}] {}", count, msg);
            }
        }
    }
}