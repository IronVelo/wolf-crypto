#![no_main]

use libfuzzer_sys::fuzz_target;
use wolf_crypto::ecc::{Curve, PublicKey, Signature, P256, P384};

fn decode<C: Curve>(data: &[u8]) {
    // only canonical DER is accepted, so whatever decodes must re-encode to the input.
    if let Ok(sig) = Signature::<C>::from_der(data) {
        assert_eq!(sig.to_der().unwrap().as_ref(), data);
    }

    if let Ok(public) = PublicKey::<C>::from_spki_der(data) {
        assert_eq!(public.to_spki_der().unwrap().as_ref(), data);
    }

    if let Ok(public) = PublicKey::<C>::from_sec1_slice(data) {
        assert_eq!(public.to_sec1().unwrap().as_ref(), data);
    }
}

fuzz_target!(|data: &[u8]| {
    decode::<P256>(data);
    decode::<P384>(data);
});
