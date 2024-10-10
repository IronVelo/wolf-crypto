#![no_main]

use libfuzzer_sys::fuzz_target;
use wolf_crypto::{aead::ChaCha20Poly1305, mac::poly1305::Key};

fuzz_target!(|data: &[u8]| {
    let mut outbuf = [0u8; 4096];
    let _ = ChaCha20Poly1305::new_encrypt(Key::new([7u8; 32]), [42u8; 12])
        .update(data, outbuf.as_mut_slice())
        .unwrap();
});
