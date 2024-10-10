#![no_main]

use libfuzzer_sys::fuzz_target;
use wolf_crypto::hex;

fuzz_target!(|data: &[u8]| {
    let mut outbuf = [0u8; 8192];

    let _res = core::hint::black_box(hex::decode_into(data, outbuf.as_mut_slice()));
    let len = hex::encode_into(data, outbuf.as_mut_slice()).unwrap();

    let mut decoded_buf = [0u8; 4096];
    hex::decode_into(&outbuf[..len], decoded_buf.as_mut_slice()).unwrap();

    assert_eq!(&decoded_buf[..data.len()], data);
});
