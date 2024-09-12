use std::mem::MaybeUninit;
use std::ptr::addr_of_mut;
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::{AeadMut};
use criterion::{Criterion, black_box, criterion_group, criterion_main, Throughput};
use wolf_crypto::aes::{Key, gcm::{AesGcm}};
use wolf_crypto::aes::gcm::Aad;
use wolf_crypto::buf::Nonce;
use wolf_crypto_sys::{Aes, INVALID_DEVID, wc_AesGcmEncrypt, wc_AesGcmSetKey, wc_AesInit};

fn init_raw_aes(key: *mut u8) -> Aes {
    unsafe {
        let mut aes = MaybeUninit::uninit();
        wc_AesInit(aes.as_mut_ptr(), core::ptr::null_mut(), INVALID_DEVID);
        wc_AesGcmSetKey(
            aes.as_mut_ptr(),
            key,
            32, // aes 256
        );
        aes.assume_init()
    }
}

fn bench_block_multiple(c: &mut Criterion) {
    const AAD: Aad = Aad::EMPTY;
    let inp = [7u8; 4096];
    let mut out = [0u8; 4096];

    let k_256 = Key::Aes256([8u8; 32]);
    let nonce = Nonce::new([3u8; 12]);
    let mut aes_256 = AesGcm::new(&k_256);

    let mut g = c.benchmark_group("aes-gcm-block-multiple");
    g.throughput(Throughput::Bytes(inp.len() as u64));

    g.bench_function("wolf/encrypt-aes-256", |b| {
        b.iter(|| {
            let tag = aes_256
                .encrypt_sized(nonce.copy(), black_box(&inp), &mut out, AAD)
                .unwrap();

            black_box(tag)
        })
    });

    let mut raw_key = [0u8; 32];
    let mut raw_nonce = [3u8; 12];

    let mut aes = init_raw_aes(raw_key.as_mut_ptr());

    g.bench_function("wolf-sys/encrypt-aes-256", |b| {
        b.iter(|| unsafe {
            let mut tag = [0u8; 16];

            let res = wc_AesGcmEncrypt(
                addr_of_mut!(aes),
                out.as_mut_ptr(),
                black_box(inp.as_ptr()),
                inp.len() as u32,
                raw_nonce.as_mut_ptr(),
                12,
                tag.as_mut_ptr(),
                16,
                core::ptr::null(),
                0
            );

            assert_eq!(res, 0);
        })
    });

    let mut r_c_aes_256 = Aes256Gcm::new_from_slice(k_256.as_slice())
        .unwrap();

    g.bench_function("rust-crypto/encrypt-aes-256", |b| {
        b.iter(|| {
            let res = r_c_aes_256
                .encrypt(aes_gcm::Nonce::from_slice(nonce.slice()), black_box(inp.as_slice()))
                .unwrap();

            black_box(res);
        })
    });
}

criterion_group!(benches, bench_block_multiple);
criterion_main!(benches);