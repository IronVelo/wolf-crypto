use wolf_crypto_sys::{
    wc_Sha512_224,
    wc_Sha512_224Update, wc_Sha512_224Final,
    wc_InitSha512_224, wc_Sha512_224Free,
    wc_Sha512_224Copy
};

mark_fips! { Sha512_224, Sealed }

make_api! {
    name: Sha512_224,
    wc: wc_Sha512_224,
    bs: 28,
    init: wc_InitSha512_224,
    update: wc_Sha512_224Update,
    finalize: wc_Sha512_224Final,
    free: wc_Sha512_224Free,
    copy: wc_Sha512_224Copy
}
