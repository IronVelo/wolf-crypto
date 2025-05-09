use wolf_crypto_sys::{
    wc_Sha512_256,
    wc_Sha512_256Update, wc_Sha512_256Final,
    wc_InitSha512_256, wc_Sha512_256Free,
    wc_Sha512_256Copy
};

mark_fips! { Sha512_256, Sealed }

make_api! {
    name: Sha512_256,
    wc: wc_Sha512_256,
    bs: 32,
    init: wc_InitSha512_256,
    update: wc_Sha512_256Update,
    finalize: wc_Sha512_256Final,
    free: wc_Sha512_256Free,
    copy: wc_Sha512_256Copy
}
