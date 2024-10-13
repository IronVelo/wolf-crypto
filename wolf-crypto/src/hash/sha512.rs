use wolf_crypto_sys::{
    wc_Sha512,
    wc_Sha512Update, wc_Sha512Final,
    wc_InitSha512, wc_Sha512Free,
    wc_Sha512Copy
};

mark_fips! { Sha512, Sealed }

make_api! {
    name: Sha512,
    wc: wc_Sha512,
    bs: 64,
    init: wc_InitSha512,
    update: wc_Sha512Update,
    finalize: wc_Sha512Final,
    free: wc_Sha512Free,
    copy: wc_Sha512Copy
}
