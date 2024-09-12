use wolf_crypto_sys::{
    Md4 as wc_Md4,
    wc_Md4Update, wc_Md4Final,
    wc_InitMd4
};

make_api! {
    sec_warning: "MD4 has been considered **fully compromised** since 1995, with original \
                  weaknesses published in 1991, as of 2007 an attack can generate collisions in \
                  less than two MD4 hash operations.",
    name: Md4,
    wc: wc_Md4,
    bs: 16,
    init: = void wc_InitMd4,
    update: = void wc_Md4Update,
    finalize: = void wc_Md4Final,
    needs-reset: true
}