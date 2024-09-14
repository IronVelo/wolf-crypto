use wolf_crypto_sys::{
    wc_Md5,
    wc_Md5Update, wc_Md5Final,
    wc_InitMd5, wc_Md5Free,
    wc_Md5Copy
};

make_api! {
    sec_warning: "MD5 should be [considered cryptographically broken and unsuitable for further use](https://www.kb.cert.org/vuls/id/836068). \
                  Collision attacks against MD5 are both practical and trivial, and theoretical \
                  attacks against MD5 have been found.",
    name: Md5,
    wc: wc_Md5,
    bs: 16,
    init: wc_InitMd5,
    update: wc_Md5Update,
    finalize: wc_Md5Final,
    free: wc_Md5Free,
    copy: wc_Md5Copy
}