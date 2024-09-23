use wolf_crypto_sys::{
    wc_ChaCha20Poly1305_Init,
    ChaChaPoly_Aead,
    wc_ChaCha20Poly1305_UpdateData, wc_ChaCha20Poly1305_UpdateAad,
    wc_ChaCha20Poly1305_Final,
    CHACHA20_POLY1305_AEAD_DECRYPT, CHACHA20_POLY1305_AEAD_ENCRYPT,

    wc_ChaCha20Poly1305_Decrypt, wc_ChaCha20Poly1305_Encrypt,
};

