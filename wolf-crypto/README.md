
# Table of Contents

1.  [`wolf-crypto`](#org08cbf70)
2.  [Current Priorities](#org8407ef1)
3.  [License](#org8ca1b81)
4.  [Notes](#orgc0d723c)
5.  [Roadmap <code>[1/5]</code>](#orga982e3e)

**WARNING - THIS LIBRARY IS IN ITS EARLY STAGES, IT IS NOT READY FOR PRODUCTION USE, USE AT YOUR OWN RISK.**


<a id="org08cbf70"></a>

# `wolf-crypto`

This library seeks to provide a safe, zero-cost, API for `wolfcrypt` by wolfSSL. It is in its very early stages, some
feature flags are misleading, for instance `allow-non-fips` implies that when disabled only FIPS 140-3 certified
cryptography is used. This is not currently the case due to the associated `wolf-crypto-sys` not currently leveraging
the `FIPS-MODE` feature. This feature will eventually be enabled, as it was my original reason for beginning to work on
this, though the library as previously mentioned is incredibly immature.

Currently, the `hash` module is the most tested segment of this codebase, outside of this module and the `aes` module
I personally would not be comfortable using anything in a general purpose application (not any of my professional
work in security).


<a id="org8407ef1"></a>

# Current Priorities

-   Focus on implementing and stabilizing the core FIPS 140-3 compatible algorithms.
-   Improve test coverage in hashing, symmetric encryption, and AEAD modules.
-   Incrementally implement and test asymmetric cryptographic functions (RSA, ECDSA, ECDH).
-   Enable `FIPS-MODE` support in `wolf-crypto-sys` to align with the FIPS compliance goals.


<a id="org8ca1b81"></a>

# License

This library is under GPLv2 licensing **unless** you purchased a commercial license from wolfSSL.


<a id="orgc0d723c"></a>

# Notes

-   Affiliation: I am not affiliated with wolfSSL, I just enjoy security and have appreciation for their work.
-   Why is this named `wolf-crypto` and not `wolfcrypt`: I did not want to take the official name by wolfSSL.


<a id="orga982e3e"></a>

# Roadmap <code>[1/5]</code>

-   [X] Hashing <code>[6/6]</code>
    -   [X] SHA2 <code>[6/6]</code>
        -   [X] SHA-224
        -   [X] SHA-256
        -   [X] SHA-384
        -   [X] SHA-512
        -   [X] SHA-512/224
        -   [X] SHA-512/256
    -   [X] SHA3 <code>[5/5]</code>
        -   [X] SHA3-224
        -   [X] SHA3-256
        -   [X] SHA3-384
        -   [X] SHA3-512
        -   [X] SHAKE <code>[2/2]</code>
            -   [X] SHAKE128
            -   [X] SHAKE256
    -   [X] SHA <code>[1/1]</code>
    -   [X] RIPEMD-160 <code>[1/1]</code>
    -   [X] MD <code>[2/2]</code>
        -   [X] MD5
        -   [X] MD4
    -   [X] BLAKE2 <code>[2/2]</code>
        -   [X] BLAKE2b
        -   [X] BLAKE2s

-   [ ] AEAD <code>[1/5]</code>
    -   [X] AES-GCM <code>[3/3]</code>
        -   [X] 256
        -   [X] 192
        -   [X] 128
    -   [ ] ChaCha20-Poly1305 <code>[0/2]</code>
        -   [ ] 256
        -   [ ] 128
    -   [ ] AES-CCM <code>[0/3]</code>
        -   [X] 256
        -   [X] 192
        -   [X] 128
    -   [ ] AES-EAX <code>[0/3]</code>
        -   [ ] 256
        -   [ ] 192
        -   [ ] 128
    -   [ ] AES-SIV <code>[0/3]</code>
        -   [ ] 256
        -   [ ] 192
        -   [ ] 128

-   [ ] Symmetric Encryption <code>[0/3]</code>
    -   [ ] AES <code>[1/4]</code>
        -   [X] CTR <code>[3/3]</code>
            -   [X] 256
            -   [X] 192
            -   [X] 128
        -   [ ] CBC <code>[0/3]</code>
            -   [ ] 256
            -   [ ] 192
            -   [ ] 128
        -   [ ] XTS <code>[0/2]</code>
            -   [ ] 256
            -   [ ] 128
        -   [ ] CFB <code>[0/3]</code>
            -   [ ] 256
            -   [ ] 192
            -   [ ] 128
    -   [ ] ChaCha20 <code>[0/2]</code>
        -   [ ] 256
        -   [ ] 128
    -   [ ] 3DES <code>[0/1]</code>
        -   [ ] 168

-   [ ] MAC <code>[0/2]</code>
    -   [ ] HMAC <code>[0/9]</code>
        -   [ ] SHA-256
        -   [ ] SHA-384
        -   [ ] SHA-512
        -   [ ] SHA3-224
        -   [ ] SHA3-256
        -   [ ] SHA3-384
        -   [ ] SHA3-512
        -   [ ] SHA
        -   [ ] MD5
    -   [ ] Poly1305 <code>[0/1]</code>
        -   [ ] Poly1305

-   [ ] Writing the Remaining Sections (asymmetric, password, padding, etc)

