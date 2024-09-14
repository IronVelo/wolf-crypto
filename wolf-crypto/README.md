
# Table of Contents

1.  [`wolf-crypto`](#org7e85d3e)
2.  [Current Priorities](#orgeb1dcb9)
3.  [License](#org767daa7)
4.  [Notes](#org225dcfd)
5.  [Roadmap <code>[0/5]</code>](#orgbaa6c62)
    1.  [Hashing <code>[5/6]</code>](#org0f47777)
        1.  [SHA2 <code>[6/6]</code>](#org46716c5)
        2.  [SHA3 <code>[5/5]</code>](#orgbb6bfdf)
        3.  [SHA <code>[1/1]</code>](#org6883056)
        4.  [RIPEMD-160 <code>[1/1]</code>](#orgd571cc3)
        5.  [MD <code>[2/2]</code>](#orgea01bf9)
        6.  [BLAKE2 <code>[1/2]</code>](#org737eae0)
    2.  [AEAD <code>[1/5]</code>](#orgb10f2fb)
        1.  [AES-GCM <code>[3/3]</code>](#orga22a233)
        2.  [ChaCha20-Poly1305 <code>[0/2]</code>](#orga49d53b)
        3.  [AES-CCM <code>[0/3]</code>](#org152bee3)
        4.  [AES-EAX <code>[0/3]</code>](#org194a8e5)
        5.  [AES-SIV <code>[0/3]</code>](#org9d1d2bd)
    3.  [Symmetric Encryption <code>[0/3]</code>](#org2748b6f)
        1.  [AES <code>[1/4]</code>](#org14bc9af)
        2.  [ChaCha20 <code>[0/2]</code>](#orgad8306d)
        3.  [3DES <code>[0/1]</code>](#orgc1be5da)
    4.  [MAC <code>[0/2]</code>](#org35f816b)
        1.  [HMAC <code>[0/9]</code>](#org26434a3)
        2.  [Poly1305 <code>[0/1]</code>](#org0a99d7c)
    5.  [Writing the Remaining Sections (asymmetric, password, padding, etc)](#org2aec607)

**WARNING - THIS LIBRARY IS IN ITS EARLY STAGES, IT IS NOT READY FOR PRODUCTION USE, USE AT YOUR OWN RISK.**


<a id="org7e85d3e"></a>

# `wolf-crypto`

This library seeks to provide a safe, zero-cost, API for `wolfcrypt` by wolfSSL. It is in its very early stages, some
feature flags are misleading, for instance `allow-non-fips` implies that when disabled only FIPS 140-3 certified
cryptography is used. This is not currently the case due to the associated `wolf-crypto-sys` not currently leveraging
the `FIPS-MODE` feature. This feature will eventually be enabled, as it was my original reason for beginning to work on
this, though the library as previously mentioned is incredibly immature.

Currently, the `hash` module is the most tested segment of this codebase, outside of this module and the `aes` module
I personally would not be comfortable using anything in a general purpose application (not any of my professional
work in security).


<a id="orgeb1dcb9"></a>

# Current Priorities

-   Focus on implementing and stabilizing the core FIPS 140-3 compatible algorithms.
-   Improve test coverage in hashing, symmetric encryption, and AEAD modules.
-   Incrementally implement and test asymmetric cryptographic functions (RSA, ECDSA, ECDH).
-   Enable `FIPS-MODE` support in `wolf-crypto-sys` to align with the FIPS compliance goals.


<a id="org767daa7"></a>

# License

This library is under GPLv2 licensing **unless** you purchased a commercial license from wolfSSL.


<a id="org225dcfd"></a>

# Notes

-   Affiliation: I am not affiliated with wolfSSL, I just enjoy security and have appreciation for their work.
-   Why is this named `wolf-crypto` and not `wolfcrypt`: I did not want to take the official name by wolfSSL.


<a id="orgbaa6c62"></a>

# TODO Roadmap <code>[0/5]</code>


<a id="org0f47777"></a>

## TODO Hashing <code>[5/6]</code>


<a id="org46716c5"></a>

### DONE SHA2 <code>[6/6]</code>

1.  DONE SHA-224

2.  DONE SHA-256

3.  DONE SHA-384

4.  DONE SHA-512

5.  DONE SHA-512/224

6.  DONE SHA-512/256


<a id="orgbb6bfdf"></a>

### DONE SHA3 <code>[5/5]</code>

1.  DONE SHA3-224

2.  DONE SHA3-256

3.  DONE SHA3-384

4.  DONE SHA3-512

5.  DONE SHAKE <code>[2/2]</code>

    1.  DONE SHAKE128
    
    2.  DONE SHAKE256


<a id="org6883056"></a>

### DONE SHA <code>[1/1]</code>


<a id="orgd571cc3"></a>

### DONE RIPEMD-160 <code>[1/1]</code>


<a id="orgea01bf9"></a>

### DONE MD <code>[2/2]</code>

1.  DONE MD5

2.  DONE MD4


<a id="org737eae0"></a>

### TODO BLAKE2 <code>[1/2]</code>

1.  DONE BLAKE2b

2.  TODO BLAKE2s


<a id="orgb10f2fb"></a>

## TODO AEAD <code>[1/5]</code>


<a id="orga22a233"></a>

### DONE AES-GCM <code>[3/3]</code>

1.  DONE 256

2.  DONE 192

3.  DONE 128


<a id="orga49d53b"></a>

### TODO ChaCha20-Poly1305 <code>[0/2]</code>

1.  TODO 256

2.  TODO 128


<a id="org152bee3"></a>

### TODO AES-CCM <code>[0/3]</code>

1.  DONE 256

2.  DONE 192

3.  DONE 128


<a id="org194a8e5"></a>

### TODO AES-EAX <code>[0/3]</code>

1.  TODO 256

2.  TODO 192

3.  TODO 128


<a id="org9d1d2bd"></a>

### TODO AES-SIV <code>[0/3]</code>

1.  TODO 256

2.  TODO 192

3.  TODO 128


<a id="org2748b6f"></a>

## TODO Symmetric Encryption <code>[0/3]</code>


<a id="org14bc9af"></a>

### TODO AES <code>[1/4]</code>

1.  DONE CTR <code>[3/3]</code>

    1.  DONE 256
    
    2.  DONE 192
    
    3.  DONE 128

2.  TODO CBC <code>[0/3]</code>

    1.  TODO 256
    
    2.  TODO 192
    
    3.  TODO 128

3.  TODO XTS <code>[0/2]</code>

    1.  TODO 256
    
    2.  TODO 128

4.  TODO CFB <code>[0/3]</code>

    1.  TODO 256
    
    2.  TODO 192
    
    3.  TODO 128


<a id="orgad8306d"></a>

### TODO ChaCha20 <code>[0/2]</code>

1.  TODO 256

2.  TODO 128


<a id="orgc1be5da"></a>

### TODO 3DES <code>[0/1]</code>

1.  TODO 168


<a id="org35f816b"></a>

## TODO MAC <code>[0/2]</code>


<a id="org26434a3"></a>

### TODO HMAC <code>[0/9]</code>

1.  TODO SHA-256

2.  TODO SHA-384

3.  TODO SHA-512

4.  TODO SHA3-224

5.  TODO SHA3-256

6.  TODO SHA3-384

7.  TODO SHA3-512

8.  TODO SHA

9.  TODO MD5


<a id="org0a99d7c"></a>

### TODO Poly1305 <code>[0/1]</code>


<a id="org2aec607"></a>

## TODO Writing the Remaining Sections (asymmetric, password, padding, etc)

