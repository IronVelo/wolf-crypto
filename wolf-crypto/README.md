
# Table of Contents

1.  [`wolf-crypto`](#org44906f4)
2.  [Current Priorities](#org9c453ad)
3.  [License](#orgb5efdb8)
4.  [Notes](#org98b8bb0)
5.  [Roadmap <code>[1/5]</code>](#orgb4bc83b)
    1.  [Hashing <code>[6/6]</code>](#orgfc1da6b)
        1.  [SHA2 <code>[6/6]</code>](#orgbb68353)
        2.  [SHA3 <code>[5/5]</code>](#org17bfb4b)
        3.  [SHA <code>[1/1]</code>](#org007821d)
        4.  [RIPEMD-160 <code>[1/1]</code>](#org300ae96)
        5.  [MD <code>[2/2]</code>](#orgb955a53)
        6.  [BLAKE2 <code>[2/2]</code>](#org8b0f630)
    2.  [AEAD <code>[1/5]</code>](#orgbe8c0da)
        1.  [AES-GCM <code>[3/3]</code>](#org99dfbf8)
        2.  [ChaCha20-Poly1305 <code>[0/2]</code>](#org125bddc)
        3.  [AES-CCM <code>[0/3]</code>](#org8f3ae01)
        4.  [AES-EAX <code>[0/3]</code>](#orgf2c5b59)
        5.  [AES-SIV <code>[0/3]</code>](#org3c658b6)
    3.  [Symmetric Encryption <code>[0/3]</code>](#orgd432248)
        1.  [AES <code>[1/4]</code>](#orgf53b3e8)
        2.  [ChaCha20 <code>[0/2]</code>](#orgb8364e6)
        3.  [3DES <code>[0/1]</code>](#orgecc464a)
    4.  [MAC <code>[0/2]</code>](#orga96262a)
        1.  [HMAC <code>[0/9]</code>](#orgb90f93e)
        2.  [Poly1305 <code>[0/1]</code>](#org32a9b44)
    5.  [Writing the Remaining Sections (asymmetric, password, padding, etc)](#orgde728c0)

**WARNING - THIS LIBRARY IS IN ITS EARLY STAGES, IT IS NOT READY FOR PRODUCTION USE, USE AT YOUR OWN RISK.**


<a id="org44906f4"></a>

# `wolf-crypto`

This library seeks to provide a safe, zero-cost, API for `wolfcrypt` by wolfSSL. It is in its very early stages, some
feature flags are misleading, for instance `allow-non-fips` implies that when disabled only FIPS 140-3 certified
cryptography is used. This is not currently the case due to the associated `wolf-crypto-sys` not currently leveraging
the `FIPS-MODE` feature. This feature will eventually be enabled, as it was my original reason for beginning to work on
this, though the library as previously mentioned is incredibly immature.

Currently, the `hash` module is the most tested segment of this codebase, outside of this module and the `aes` module
I personally would not be comfortable using anything in a general purpose application (not any of my professional
work in security).


<a id="org9c453ad"></a>

# Current Priorities

-   Focus on implementing and stabilizing the core FIPS 140-3 compatible algorithms.
-   Improve test coverage in hashing, symmetric encryption, and AEAD modules.
-   Incrementally implement and test asymmetric cryptographic functions (RSA, ECDSA, ECDH).
-   Enable `FIPS-MODE` support in `wolf-crypto-sys` to align with the FIPS compliance goals.


<a id="orgb5efdb8"></a>

# License

This library is under GPLv2 licensing **unless** you purchased a commercial license from wolfSSL.


<a id="org98b8bb0"></a>

# Notes

-   Affiliation: I am not affiliated with wolfSSL, I just enjoy security and have appreciation for their work.
-   Why is this named `wolf-crypto` and not `wolfcrypt`: I did not want to take the official name by wolfSSL.


<a id="orgb4bc83b"></a>

# TODO Roadmap <code>[1/5]</code>


<a id="orgfc1da6b"></a>

## DONE Hashing <code>[6/6]</code>


<a id="orgbb68353"></a>

### DONE SHA2 <code>[6/6]</code>

1.  DONE SHA-224

2.  DONE SHA-256

3.  DONE SHA-384

4.  DONE SHA-512

5.  DONE SHA-512/224

6.  DONE SHA-512/256


<a id="org17bfb4b"></a>

### DONE SHA3 <code>[5/5]</code>

1.  DONE SHA3-224

2.  DONE SHA3-256

3.  DONE SHA3-384

4.  DONE SHA3-512

5.  DONE SHAKE <code>[2/2]</code>

    1.  DONE SHAKE128
    
    2.  DONE SHAKE256


<a id="org007821d"></a>

### DONE SHA <code>[1/1]</code>


<a id="org300ae96"></a>

### DONE RIPEMD-160 <code>[1/1]</code>


<a id="orgb955a53"></a>

### DONE MD <code>[2/2]</code>

1.  DONE MD5

2.  DONE MD4


<a id="org8b0f630"></a>

### DONE BLAKE2 <code>[2/2]</code>

1.  DONE BLAKE2b

2.  DONE BLAKE2s


<a id="orgbe8c0da"></a>

## TODO AEAD <code>[1/5]</code>


<a id="org99dfbf8"></a>

### DONE AES-GCM <code>[3/3]</code>

1.  DONE 256

2.  DONE 192

3.  DONE 128


<a id="org125bddc"></a>

### TODO ChaCha20-Poly1305 <code>[0/2]</code>

1.  TODO 256

2.  TODO 128


<a id="org8f3ae01"></a>

### TODO AES-CCM <code>[0/3]</code>

1.  DONE 256

2.  DONE 192

3.  DONE 128


<a id="orgf2c5b59"></a>

### TODO AES-EAX <code>[0/3]</code>

1.  TODO 256

2.  TODO 192

3.  TODO 128


<a id="org3c658b6"></a>

### TODO AES-SIV <code>[0/3]</code>

1.  TODO 256

2.  TODO 192

3.  TODO 128


<a id="orgd432248"></a>

## TODO Symmetric Encryption <code>[0/3]</code>


<a id="orgf53b3e8"></a>

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


<a id="orgb8364e6"></a>

### TODO ChaCha20 <code>[0/2]</code>

1.  TODO 256

2.  TODO 128


<a id="orgecc464a"></a>

### TODO 3DES <code>[0/1]</code>

1.  TODO 168


<a id="orga96262a"></a>

## TODO MAC <code>[0/2]</code>


<a id="orgb90f93e"></a>

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


<a id="org32a9b44"></a>

### TODO Poly1305 <code>[0/1]</code>


<a id="orgde728c0"></a>

## TODO Writing the Remaining Sections (asymmetric, password, padding, etc)

