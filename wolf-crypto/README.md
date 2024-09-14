
# Table of Contents

1.  [`wolf-crypto`](#orgce80e76)
2.  [Current Priorities](#orgc1c62b2)
3.  [License](#orgae43b97)
4.  [Notes](#org180719d)
5.  [Roadmap <code>[0/5]</code>](#org5d68716)
    1.  [Hashing <code>[4/6]</code>](#orgf1d2c62)
        1.  [SHA2 <code>[6/6]</code>](#orge46e7c1)
        2.  [SHA3 <code>[5/5]</code>](#orgcc81c61)
        3.  [SHA <code>[0/1]</code>](#orged42677)
        4.  [RIPEMD-160 <code>[1/1]</code>](#org557f80c)
        5.  [MD <code>[2/2]</code>](#org27cdd82)
        6.  [BLAKE2 <code>[1/2]</code>](#org776d770)
    2.  [AEAD <code>[1/5]</code>](#org08de865)
        1.  [AES-GCM <code>[3/3]</code>](#org5f1c6c5)
        2.  [ChaCha20-Poly1305 <code>[0/2]</code>](#org31f3d77)
        3.  [AES-CCM <code>[0/3]</code>](#org01df701)
        4.  [AES-EAX <code>[0/3]</code>](#org4b4b015)
        5.  [AES-SIV <code>[0/3]</code>](#org32c1f36)
    3.  [Symmetric Encryption <code>[0/3]</code>](#org286805f)
        1.  [AES <code>[1/4]</code>](#orgaecf591)
        2.  [ChaCha20 <code>[0/2]</code>](#orge81d5ac)
        3.  [3DES <code>[0/1]</code>](#orgffcb237)
    4.  [MAC <code>[0/2]</code>](#org5c286e3)
        1.  [HMAC <code>[0/9]</code>](#org19c1aae)
        2.  [Poly1305 <code>[0/1]</code>](#orgb20b339)
    5.  [Writing the Remaining Sections (asymmetric, password, padding, etc)](#orga91497b)

**WARNING - THIS LIBRARY IS IN ITS EARLY STAGES, IT IS NOT READY FOR PRODUCTION USE, USE AT YOUR OWN RISK.**


<a id="orgce80e76"></a>

# `wolf-crypto`

This library seeks to provide a safe, zero-cost, API for `wolfcrypt` by wolfSSL. It is in its very early stages, some
feature flags are misleading, for instance `allow-non-fips` implies that when disabled only FIPS 140-3 certified
cryptography is used. This is not currently the case due to the associated `wolf-crypto-sys` not currently leveraging
the `FIPS-MODE` feature. This feature will eventually be enabled, as it was my original reason for beginning to work on
this, though the library as previously mentioned is incredibly immature.

Currently, the `hash` module is the most tested segment of this codebase, outside of this module and the `aes` module
I personally would not be comfortable using anything in a general purpose application (not any of my professional
work in security).


<a id="orgc1c62b2"></a>

# Current Priorities

-   Focus on implementing and stabilizing the core FIPS 140-3 compatible algorithms.
-   Improve test coverage in hashing, symmetric encryption, and AEAD modules.
-   Incrementally implement and test asymmetric cryptographic functions (RSA, ECDSA, ECDH).
-   Enable `FIPS-MODE` support in `wolf-crypto-sys` to align with the FIPS compliance goals.


<a id="orgae43b97"></a>

# License

This library is under GPLv2 licensing **unless** you purchased a commercial license from wolfSSL.


<a id="org180719d"></a>

# Notes

-   Affiliation: I am not affiliated with wolfSSL, I just enjoy security and have appreciation for their work.
-   Why is this named `wolf-crypto` and not `wolfcrypt`: I did not want to take the official name by wolfSSL.


<a id="org5d68716"></a>

# TODO Roadmap <code>[0/5]</code>


<a id="orgf1d2c62"></a>

## TODO Hashing <code>[4/6]</code>


<a id="orge46e7c1"></a>

### DONE SHA2 <code>[6/6]</code>

1.  DONE SHA-224

2.  DONE SHA-256

3.  DONE SHA-384

4.  DONE SHA-512

5.  DONE SHA-512/224

6.  DONE SHA-512/256


<a id="orgcc81c61"></a>

### DONE SHA3 <code>[5/5]</code>

1.  DONE SHA3-224

2.  DONE SHA3-256

3.  DONE SHA3-384

4.  DONE SHA3-512

5.  DONE SHAKE <code>[2/2]</code>

    1.  DONE SHAKE128
    
    2.  DONE SHAKE256


<a id="orged42677"></a>

### TODO SHA <code>[0/1]</code>


<a id="org557f80c"></a>

### DONE RIPEMD-160 <code>[1/1]</code>


<a id="org27cdd82"></a>

### DONE MD <code>[2/2]</code>

1.  DONE MD5

2.  DONE MD4


<a id="org776d770"></a>

### TODO BLAKE2 <code>[1/2]</code>

1.  DONE BLAKE2b

2.  TODO BLAKE2s


<a id="org08de865"></a>

## TODO AEAD <code>[1/5]</code>


<a id="org5f1c6c5"></a>

### DONE AES-GCM <code>[3/3]</code>

1.  DONE 256

2.  DONE 192

3.  DONE 128


<a id="org31f3d77"></a>

### TODO ChaCha20-Poly1305 <code>[0/2]</code>

1.  TODO 256

2.  TODO 128


<a id="org01df701"></a>

### TODO AES-CCM <code>[0/3]</code>

1.  DONE 256

2.  DONE 192

3.  DONE 128


<a id="org4b4b015"></a>

### TODO AES-EAX <code>[0/3]</code>

1.  TODO 256

2.  TODO 192

3.  TODO 128


<a id="org32c1f36"></a>

### TODO AES-SIV <code>[0/3]</code>

1.  TODO 256

2.  TODO 192

3.  TODO 128


<a id="org286805f"></a>

## TODO Symmetric Encryption <code>[0/3]</code>


<a id="orgaecf591"></a>

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


<a id="orge81d5ac"></a>

### TODO ChaCha20 <code>[0/2]</code>

1.  TODO 256

2.  TODO 128


<a id="orgffcb237"></a>

### TODO 3DES <code>[0/1]</code>

1.  TODO 168


<a id="org5c286e3"></a>

## TODO MAC <code>[0/2]</code>


<a id="org19c1aae"></a>

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


<a id="orgb20b339"></a>

### TODO Poly1305 <code>[0/1]</code>


<a id="orga91497b"></a>

## TODO Writing the Remaining Sections (asymmetric, password, padding, etc)

