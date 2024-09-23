
# Table of Contents

1.  [`wolf-crypto`](#org0b82cf3)
2.  [Testing](#org5c8ab4e)
    1.  [Current Test Suite](#org947b63f)
        1.  [Unit Tests](#org22137e8)
        2.  [Property Tests](#org3de3754)
        3.  [NIST CSRC CAVP Tests](#org5c8f92f)
        4.  [Official KATs (Known Answer Tests)](#org54a30c5)
    2.  [Goals and Approach](#org787601f)
    3.  [Comparison with `wolfcrypt`](#org42350d8)
    4.  [Formal Verification Considerations](#orgda5b268)
        1.  [Current Tools and Limitations](#orge12ba63)
        2.  [Future Prospects](#orgecea49c)
        3.  [Important Note on Limitations](#orgb1a6f6a)
    5.  [Future Enhancements](#orgd71683d)
        1.  [Constant-time Behavior Testing](#org6b068dc)
        2.  [Expanded Test Coverage](#orgc37014f)
3.  [Current Priorities](#orgdf44488)
4.  [License](#org21c8e0d)
5.  [Notes](#org8a949af)
6.  [Roadmap <code>[1/5]</code>](#org591a529)

**WARNING - THIS LIBRARY IS IN ITS EARLY STAGES, IT IS NOT READY FOR PRODUCTION USE, USE AT YOUR OWN RISK.**

<a id="org0b82cf3"></a>

# `wolf-crypto`

This library seeks to provide a safe, zero-cost, API for `wolfcrypt` by wolfSSL. It is in its very early stages, some
feature flags are misleading, for instance `allow-non-fips` implies that when disabled only FIPS 140-3 certified
cryptography is used. This is not currently the case due to the associated `wolf-crypto-sys` not currently leveraging
the `FIPS-MODE` feature. This feature will eventually be enabled, as it was my original reason for beginning to work on
this, though the library as previously mentioned is incredibly immature.

Currently, the `hash` module is the most tested segment of this codebase, outside of this module and the `aes` module
I personally would not be comfortable using anything in a general purpose application (not any of my professional
work in security).


<a id="org5c8ab4e"></a>

# Testing

Despite not implementing cryptography by hand, this library deals with cryptography and FFI (involving `unsafe` code).
Consequently, comprehensive testing is crucial. Although still in alpha, we maintain an extensive test suite:


<a id="org947b63f"></a>

## Current Test Suite


<a id="org22137e8"></a>

### Unit Tests

-   Check edge cases
-   Ensure behavior equivalent to robust implementations (e.g., `rust-crypto`) under these edge cases.


<a id="org3de3754"></a>

### Property Tests

-   Verify expected properties (e.g., encryption bijectivity).
-   Confirm documented properties.
-   Compare against robust implementations for equivalence.


<a id="org5c8f92f"></a>

### NIST CSRC CAVP Tests

-   Implemented for hashing functions (current or previously NIST-recommended).
-   Includes:
    -   Monte-Carlo tests.
    -   Known Answer tests (short and long datasets).


<a id="org54a30c5"></a>

### Official KATs (Known Answer Tests)

-   Used for algorithms not covered by NIST CAVP.
-   Example: BLAKE2 algorithm.


<a id="org787601f"></a>

## Goals and Approach

-   Aim for production-ready robustness by first minor release.
-   Design as a thin, type-safe, and memory-safe wrapper around FIPS 140-3 certified `wolfcrypt`.
-   Careful to avoid introducing security risks.
-   Enforce secure programming practices (e.g., prompt zeroing of secrets from memory).


<a id="org42350d8"></a>

## Comparison with `wolfcrypt`

-   `wolfcrypt` has undergone necessary testing and validation for FIPS 140-3 certification.
-   We apply rigorous testing to our abstraction layer.
-   Ensure we don't inadvertently violate underlying certified properties.
-   Build confidence through equivalence testing with other Rust cryptography projects.


<a id="orgda5b268"></a>

## Formal Verification Considerations

-   Not formally verified due to impracticality with current Rust tools and FFI.
-   Formal verification is rare but highly valuable for ensuring correctness.
-   Attempting to formally verify our API would have minimal benefits due to necessary assumptions about `wolfcrypt`.


<a id="orge12ba63"></a>

### Current Tools and Limitations

1.  `Prusti`

    -   Handling of lifetimes is practically non-existent.
    -   Viper framework struggles with prophecies.
    -   Workaround: Creating assumed-correct functions that `snap` underlying data, stripping lifetimes.

2.  `Creusot`

    -   Built on Why3 with comma lang.
    -   Excellent handling of lifetimes using prophecies (based on Martín Abadi and Leslie Lamport's work).
    -   Challenges:
        -   Installation can be difficult (script issues, manual installation sometimes necessary).
        -   Requires nightly Rust, even when not verifying specifications.
        -   Necessitates conditional compilation for everything.

3.  `Kani`

    -   Less rigorous than `Prusti` or `Creusot`, but useful for libraries lacking formal verification.
    -   Currently lacks proper FFI support, limiting its applicability to this crate.
    -   This crate implements `Kani`'s `Arbitrary` trait for certain types.
    -   Some `proofs` using `Kani` are included, anticipating future improvements in FFI support.


<a id="orgecea49c"></a>

### Future Prospects

-   Formal verification tools in Rust are promising but still in early stages.
-   As tools improve, particularly in handling FFI, more comprehensive verification may become feasible.
-   Continuous monitoring of advancements in formal verification for Rust.


<a id="orgb1a6f6a"></a>

### Important Note on Limitations

Even with potential future formal verification of our API, it would not constitute complete formal verification
as `wolfcrypt`, the underlying cryptographic module, is not formally verified. True formal guarantees would
require formal verification of both our API and the underlying `wolfcrypt` implementation.


<a id="orgd71683d"></a>

## Future Enhancements


<a id="org6b068dc"></a>

### Constant-time Behavior Testing

-   Challenge: High-level abstraction introduces noise in black-box testing.
-   Considerations:
    -   `wolfcrypt`'s cryptography implementation is constant-time.
    -   Public API includes non-constant-time checks.
-   Potential approaches:
    -   Manual review of assembly.
    -   High-level taint analysis (challenging across FFI).
-   Importance: Preventing information leakage.


<a id="orgc37014f"></a>

### Expanded Test Coverage

-   Focus on security properties beyond traditional code coverage.
-   Implement more sophisticated constant-time behavior tests when feasible.


<a id="orgdf44488"></a>

# Current Priorities

-   Focus on implementing and stabilizing the core FIPS 140-3 compatible algorithms.
-   Improve test coverage in hashing, symmetric encryption, and AEAD modules.
-   Incrementally implement and test asymmetric cryptographic functions (RSA, ECDSA, ECDH).
-   Enable `FIPS-MODE` support in `wolf-crypto-sys` to align with the FIPS compliance goals.


<a id="org21c8e0d"></a>

# License

This library is under GPLv2 licensing **unless** you purchased a commercial license from wolfSSL.


<a id="org8a949af"></a>

# Notes

-   Affiliation: I am not affiliated with wolfSSL, I just enjoy security and have appreciation for their work.
-   Why is this named `wolf-crypto` and not `wolfcrypt`: I did not want to take the official name by wolfSSL.


<a id="org591a529"></a>

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

