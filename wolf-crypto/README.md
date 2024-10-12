
# Table of Contents

1.  [`wolf-crypto`](#orga572f47)
2.  [Testing](#org689cd34)
    1.  [Current Test Suite](#org8c1b93d)
        1.  [Property Tests](#org045c894)
        2.  [Unit Tests](#org5d4c2d6)
        3.  [Constant-Time Verification](#org6bd428b)
        4.  [NIST CSRC CAVP Tests](#org8d0dd3d)
        5.  [Official Known Answer Tests (KATs)](#org3de3704)
        6.  [Formal Verification](#orgc5a74b4)
3.  [Goals and Approach](#orgca55fc4)
4.  [Ongoing Testing Priorities](#org44d9ede)
5.  [Current Priorities](#orge1265ef)
6.  [License](#org73b40d6)
7.  [Roadmap <code>[2/6]</code>](#org6c915ae)

**WARNING - THIS LIBRARY IS IN ITS EARLY STAGES, IT IS NOT READY FOR PRODUCTION USE, USE AT YOUR OWN RISK.**


<a id="orga572f47"></a>

# `wolf-crypto`

`wolf-crypto` is a Rust library that provides a safe, zero-cost abstraction over `wolfcrypt`,
the cryptographic library by wolfSSL. Designed to offer memory-safe, type-safe cryptographic
operations, `wolf-crypto` focuses on performance, security, and adherence to FIPS 140-3 standards.

Currently in ****alpha****, the library is undergoing active development and should not be considered
stable for production use. The API is subject to change as we incorporate feedback and continue
to refine the design. However, once the library reaches its first minor release, the API will be
locked in and guaranteed stable\*, with no breaking changes\*.

`wolf-crypto` leverages Rust’s safety guarantees, preventing common vulnerabilities such as memory
leaks, buffer overflows, and other issues prevalent in C-based cryptographic libraries. While still
in alpha, the library has undergone extensive testing and is designed to become an ideal choice
for secure cryptographic operations once it achieves stability.

We encourage feedback from the community as we work toward stabilizing the API, ensuring that
`wolf-crypto` is ready for production use while maintaining FIPS 140-3 compliance, formal
verification, and rigorous testing.


<a id="org689cd34"></a>

# Testing

Given the critical nature of cryptographic libraries, comprehensive testing is fundamental to ensuring
the reliability, security, and correctness of the `wolf-crypto` library. While cryptographic implementations
are inherently sensitive, the library's interaction with foreign function interfaces (FFI) and unsafe Rust
code necessitates rigorous testing across all areas.

Every component of this library is now fully tested to provide maximum confidence in its functionality. Our
approach emphasizes property-based testing, supported by unit testing, formal verification using Kani (for
pure-Rust components), and validation through the NIST CAVP program. Constant-time behavior is verified,
ensuring that operations are secure and timing attacks are mitigated.


<a id="org8c1b93d"></a>

## Current Test Suite


<a id="org045c894"></a>

### Property Tests

Property-based testing is the backbone of our testing framework, ensuring the expected properties of cryptographic
algorithms are upheld across a wide range of inputs.

-   Validate encryption bijectivity: encryption followed by decryption always returns the original plaintext.
-   Verify documented cryptographic properties, such as associativity, commutativity, and other expected behaviors.
-   Stress testing with random and large datasets to uncover edge cases.
-   Cross-verify with other cryptographic libraries for functional equivalence and correctness.


<a id="org5d4c2d6"></a>

### Unit Tests

Unit tests complement the property tests by covering specific edge cases and known boundaries.

-   Edge case testing, including null inputs, minimum-length inputs, and maximum-length outputs.
-   Ensure behavior equivalent to robust implementations (e.g., `rust-crypto`) under these conditions.


<a id="org6bd428b"></a>

### Constant-Time Verification

Cryptographic functions are tested for constant-time behavior with respect to their content, ensuring that no
exploitable timing variations exist based on the values being compared.

-   Automated verification using Haybale Pitchfork from UCSD PLSysSec to confirm that `ct_eq` and similar functions
    behave consistently relative to input content.
-   Manual code audits are performed to ensure no branches or loops could introduce variable timing based on input
    data.


<a id="org8d0dd3d"></a>

### NIST CSRC CAVP Tests

For NIST-recommended algorithms, we conduct thorough testing based on the Cryptographic Algorithm Validation Program
(CAVP) to ensure compliance with industry standards.

-   Monte Carlo tests stress the algorithms using randomized data over thousands of iterations to verify their resilience.
-   Known Answer Tests (KATs) are conducted with short and long datasets to ensure cryptographic correctness and reproducibility.


<a id="org3de3704"></a>

### Official Known Answer Tests (KATs)

For non-NIST algorithms, such as BLAKE2, we perform official Known Answer Tests to ensure the algorithms
conform to standard implementations.

-   Short and long input dataset coverage to ensure consistency across data sizes.
-   Cross-validation with independent implementations and specifications.


<a id="orgc5a74b4"></a>

### Formal Verification

For parts of the library that are pure Rust and do not cross FFI boundaries, formal verification with Kani is
used (carefully to ensure completeness) to provide additional assurance of correctness. This is especially
important for components such as hex encoding, constant-time equality checks, and other key transformations.


<a id="orgca55fc4"></a>

# Goals and Approach

Our testing approach is focused on ensuring that the library is production-ready, highly secure, and meets FIPS 140-3 compliance standards.

-   Secure design: Enforcing best practices like zeroing secrets from memory after use to prevent unintended data exposure.
-   Compile-time FIPS compliance: Using Rust’s type system to enforce FIPS restrictions at compile time and ensure correct usage.
-   Continuous testing: As the library evolves, new algorithms undergo rigorous testing to guarantee their security and correctness.


<a id="org44d9ede"></a>

# Ongoing Testing Priorities

Our testing framework is continuously evolving, with ongoing efforts focused on:

-   Strengthening FIPS 140-3 enforcement, ensuring that algorithms in FIPS scope are properly handled at compile time.
-   Expanding performance and scalability testing, ensuring that the library operates efficiently under high-load scenarios.
-   Adding new algorithms and immediately subjecting them to the full suite of tests to ensure their robustness and correctness.


<a id="orge1265ef"></a>

# Current Priorities

-   Focus on implementing and stabilizing the core FIPS 140-3 compatible algorithms.
-   Create a clear boundary between algorithms in FIPS scope, without the `allow-non-fips`
    feature enabled attempt to enforce FIPS requirements in usage at compilation time.
-   Continual improvements in testing and documentation.
-   Expose more algorithms offered by wolfSSL's `wolfcrypt`.


<a id="org73b40d6"></a>

# License

This library is under GPLv2 licensing **unless** you purchased a commercial license from wolfSSL.


<a id="org6c915ae"></a>

# Roadmap <code>[2/6]</code>

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
    -   [X] SHA
    -   [X] RIPEMD-160
    -   [X] MD <code>[2/2]</code>
        -   [X] MD5
        -   [X] MD4
    -   [X] BLAKE2 <code>[2/2]</code>
        -   [X] BLAKE2b
        -   [X] BLAKE2s

-   [-] AEAD <code>[2/5]</code>
    -   [X] AES-GCM <code>[3/3]</code>
        -   [X] 256
        -   [X] 192
        -   [X] 128
    -   [X] ChaCha20-Poly1305 <code>[2/2]</code>
        -   [X] 256
        -   [X] 128
    -   [ ] AES-CCM <code>[0/3]</code>
        -   [ ] 256
        -   [ ] 192
        -   [ ] 128
    -   [ ] AES-EAX <code>[0/3]</code>
        -   [ ] 256
        -   [ ] 192
        -   [ ] 128
    -   [ ] AES-SIV <code>[0/3]</code>
        -   [ ] 256
        -   [ ] 192
        -   [ ] 128

-   [-] Symmetric Encryption <code>[1/3]</code>
    -   [-] AES <code>[1/4]</code>
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
    -   [X] ChaCha20 <code>[2/2]</code>
        -   [X] 256
        -   [X] 128
    -   [ ] 3DES <code>[0/1]</code>
        -   [ ] 168

-   [X] MAC <code>[2/2]</code>
    -   [X] HMAC <code>[9/9]</code>
        -   [X] SHA-256
        -   [X] SHA-384
        -   [X] SHA-512
        -   [X] SHA3-224
        -   [X] SHA3-256
        -   [X] SHA3-384
        -   [X] SHA3-512
        -   [X] SHA
        -   [X] MD5
    -   [X] Poly1305
-   [-] KDF <code>[3/4]</code>
    -   [X] HKDF
    -   [X] PBKDF1
    -   [X] PBKDF2
    -   [ ] PKCS12 PBKDF

-   [ ] Writing the Remaining Sections (asymmetric, password, padding, etc)

