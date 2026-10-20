
# Table of Contents

1.  [NIST MCT and KATs](#orgb5a06e6)
    1.  [Introduction](#org5381d88)
    2.  [Current State](#org67529c5)
    3.  [Requirements To Run Tests](#orgafb45e2)
2.  [HMAC](#org73d97ab)
3.  [ECC (ECDSA and ECC CDH)](#orgecc0001)
4.  [AES Key Wrap (KW)](#orgkw00001)
5.  [Hash_DRBG](#orgdrbg0001)


<a id="orgb5a06e6"></a>

# NIST MCT and KATs


<a id="org5381d88"></a>

## Introduction

These tests are sourced from
[cryptographic-algorithm-validation-program](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing),
since these files are massive, they are not included in the git repository, instead they are downloaded when
you run the tests.

The destination for these files is in the `test-vectors` directory. If you wish to run the tests and not keep these
artifacts around you may delete this directory manually. It is not automatically cleaned up as again, these test
suites are very large, and it takes around 8 seconds on my machine to load initially.

For more information on this test suite, please see the relevant papers from NIST:

-   [Description of Known Answer Test (KAT) and Monte Carlo Test (MCT) for SHA-3 Candidate Algorithm Submissions](https://csrc.nist.gov/CSRC/media/Projects/Hash-Functions/documents/SHA3-KATMCT1.pdf)
-   [The Secure Hash Algorithm Validation System (SHAVS)](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/SHAVS.pdf)


<a id="org67529c5"></a>

## Current State

The test suite is almost complete, the SHAVS / SHA-3 Candidate Algorithm Submissions tests are complete for
everything outside of `SHAKE`. 

To address `SHAKE` a new parser for it must be implemented for the MCTs and KATs, after this is complete
implementing the tests will be straight forward. There is not much heavy lifting involved in this, but
much work needs to be put in (in the free time that I have) for ensuring that these tests are being performed
**correctly**. 

We have a utility for loading the necessary associated data with each test from NIST, and validators to
ensure that all sources are truly from NIST. These run for any missing testing data, checking the
`test-vectors` directory on startup.

The next steps are:

1.  [X] Create SHA-1 Monte Carlo Tests
2.  [X] Create parser for other forms of tests
3.  [X] Create tests for each hashing function using aforementioned parser
4.  [ ] Create augmented MCT parser for SHAKE
5.  [ ] Create SHAKE MCT tests


<a id="orgafb45e2"></a>

## Requirements To Run Tests

Right now, I've written these tests with linux users in mind, as I am a linux user myself. I'm sure
mac users also are capable of running these tests, but I am not positive. To avoid including more dependencies
or implementing higher level protocols over `TcpStream` I directly call `wget` and `unzip` to load the
test data.

If we break this out into a library, it probably would be a good call to avoid these dependencies, but for
now they are here.

So, again, you will need to have these installed on your machine to run the test suite:

-   `wget`
-   `unzip`


<a id="org73d97ab"></a>

# HMAC

HMAC CAVP (HMACVS) is implemented. The test requires `allow-non-fips` to be enabled, this is because the test vectors
include keys which are not FIPS compliant.


<a id="orgecc0001"></a>

# ECC (ECDSA and ECC CDH)

`nist_ecc.rs` runs the CAVP vectors for the `ecc` module. Unlike the hash vectors these are small, so the
needed subset is committed under `vectors/` and the tests run offline.

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">
<thead>
<tr><th scope="col" class="org-left">File</th><th scope="col" class="org-left">Source file in the CAVP zip</th><th scope="col" class="org-left">Sections kept</th></tr>
</thead>
<tbody>
<tr><td class="org-left"><code>vectors/ecdsa/SigVer.rsp</code></td><td class="org-left"><code>186-4ecdsatestvectors/SigVer.rsp</code></td><td class="org-left"><code>[P-256,SHA-256]</code>, <code>[P-384,SHA-384]</code></td></tr>
<tr><td class="org-left"><code>vectors/ecdsa/SigGen.txt</code></td><td class="org-left"><code>186-4ecdsatestvectors/SigGen.txt</code></td><td class="org-left"><code>[P-256,SHA-256]</code>, <code>[P-384,SHA-384]</code></td></tr>
<tr><td class="org-left"><code>vectors/ecdsa/PKV.rsp</code></td><td class="org-left"><code>186-4ecdsatestvectors/PKV.rsp</code></td><td class="org-left"><code>[P-256]</code>, <code>[P-384]</code></td></tr>
<tr><td class="org-left"><code>vectors/ecccdh/KAS_ECC_CDH_PrimitiveTest.txt</code></td><td class="org-left"><code>KAS_ECC_CDH_PrimitiveTest.txt</code></td><td class="org-left"><code>[P-256]</code>, <code>[P-384]</code></td></tr>
</tbody>
</table>

Sources (fetched 2026-10-20):

-   [186-4ecdsatestvectors.zip](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip),
    SHA-256 `fe47cc92b4cee418236125c9ffbcd9bb01c8c34e74a4ba195d954bcb72824752`
-   [ecccdhtestvectors.zip](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/ecccdhtestvectors.zip),
    SHA-256 `5fff092551f2d72e89a3d9362711878708f9a14b502f0dfae819649105b0ea39`

The subset files are byte-for-byte copies of the original header comments and of the kept sections (CRLF line
endings preserved), every other section is dropped. Only the hash matching the curve is kept (SHA-256 with P-256,
SHA-384 with P-384), since the API does not allow a digest of another size to be signed or verified.

The tests cover:

-   SigVer: every case verifies (`P`) or fails (`F`) as expected; a modified `Q` that is not a valid public key is
    rejected on import.
-   SigGen: the private key `d` derives the published `Q`, and the published signature verifies (the per-message
    secret `k` cannot be injected through the API, so signature generation itself is covered by the property tests
    against RustCrypto).
-   PKV: public key validation accepts exactly the valid keys.
-   ECC CDH: importing `dIUT` derives `QIUT`, and the shared secret with `QCAVS` is `ZIUT`.


<a id="orgkw00001"></a>

# AES Key Wrap (KW)

`nist_kw.rs` runs the CAVP KWVS vectors for `aes::kw`. The forward-cipher KW files are committed whole under
`vectors/kw/` and the tests run offline.

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">
<thead>
<tr><th scope="col" class="org-left">File</th><th scope="col" class="org-left">Source file in the CAVP zip</th><th scope="col" class="org-left">Sections kept</th></tr>
</thead>
<tbody>
<tr><td class="org-left"><code>vectors/kw/KW_AE_128.txt</code></td><td class="org-left"><code>kwtestvectors/KW_AE_128.txt</code></td><td class="org-left">all</td></tr>
<tr><td class="org-left"><code>vectors/kw/KW_AE_192.txt</code></td><td class="org-left"><code>kwtestvectors/KW_AE_192.txt</code></td><td class="org-left">all</td></tr>
<tr><td class="org-left"><code>vectors/kw/KW_AE_256.txt</code></td><td class="org-left"><code>kwtestvectors/KW_AE_256.txt</code></td><td class="org-left">all</td></tr>
<tr><td class="org-left"><code>vectors/kw/KW_AD_128.txt</code></td><td class="org-left"><code>kwtestvectors/KW_AD_128.txt</code></td><td class="org-left">all</td></tr>
<tr><td class="org-left"><code>vectors/kw/KW_AD_192.txt</code></td><td class="org-left"><code>kwtestvectors/KW_AD_192.txt</code></td><td class="org-left">all</td></tr>
<tr><td class="org-left"><code>vectors/kw/KW_AD_256.txt</code></td><td class="org-left"><code>kwtestvectors/KW_AD_256.txt</code></td><td class="org-left">all</td></tr>
</tbody>
</table>

Source (fetched 2026-10-20):

-   [kwtestvectors.zip](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/kwtestvectors.zip),
    SHA-256 `04a4a82e4de65bca505125295003f9c75a5a815afda046dc83661b8b580dfdf3`

The files are byte-for-byte copies. Not kept: the `_inv` files (KW with the AES inverse cipher as the forward
function, not offered by `wolfcrypt`), the KWP files (KWP is not implemented by the vendored `wolfcrypt`) and the
TDEA `TKW` files.

The tests cover, for AES-128, AES-192 and AES-256 and every plaintext length (128, 192, 256, 320 and 4096 bits,
100 cases each):

-   KW-AE: wrapping `P` under `K` gives `C`.
-   KW-AD: unwrapping `C` under `K` gives `P`, or fails for the cases marked `FAIL` (20 per plaintext length).


<a id="orgdrbg0001"></a>

# Hash_DRBG

`nist_drbg.rs` runs the CAVP DRBGVS vectors for the Hash_DRBG (SHA-256) mechanism behind `random::Rng`,
through `random::kat::hash_drbg_sha256`. The needed subset is committed under `vectors/drbg/` and the tests
run offline.

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">
<thead>
<tr><th scope="col" class="org-left">File</th><th scope="col" class="org-left">Source file in the CAVP zip</th><th scope="col" class="org-left">Sections kept</th></tr>
</thead>
<tbody>
<tr><td class="org-left"><code>vectors/drbg/Hash_DRBG_no_reseed.rsp</code></td><td class="org-left"><code>drbgvectors_no_reseed.zip</code>: <code>Hash_DRBG.rsp</code></td><td class="org-left">see below</td></tr>
<tr><td class="org-left"><code>vectors/drbg/Hash_DRBG_pr_false.rsp</code></td><td class="org-left"><code>drbgvectors_pr_false.zip</code>: <code>Hash_DRBG.rsp</code></td><td class="org-left">see below</td></tr>
</tbody>
</table>

Source (fetched 2026-10-20):

-   [drbgtestvectors.zip](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip),
    SHA-256 `5f7e5658ebd5b4e6785a7b12fa32333511d2acc2f2d9c5ae1ffa16b699377769`

The subset files are byte-for-byte copies of the original header comments and of the kept sections (CRLF line
endings preserved), every other section is dropped. Kept are the `[SHA-256]` sections with
`[PersonalizationStringLen = 0]` and `[AdditionalInputLen = 0]` (4 sections of 15 cases in each file), as
`wolfcrypt`'s known-answer interface (`wc_RNG_HealthTest_ex`) takes neither input. The `pr_true` set is not
used, prediction resistance is not offered.

The tests cover:

-   `no_reseed`: instantiate with `EntropyInput` and `Nonce`, generate twice, the second output is `ReturnedBits`.
-   `pr_false`: the same, with a reseed with `EntropyInputReseed` after instantiation.
