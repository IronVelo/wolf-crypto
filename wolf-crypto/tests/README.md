
# Table of Contents

1.  [NIST MCT and KATs](#orge090024)
    1.  [Introduction](#orgcf7bdaa)
    2.  [Current State](#org2ccc43e)
    3.  [Requirements To Run Tests](#org596eab8)


<a id="orge090024"></a>

# NIST MCT and KATs


<a id="orgcf7bdaa"></a>

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


<a id="org2ccc43e"></a>

## Current State

The test suite is almost complete, the SHAVS / SHA-3 Candidate Algorithm Submissions tests are complete for
everything outside of `SHAKE`. 

To address `SHAKE` a new parser for it must be implemented for the MCTs and KATs, after this is complete
implementing the tests will be straight forward. There is not much heavy lifting involved in this, but
much work needs to be put in (in the freetime that I have) for ensuring that these tests are being performed
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


<a id="org596eab8"></a>

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

