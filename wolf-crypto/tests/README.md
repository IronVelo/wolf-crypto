
# Table of Contents

1.  [NIST MCT and KATs](#org9085813)
    1.  [Introduction](#orge996d62)
    2.  [Current State](#org2d7cc4c)
    3.  [FOSS Test Module?](#org912df49)
    4.  [Requirements To Run Tests](#orgf2659a9)


<a id="org9085813"></a>

# NIST MCT and KATs


<a id="orge996d62"></a>

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


<a id="org2d7cc4c"></a>

## Current State

Currently, this test suite is not fully implemented. We have the Monte Carlo tests operational for SHA-3,
and the Monte Carlo tests are not yet implemented for SHA as well as SHAKE.

The fundamental parsers to ease loading and setting up these tests are complete, as well as the
standard MCT parser. This parser will need to be modified for SHAKE as the format of the data is slightly
different.

We have a utility for loading the necessary associated data with each test from NIST, and validators to
ensure that all sources are truly from NIST. These run for any missing testing data, checking the
`test-vectors` directory on startup.

The next steps are:

1.  Create SHA-1 Monte Carlo Tests
2.  Create parser for other forms of tests
3.  Create tests for each hashing function using aforementioned parser
4.  Create augmented MCT parser for SHAKE
5.  Create SHAKE MCT tests


<a id="org912df49"></a>

## FOSS Test Module?

Other implementations of hash functions (to the extent of my knowledge) in Rust do not leverage these
test suites by NIST. While I am not implying any of their implementations are incorrect, it is a
valuable suite of tests and the tools we have created for running these tests could be of value to
them.


<a id="orgf2659a9"></a>

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

