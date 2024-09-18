macro_rules! ingest_paths {
    ($prefix:literal, $($ident:ident .rsp)*) => {
        &[
            $((
                // test name
                stringify!($ident),
                // path to data
                concat!(
                    env!("CARGO_MANIFEST_DIR"), "/test-vectors/",
                    $prefix,
                    "/",
                    stringify!($ident),
                    ".rsp"
                )
            )),*
        ]
    };
    ($vis:vis $as:ident => $prefix:literal, $($tt:tt)*) => {
        $vis const $as: &'static [(&'static str, &'static str)] = ingest_paths!($prefix, $($tt)*);
    }
}

// -------------------------- SHAKE FILES

ingest_paths! { pub SHAKE128_BYTE_FILES => "shake-bytes",
    SHAKE128LongMsg.rsp
    SHAKE128Monte.rsp
    SHAKE128ShortMsg.rsp
    SHAKE128VariableOut.rsp
}

ingest_paths! { pub SHAKE256_BYTE_FILES => "shake-bytes",
    SHAKE256LongMsg.rsp
    SHAKE256Monte.rsp
    SHAKE256ShortMsg.rsp
    SHAKE256VariableOut.rsp
}

ingest_paths! { pub SHAKE128_BIT_FILES => "shake-bits",
    SHAKE128LongMsg.rsp
    SHAKE128Monte.rsp
    SHAKE128ShortMsg.rsp
    SHAKE128VariableOut.rsp
}

ingest_paths! { pub SHAKE256_BIT_FILES => "shake_bits",
    SHAKE256LongMsg.rsp
    SHAKE256Monte.rsp
    SHAKE256ShortMsg.rsp
    SHAKE256VariableOut.rsp
}

// -------------------------- SHA-3 FILES

ingest_paths! { pub SHA3_224_BIT_FILES => "sha-3-bits",
    SHA3_224Monte.rsp
    SHA3_224LongMsg.rsp
    SHA3_224ShortMsg.rsp
}

ingest_paths! { pub SHA3_256_BIT_FILES => "sha-3-bits",
    SHA3_256Monte.rsp
    SHA3_256LongMsg.rsp
    SHA3_256ShortMsg.rsp
}

ingest_paths! { pub SHA3_384_BIT_FILES => "sha-3-bits",
    SHA3_384Monte.rsp
    SHA3_384LongMsg.rsp
    SHA3_384ShortMsg.rsp
}

ingest_paths! { pub SHA3_512_BIT_FILES => "sha-3-bits",
    SHA3_512Monte.rsp
    SHA3_512LongMsg.rsp
    SHA3_512ShortMsg.rsp
}

ingest_paths! { pub SHA3_224_BYTE_FILES => "sha-3-bytes",
    SHA3_224Monte.rsp
    SHA3_224LongMsg.rsp
    SHA3_224ShortMsg.rsp
}

ingest_paths! { pub SHA3_256_BYTE_FILES => "sha-3-bytes",
    SHA3_256Monte.rsp
    SHA3_256LongMsg.rsp
    SHA3_256ShortMsg.rsp
}

ingest_paths! { pub SHA3_384_BYTE_FILES => "sha-3-bytes",
    SHA3_384Monte.rsp
    SHA3_384LongMsg.rsp
    SHA3_384ShortMsg.rsp
}

ingest_paths! { pub SHA3_512_BYTE_FILES => "sha-3-bytes",
    SHA3_512Monte.rsp
    SHA3_512LongMsg.rsp
    SHA3_512ShortMsg.rsp
}

// ------------------------- SHA 1 | 2 FILES

ingest_paths! { pub SHA1_BIT_FILES => "sha-bits/shabittestvectors",
    SHA1Monte.rsp
    SHA1ShortMsg.rsp
    SHA1LongMsg.rsp
}

ingest_paths! { pub SHA224_BIT_FILES => "sha-bits/shabittestvectors",
    SHA224Monte.rsp
    SHA224ShortMsg.rsp
    SHA224LongMsg.rsp
}

ingest_paths! { pub SHA256_BIT_FILES => "sha-bits/shabittestvectors",
    SHA256Monte.rsp
    SHA256ShortMsg.rsp
    SHA256LongMsg.rsp
}

ingest_paths! { pub SHA384_BIT_FILES => "sha-bits/shabittestvectors",
    SHA384Monte.rsp
    SHA384ShortMsg.rsp
    SHA384LongMsg.rsp
}

ingest_paths! { pub SHA512_BIT_FILES => "sha-bits/shabittestvectors",
    SHA512Monte.rsp
    SHA512ShortMsg.rsp
    SHA512LongMsg.rsp
}

ingest_paths! { pub SHA512_224_BIT_FILES => "sha-bits/shabittestvectors",
    SHA512_224Monte.rsp
    SHA512_224ShortMsg.rsp
    SHA512_224LongMsg.rsp
}

ingest_paths! { pub SHA512_256_BIT_FILES => "sha-bits/shabittestvectors",
    SHA512_256Monte.rsp
    SHA512_256ShortMsg.rsp
    SHA512_256LongMsg.rsp
}

ingest_paths! { pub SHA1_BYTE_FILES => "sha-bytes/shabytetestvectors",
    SHA1Monte.rsp
    SHA1ShortMsg.rsp
    SHA1LongMsg.rsp
}

ingest_paths! { pub SHA224_BYTE_FILES => "sha-bytes/shabytetestvectors",
    SHA224Monte.rsp
    SHA224ShortMsg.rsp
    SHA224LongMsg.rsp
}

ingest_paths! { pub SHA256_BYTE_FILES => "sha-bytes/shabytetestvectors",
    SHA256Monte.rsp
    SHA256ShortMsg.rsp
    SHA256LongMsg.rsp
}

ingest_paths! { pub SHA384_BYTE_FILES => "sha-bytes/shabytetestvectors",
    SHA384Monte.rsp
    SHA384ShortMsg.rsp
    SHA384LongMsg.rsp
}

ingest_paths! { pub SHA512_BYTE_FILES => "sha-bytes/shabytetestvectors",
    SHA512Monte.rsp
    SHA512ShortMsg.rsp
    SHA512LongMsg.rsp
}

ingest_paths! { pub SHA512_224_BYTE_FILES => "sha-bytes/shabytetestvectors",
    SHA512_224Monte.rsp
    SHA512_224ShortMsg.rsp
    SHA512_224LongMsg.rsp
}

ingest_paths! { pub SHA512_256_BYTE_FILES => "sha-bytes/shabytetestvectors",
    SHA512_256Monte.rsp
    SHA512_256ShortMsg.rsp
    SHA512_256LongMsg.rsp
}