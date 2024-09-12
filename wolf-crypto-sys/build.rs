#![allow(deprecated)] // FIX
#![allow(dead_code)]
use std::env;
use std::path::PathBuf;

#[derive(Debug)]
enum SourceFile {
    Asm(PathBuf),
    C(PathBuf),
}

impl SourceFile {
    fn path(self) -> PathBuf {
        match self {
            Self::Asm(path) | Self::C(path) => path
        }
    }
}

macro_rules! path_fname {
    ($path:ident) => {
        $path
            .file_name()
            .expect("Failed to get path filename")
            .to_str()
            .expect("Path filename was not valid utf-8")
    }
}

fn is_x86_target() -> bool {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    arch == "x86" || arch == "x86_64"
}

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=wolfcrypt");

    let bindings = bindgen::Builder::default()
        .use_core()
        .ctypes_prefix("::core::ffi")
        .header("wrapper.h")
        .clang_arg("-I./wolfcrypt/include")
        .clang_arg("-DWOLFCRYPT_ONLY")
        .clang_arg("-DWOLFSSL_NO_MALLOC")
        .clang_arg("-DUSE_FAST_MATH")
        .clang_arg("-DTFM_TIMING_RESISTANT")
        .clang_arg("-DWC_RSA_BLINDING")
        .clang_arg("-DECC_TIMING_RESISTANT")
        .clang_arg("-DHAVE_AESGCM")
        .clang_arg("-DWOLFSSL_AES_COUNTER")
        .clang_arg("-DWOLFSSL_AES_CBC_LENGTH_CHECKS")
        .clang_arg("-DWOLFSSL_SHA224")
        .clang_arg("-DWOLFSSL_SHA384")
        .clang_arg("-DWOLFSSL_SHA512")
        .clang_arg("-DWOLFSSL_SHA3")
        .clang_arg("-DHAVE_SHA3")
        .clang_arg("-DHAVE_BLAKE2")
        .clang_arg("-DHAVE_BLAKE2B")
        .clang_arg("-DHAVE_BLAKE2S")
        .clang_arg("-DWOLFSSL_RIPEMD")
        .clang_arg("-DHAVE_RIPEMD");
        //.clang_arg("-DHAVE_FIPS");

    // if is_x86_target() {
    //     bindings = bindings.clang_arg("-DWOLFSSL_AESNI")
    //         .clang_arg("-maes");
    // }

    let bindings = bindings
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings");

    let (_asm_files, source_files): (Vec<_>, Vec<_>) = std::fs::read_dir("wolfcrypt/src/wolfcrypt/src")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            match path.extension().and_then(|ext| ext.to_str()) {
                Some("S") if !matches!(path_fname!(path), "sp_sm2_x86_64_asm.S") => Some(SourceFile::Asm(path)),
                Some("c") if !matches!(path_fname!(path), "evp.c" | "misc.c" | "tfm.c") => Some(SourceFile::C(path)),
                _ => None,
            }
        })
        .collect::<Vec<SourceFile>>()
        .into_iter()
        .partition(|file| matches!(file, SourceFile::Asm(_)));

    let mut build = cc::Build::new();
    build
        .include("wolfcrypt/include")
        .include("wolfcrypt/src")
        .define("WOLFCRYPT_ONLY", None)
        .define("WOLFSSL_NO_MALLOC", None)
        .define("USE_FAST_MATH", None)
        .define("TFM_TIMING_RESISTANT", None)
        .define("ECC_TIMING_RESISTANT", None)
        .define("WC_RSA_BLINDING", None)
        .define("HAVE_AESGCM", None)
        .define("HAVE_AES_DECRYPT", None)
        .define("WOLFSSL_AES_COUNTER", None)
        .define("WOLFSSL_AES_CBC_LENGTH_CHECKS", None)
        .define("WOLFSSL_SHA224", None)
        .define("WOLFSSL_SHA384", None)
        .define("WOLFSSL_SHA512", None)
        .define("WOLFSSL_SHA3", None)
        .define("HAVE_SHA3", None)
        .define("HAVE_BLAKE2", None)
        .define("HAVE_BLAKE2S", None)
        .define("HAVE_BLAKE2B", None)
        .define("WOLFSSL_RIPEMD", None)
        .define("HAVE_RIPEMD", None);
        // .define("HAVE_FIPS", None);

    // if is_x86_target() {
    //     build.define("WOLFSSL_AESNI", None)
    //         .define("INTEL_SPEEDUP", None)
    //         .flag("-march=native");
    // }

    build.files(source_files.into_iter().map(SourceFile::path))
        // .objects(assembled)
        .debug(true)
        .compile("wolfcrypt");

    println!("cargo:rustc-link-lib=static=wolfcrypt");
    println!("cargo:rustc-link-search=native={}", out_path.display());
}
