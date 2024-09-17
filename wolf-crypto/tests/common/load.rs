use std::{fs, io};
use std::path::{Path, PathBuf};
use std::process::{Command};
use crate::common::{trusted_url::NistUrl};
use std::sync::OnceLock;

macro_rules! run_command {
    ($cmd_name:literal, $cmd:expr) => {
        match $cmd.output() {
            Ok(::std::process::Output { status, stderr, .. }) if !status.success() => Err(
                ::std::io::Error::other(format!(
                    concat!("[{}] ", $cmd_name, "failed: {}"),
                    status,
                    String::from_utf8_lossy(stderr.as_slice())
                ))
            ),
            Err(_err) => Err(_err),
            _ => Ok(())
        }
    };
}

pub fn wget_to<P: AsRef<Path>>(url: NistUrl, output_dir: P) -> io::Result<()> {
    run_command!("WGET", Command::new("wget")
        .arg(url.get())
        .arg("-P").arg(output_dir.as_ref().as_os_str())
    )
}

pub fn unzip_to<SP: AsRef<Path>, DP: AsRef<Path>>(src: SP, dst: DP) -> io::Result<()> {
    run_command!("UNZIP", Command::new("unzip")
        .arg(src.as_ref().as_os_str())
        .arg("-d").arg(dst.as_ref().as_os_str())
    )
}

pub struct Setup {
    url: &'static str,
    unzip: &'static str
}

impl Setup {
    pub const fn new(url: &'static str, unzip: &'static str) -> Self {
        Self { url, unzip }
    }

    /// The URL to the zipped data
    pub const fn url(&self) -> &'static str {
        self.url
    }

    /// Path of the unzipped data
    pub const fn unzip(&self) -> &'static str {
        self.unzip
    }

    /// Shallow existence check
    pub fn is_loaded(&self) -> bool {
        Path::new(self.unzip).exists()
    }
}

macro_rules! vectors_dir {
    () => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors")
    };
    (with $($with:literal),* $(,)?) => {
        concat!(vectors_dir!(), $("/", $with),*)
    };
}

macro_rules! make_setup {
    ($(($dst:literal, $url:literal)),* $(,)?) => {
        [$(Setup::new($url, vectors_dir!(with $dst))),*]
    };
}

pub const SETUP: &'static [Setup] = &make_setup!(
    ("sha-3-bits", "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bittestvectors.zip"),
    ("sha-3-bytes", "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip"),
    ("shake-bits", "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebittestvectors.zip"),
    ("shake-bytes", "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip"),
    ("sha-bits", "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabittestvectors.zip"),
    ("sha-bytes", "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip")
);
pub const VECTORS_DIR: &'static str = vectors_dir!();

macro_rules! io_err {
    ($($tt:tt)*) => {::std::io::Error::other(format!($($tt)*))};
}

fn load_test(needs_setup: &Setup, local: &mut PathBuf) -> io::Result<()> {
    let raw_url = needs_setup.url();
    let url = NistUrl::new(raw_url)
        .ok_or_else(|| io_err!(
            "[UNTRUSTED] Attempted to use untrusted URL: {raw_url}. Currently only resources from \
            NIST's Computer Security Research Center are allowed. If you want a new resource to \
            be trusted this must be documented and undergo review."
        ))?;

    let mut rev_path = Path::new(url.path()).iter().rev();

    let file_name = rev_path.next().ok_or_else(
        || io_err!("[MALFORMED] Expected file name for: {}", url.get())
    )?;

    local.push(file_name);

    if !local.exists() {
        wget_to(url, vectors_dir!())?
    }

    // make unzip dir
    fs::create_dir_all(needs_setup.unzip())?;
    unzip_to(local, needs_setup.unzip())
}

fn load_from<'a>(mut ns_iter: impl Iterator<Item = &'a Setup>) -> io::Result<()> {
    let Some(first) = ns_iter.next() else {
        // no items
        return Ok(())
    };

    let mut local = Path::new(vectors_dir!()).to_path_buf();
    local.reserve(30);

    load_test(first, &mut local)?;

    for needs_setup in ns_iter {
        // reset our local buf
        local.pop();
        load_test(needs_setup, &mut local)?
    }

    Ok(())
}

fn load_tests_impl() -> io::Result<()> {
    if Path::new(vectors_dir!()).exists() {
        load_from(SETUP.iter().filter(|item| !item.is_loaded()))
    } else {
        fs::create_dir(vectors_dir!()).and_then(|_| load_from(SETUP.iter()))
    }
}

#[must_use = "You must handle the potential error"]
pub struct IoRes(&'static io::Result<()>);

impl IoRes {
    pub fn unwrap(&self) {
        if let Err(err) = self.0 {
            panic!("{}", err)
        }
    }
}

pub fn load_tests() -> IoRes {
    static ONCE: OnceLock<io::Result<()>> = OnceLock::new();
    IoRes(ONCE.get_or_init(load_tests_impl))
}
