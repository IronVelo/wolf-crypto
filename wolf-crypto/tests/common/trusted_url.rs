use crate::common::parse::take;

#[inline]
#[must_use]
fn from_utf8(raw: &[u8]) -> Option<&str> {
    core::str::from_utf8(raw).ok()
}

/// Ensure that the associated URL is from the NIST Computer Security Resource Center.
///
/// This is to ensure we do not accidentally install anything malicious in the future / even
/// from an untrusted source. This may change as we add trusted sources, but these must be
/// documented. NIST in general does not need to be documented that we trust it, as it is the
/// national institute of standards and technology.
pub fn ensure_nist_crsc(url: &str) -> Option<&str> {
    // we only allow https
    let rem = take(b"https://")(url.as_bytes())?;

    // we ensure from the computer security resource center. This is done separately as NIST
    // trusted resources may change.

    let rem = take(b"csrc.")(rem)?;
    // Ensure this is not a subdomain by taking /

    take(b"nist.gov/")(rem).and_then(from_utf8)
}

#[repr(align(64))]
#[derive(Copy, Clone)]
pub struct NistUrl<'u> {
    // padding just so that transmuting to this type turns into junk without some
    // effort. Also, padded to cacheline (256 bits + 128 bits (str) + 128 bits (path) = 512 bits)
    s_pad: [u8; 32],
    inner: &'u str,
    path: &'u str
}

impl<'u> NistUrl<'u> {
    pub fn new(url: &'u str) -> Option<Self> {
        if let Some(path) = ensure_nist_crsc(url) {
            Some(Self { s_pad: [7u8; 32], inner: url, path })
        } else {
            None
        }
    }

    #[inline]
    #[must_use]
    pub fn get(&self) -> &'u str {
        assert_eq!(self.s_pad, [7u8; 32]);
        self.inner
    }

    #[inline]
    #[must_use]
    pub fn path(&self) -> &'u str {
        assert_eq!(self.s_pad, [7u8; 32]);
        self.path
    }
}