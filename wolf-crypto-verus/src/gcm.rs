//! Verified decryption wrapper (VERIFIED).
//!
//! Proved: length validation precedes any FFI call; on every failure path the
//! output buffer is zeroized, so unauthenticated plaintext that wolfCrypt may
//! have written is never released; on success the output is the unique
//! plaintext whose encryption is `(ct, tag)` (from the authentication axiom).

use vstd::prelude::*;
use crate::ffi::{slice_len, CryptoError, Gcm};
#[cfg(verus)]
use crate::spec::*;
use crate::spec::{MAX_MSG_LEN, NONCE_LEN, TAG_LEN};

verus! {

/// Why [`Gcm::open`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// `ct.len() != out.len()`, or a length exceeds [`MAX_MSG_LEN`].
    InvalidLength,
    /// The tag did not verify (or wolfCrypt reported another error).
    Rejected,
}

/// Overwrite every byte of `buf` with zero.
pub fn zeroize_slice(buf: &mut [u8])
    ensures
        final(buf)@.len() == old(buf)@.len(),
        forall|i: int| 0 <= i < final(buf)@.len() ==> final(buf)@[i] == 0u8,
    opens_invariants none
    no_unwind
{
    let mut i: usize = 0;
    while i < slice_len(buf)
        invariant
            i <= buf@.len(),
            buf@.len() == old(buf)@.len(),
            forall|j: int| 0 <= j < i ==> buf@[j] == 0u8,
        decreases buf@.len() - i,
    {
        buf[i] = 0u8;
        i += 1;
    }
}

impl Gcm {
    /// Authenticated decryption of `ct` into `out`.
    pub fn open(
        &mut self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
        tag: &[u8; TAG_LEN],
        out: &mut [u8],
    ) -> (r: Result<(), OpenError>)
        ensures
            final(self).key() == old(self).key(),
            final(out)@.len() == old(out)@.len(),
            (ct@.len() != old(out)@.len() || ct@.len() > MAX_MSG_LEN || aad@.len() > MAX_MSG_LEN)
                ==> r matches Err(OpenError::InvalidLength),
            r is Ok ==> {
                &&& aes_gcm_open(final(self).key(), nonce@, aad@, ct@, tag@) == Some(final(out)@)
                &&& aes_gcm_seal(final(self).key(), nonce@, aad@, final(out)@) == (ct@, tag@)
            },
            r is Err ==> forall|i: int| 0 <= i < final(out)@.len() ==> final(out)@[i] == 0u8,
        opens_invariants none
        no_unwind
    {
        if slice_len(ct) != slice_len(out) || slice_len(ct) > MAX_MSG_LEN || slice_len(aad) > MAX_MSG_LEN {
            zeroize_slice(out);
            return Err(OpenError::InvalidLength);
        }
        match self.open_raw(nonce, aad, ct, tag, out) {
            Ok(()) => {
                proof {
                    broadcast use group_aes_gcm_axioms, Gcm::axiom_key_valid;
                    assert(valid_key(self.key()));
                }
                Ok(())
            },
            Err(CryptoError) => {
                zeroize_slice(out);
                Err(OpenError::Rejected)
            },
        }
    }
}

} // verus!
