//! Trusted boundary to wolf-crypto / wolfCrypt (TRUSTED).
//!
//! Every function here is `#[verifier::external_body]`: Verus does not see the
//! body, it assumes the `ensures` clause. Each contract states only what the
//! wolf-crypto API (and the wolfCrypt behaviour it documents) provides, in
//! terms of the abstract model in [`crate::spec`]. Keep bodies to a single
//! call into wolf-crypto plus argument plumbing so the trusted surface stays
//! reviewable.
//!
//! The only way for verified code to obtain a [`NonceLedger`] is through the
//! minting constructors of [`Gcm`] (`Tracked::assume_new` is not callable from
//! verified code), so the ledger is an unforgeable, linear capability for "the
//! set of nonces ever used under this key".

use vstd::prelude::*;
use crate::nonce::PREFIX_LEN;
#[cfg(verus)]
use crate::nonce::counter_nonce;
#[cfg(verus)]
use crate::spec::*;
use crate::spec::{NONCE_LEN, TAG_LEN};

use wolf_crypto::aead::AesGcm;
use wolf_crypto::aes::Key;
use wolf_crypto::buf::Nonce;
use wolf_crypto::random::Rng;

verus! {

/// Opaque error from wolfCrypt (bad arguments, RNG failure, or for `open`,
/// authentication failure; the verified layer does not distinguish them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError;

/// An AES-GCM context bound to one key.
///
/// Wraps `wolf_crypto::aead::AesGcm`, which zeroizes wolfCrypt's copy of the
/// key schedule on drop (`wc_AesFree`). Not `Clone`.
#[verifier::external_body]
pub struct Gcm {
    inner: AesGcm,
}

/// Ghost capability: the complete set of nonces ever used to seal under the
/// key `key()`, across all process lifetimes of that key.
///
/// Linear (not `Copy`/`Clone`) and unforgeable by verified code. Exactly one
/// ledger per key value may exist; this is guaranteed by the TRUSTED minting
/// obligations of [`Gcm::generate`] and [`Gcm::resume`].
// Ghost state is erased outside Verus.
#[cfg_attr(not(verus), allow(dead_code))]
pub tracked struct NonceLedger {
    ghost key: Seq<u8>,
    ghost used: Set<Seq<u8>>,
}

impl NonceLedger {
    pub closed spec fn key(self) -> Seq<u8> {
        self.key
    }

    pub closed spec fn used(self) -> Set<Seq<u8>> {
        self.used
    }

    /// Ghost-only: mark `nonce` as used without sealing (e.g. to retire a
    /// nonce whose use is uncertain). Only ever makes the ledger stricter.
    pub proof fn burn(tracked &mut self, nonce: Seq<u8>)
        ensures
            final(self).key() == old(self).key(),
            final(self).used() == old(self).used().insert(nonce),
    {
        self.used = self.used.insert(nonce);
    }
}

impl Gcm {
    /// The abstract key bytes this context encrypts under.
    pub uninterp spec fn key(&self) -> Seq<u8>;

    /// AXIOM (trusted): a constructed context always holds a valid AES key
    /// (`wolf_crypto::aes::Key` only has 128/192/256-bit variants and
    /// `AesGcm::new` fails otherwise).
    pub broadcast axiom fn axiom_key_valid(gcm: &Gcm)
        ensures
            valid_key(#[trigger] gcm.key()),
    ;

    /// TRUSTED: generate a fresh AES-256 key from wolfCrypt's DRBG.
    ///
    /// Minting obligation (assumed): the key is fresh, so no nonce has ever
    /// been used with it and no other ledger for it exists. This rests on the
    /// DRBG and a 2^-256 collision probability, i.e. a computational
    /// assumption, not a proof.
    ///
    /// The key bytes never leave wolfCrypt, so a generated key is ephemeral
    /// (one process lifetime). Keys that must survive restarts are created
    /// and stored by the caller's key management and enter through
    /// [`Gcm::resume`] (with `high_water = 0` before their first use).
    #[verifier::external_body]
    pub fn generate() -> (r: Result<(Gcm, Tracked<NonceLedger>), CryptoError>)
        ensures
            r matches Ok((gcm, ledger)) ==> {
                &&& valid_key(gcm.key())
                &&& gcm.key().len() == 32
                &&& ledger@.key() == gcm.key()
                &&& ledger@.used() == Set::<Seq<u8>>::empty()
            },
        opens_invariants none
        no_unwind
    {
        let mut rng = Rng::new().map_err(|_| CryptoError)?;
        let key: Key = rng.random_array::<32>().map_err(|_| CryptoError)?.into();
        // `key` is zeroized on drop by wolf-crypto; wolfCrypt keeps its own
        // copy inside the `Aes` struct, zeroized by `AesGcm`'s drop.
        let inner = AesGcm::new(&key).map_err(|_| CryptoError)?;
        Ok((Gcm { inner }, Tracked::assume_new()))
    }

    /// TRUSTED: re-open an existing AES-256 key after a restart.
    ///
    /// Persistence obligation (assumed, the caller's responsibility):
    ///
    /// 1. every nonce ever used to seal under `key` was produced by the
    ///    counter construction with fixed field `prefix` (no other context
    ///    seals under this key), and
    /// 2. `high_water` is at least the last value made durable for this key
    ///    via [`crate::sealer::DurableMark::assume_persisted`], read back from
    ///    storage that is durable (written and synced before the mark was
    ///    taken) and monotonic (never rolled back, e.g. by restoring an old
    ///    backup or VM snapshot).
    ///
    /// Under (1) and (2) every used nonce is `counter_nonce(prefix, c)` with
    /// `c < high_water`, which is what the ledger states. If storage can be
    /// rolled back, this obligation fails and nonces WILL repeat: rotate the
    /// key instead of resuming.
    ///
    /// The caller's key buffer is zeroized.
    #[verifier::external_body]
    pub fn resume(key: &mut [u8; 32], prefix: &[u8; PREFIX_LEN], high_water: u64)
        -> (r: Result<(Gcm, Tracked<NonceLedger>), CryptoError>)
        ensures
            final(key)@ == Seq::new(32, |_i| 0u8),
            r matches Ok((gcm, ledger)) ==> {
                &&& valid_key(gcm.key())
                &&& gcm.key() == old(key)@
                &&& ledger@.key() == gcm.key()
                &&& forall|n: Seq<u8>| #[trigger] ledger@.used().contains(n)
                    ==> exists|c: u64| c < high_water && n == counter_nonce(prefix@, c)
            },
        opens_invariants none
        no_unwind
    {
        // `prefix` and `high_water` only constrain the ghost ledger.
        let _ = (prefix, high_water);
        let k: Key = (*key).into();
        zeroize_key_buf(key);
        let inner = AesGcm::new(&k).map_err(|_| CryptoError)?;
        Ok((Gcm { inner }, Tracked::assume_new()))
    }

    /// TRUSTED: one call to `wc_AesGcmEncrypt` via `AesGcm::try_encrypt`.
    ///
    /// The verified precondition is the nonce discipline: `nonce` must not be
    /// in the key's ledger, and is added to it whether or not wolfCrypt
    /// succeeds (a failed call is conservatively treated as having used the
    /// nonce). On success `ct` and the returned tag are `aes_gcm_seal(..)`.
    /// On failure `ct` holds unspecified bytes.
    #[verifier::external_body]
    pub fn seal_raw(
        &mut self,
        Tracked(ledger): Tracked<&mut NonceLedger>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> (r: Result<[u8; TAG_LEN], CryptoError>)
        requires
            old(ledger).key() == old(self).key(),
            !old(ledger).used().contains(nonce@),
            pt@.len() == old(ct)@.len(),
            pt@.len() <= MAX_MSG_LEN,
            aad@.len() <= MAX_MSG_LEN,
        ensures
            final(self).key() == old(self).key(),
            final(ledger).key() == old(ledger).key(),
            final(ledger).used() == old(ledger).used().insert(nonce@),
            final(ct)@.len() == old(ct)@.len(),
            r matches Ok(tag) ==> (final(ct)@, tag@) == aes_gcm_seal(final(self).key(), nonce@, aad@, pt@),
        opens_invariants none
        no_unwind
    {
        let n = Nonce::new(*nonce);
        match self.inner.try_encrypt(n, pt, ct, aad) {
            Ok(tag) => Ok(tag.take()),
            Err(_) => Err(CryptoError),
        }
    }

    /// TRUSTED: one call to `wc_AesGcmDecrypt` via `AesGcm::try_decrypt`.
    ///
    /// On success, `out` is the authenticated plaintext. On failure `out`
    /// may hold arbitrary bytes, including unauthenticated plaintext (unless
    /// built with `WC_AES_GCM_DEC_AUTH_EARLY`, wolfCrypt's C path decrypts
    /// before comparing tags), so callers must not use it; the verified
    /// [`Gcm::open`] zeroizes it.
    #[verifier::external_body]
    pub fn open_raw(
        &mut self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
        tag: &[u8; TAG_LEN],
        out: &mut [u8],
    ) -> (r: Result<(), CryptoError>)
        requires
            ct@.len() == old(out)@.len(),
            ct@.len() <= MAX_MSG_LEN,
            aad@.len() <= MAX_MSG_LEN,
        ensures
            final(self).key() == old(self).key(),
            final(out)@.len() == old(out)@.len(),
            r is Ok ==> aes_gcm_open(final(self).key(), nonce@, aad@, ct@, tag@) == Some(final(out)@),
        opens_invariants none
        no_unwind
    {
        let n = Nonce::new(*nonce);
        let t = wolf_crypto::aead::Tag::new(*tag);
        if self.inner.try_decrypt(n, ct, out, aad, &t).is_ok() {
            Ok(())
        } else {
            Err(CryptoError)
        }
    }
}

/// TRUSTED: `<[u8]>::len`, restated with `opens_invariants none` and
/// `no_unwind` (vstd's specification of `len` carries neither).
#[verifier::external_body]
#[verifier::when_used_as_spec(spec_slice_len)]
#[inline(always)]
pub fn slice_len(s: &[u8]) -> (r: usize)
    ensures
        r == s@.len(),
    opens_invariants none
    no_unwind
{
    s.len()
}

pub open spec fn spec_slice_len(s: &[u8]) -> usize {
    s@.len() as usize
}

/// TRUSTED: volatile zeroization of a key buffer (`zeroize` crate).
#[verifier::external_body]
fn zeroize_key_buf(key: &mut [u8; 32])
    ensures
        final(key)@ == Seq::new(32, |_i| 0u8),
    opens_invariants none
    no_unwind
{
    use zeroize::Zeroize;
    key.zeroize();
}

} // verus!
