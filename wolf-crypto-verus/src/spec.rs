//! Abstract model of AES-GCM (TRUSTED).
//!
//! AES-GCM is modelled as two uninterpreted mathematical functions over byte
//! sequences. Nothing here is proved: the axioms are the functional facts about
//! GCM (NIST SP 800-38D) that the verified wrapper layer relies on, and they
//! are part of the trusted computing base together with the contracts in
//! [`crate::ffi`].
//!
//! The axioms are deliberately *functional* (lengths, round-trip, determinism
//! of the tag check). Computational security properties (confidentiality,
//! INT-CTXT, the catastrophic consequences of nonce reuse) are not expressible
//! here and are not axiomatised; the nonce discipline in [`crate::nonce`] and
//! [`crate::sealer`] is what makes the standard GCM security bounds applicable.

use vstd::prelude::*;

verus! {

/// Byte length of a GCM nonce (96-bit IV, the only size the verified layer
/// accepts; SP 800-38D 8.2 deterministic construction).
pub const NONCE_LEN: usize = 12;

/// Byte length of the full GCM authentication tag (the only size accepted).
pub const TAG_LEN: usize = 16;

/// Largest plaintext / AAD length accepted, imposed by wolfCrypt's `word32`
/// length parameters. This is far below the SP 800-38D limit of
/// 2^39 - 256 bits per invocation.
pub const MAX_MSG_LEN: usize = 0xffff_ffff;

/// Valid AES key lengths (128, 192 or 256 bits).
pub open spec fn valid_key(key: Seq<u8>) -> bool {
    key.len() == 16 || key.len() == 24 || key.len() == 32
}

/// `GCM-AE_K(IV, P, A) = (C, T)`, SP 800-38D 7.1, with a 128-bit tag.
pub uninterp spec fn aes_gcm_seal(
    key: Seq<u8>,
    nonce: Seq<u8>,
    aad: Seq<u8>,
    pt: Seq<u8>,
) -> (Seq<u8>, Seq<u8>);

/// `GCM-AD_K(IV, C, A, T)`, SP 800-38D 7.2: `Some(P)` or `None` (FAIL).
pub uninterp spec fn aes_gcm_open(
    key: Seq<u8>,
    nonce: Seq<u8>,
    aad: Seq<u8>,
    ct: Seq<u8>,
    tag: Seq<u8>,
) -> Option<Seq<u8>>;

/// AXIOM (trusted): GCM is length preserving and produces a 16-byte tag.
pub broadcast axiom fn axiom_seal_lengths(key: Seq<u8>, nonce: Seq<u8>, aad: Seq<u8>, pt: Seq<u8>)
    requires
        valid_key(key),
        nonce.len() == NONCE_LEN,
    ensures
        (#[trigger] aes_gcm_seal(key, nonce, aad, pt)).0.len() == pt.len(),
        aes_gcm_seal(key, nonce, aad, pt).1.len() == TAG_LEN,
;

/// AXIOM (trusted): correctness, `open(seal(x)) == x`.
pub broadcast axiom fn axiom_open_seal(key: Seq<u8>, nonce: Seq<u8>, aad: Seq<u8>, pt: Seq<u8>)
    requires
        valid_key(key),
        nonce.len() == NONCE_LEN,
    ensures
        aes_gcm_open(
            key,
            nonce,
            aad,
            (#[trigger] aes_gcm_seal(key, nonce, aad, pt)).0,
            aes_gcm_seal(key, nonce, aad, pt).1,
        ) == Some(pt),
;

/// AXIOM (trusted): authentication failure. Decryption only succeeds on
/// exactly the outputs of encryption: if `open` accepts `(C, T)` yielding
/// `P`, then `(C, T)` is the encryption of `P`. Equivalently, any `(C, T)`
/// not in the image of `seal` under `(K, IV, A)` is rejected. This holds for
/// GCM because `C = P xor keystream(K, IV)` and the tag check recomputes `T`
/// exactly; it is a functional fact, not a forgery bound.
pub broadcast axiom fn axiom_open_auth(
    key: Seq<u8>,
    nonce: Seq<u8>,
    aad: Seq<u8>,
    ct: Seq<u8>,
    tag: Seq<u8>,
)
    requires
        valid_key(key),
        nonce.len() == NONCE_LEN,
        (#[trigger] aes_gcm_open(key, nonce, aad, ct, tag)) is Some,
    ensures
        aes_gcm_seal(key, nonce, aad, aes_gcm_open(key, nonce, aad, ct, tag)->Some_0) == (ct, tag),
;

pub broadcast group group_aes_gcm_axioms {
    axiom_seal_lengths,
    axiom_open_seal,
    axiom_open_auth,
}

/// Derived (proved from the axioms): a successful open has the ciphertext's
/// length and a 16-byte tag.
pub proof fn lemma_open_lengths(
    key: Seq<u8>,
    nonce: Seq<u8>,
    aad: Seq<u8>,
    ct: Seq<u8>,
    tag: Seq<u8>,
)
    requires
        valid_key(key),
        nonce.len() == NONCE_LEN,
        aes_gcm_open(key, nonce, aad, ct, tag) is Some,
    ensures
        aes_gcm_open(key, nonce, aad, ct, tag)->Some_0.len() == ct.len(),
        tag.len() == TAG_LEN,
{
    broadcast use group_aes_gcm_axioms;
    let pt = aes_gcm_open(key, nonce, aad, ct, tag)->Some_0;
    assert(aes_gcm_seal(key, nonce, aad, pt) == (ct, tag));
}

} // verus!
