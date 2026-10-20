//! Verification-only client code (compiled only under `cfg(verus)`).
//!
//! Shows that the guarantees compose for a verified caller: two seals under
//! one sealer never share a nonce, and the full generate / reserve / seal /
//! restart / resume flow type-checks against the ghost obligations.
//!
//! `nonce_reuse_rejected` is a negative check: with
//! `cargo verus focus --features negative-check` verification must FAIL at
//! the second `seal_raw` call, because the ledger already holds the nonce.

use vstd::prelude::*;
use crate::ffi::{Gcm, NonceLedger};
use crate::nonce::{counter_nonce, PREFIX_LEN};
use crate::sealer::{lemma_fresh_ledger, CounterSealer, DurableMark};
use crate::spec::NONCE_LEN;

verus! {

fn two_seals_never_share_a_nonce(s: &mut CounterSealer, pt: &[u8], ct1: &mut [u8], ct2: &mut [u8]) {
    let r1 = s.seal(&[], pt, ct1);
    let r2 = s.seal(&[], pt, ct2);
    if let (Ok((n1, _)), Ok((n2, _))) = (r1, r2) {
        assert(n1@ != n2@);
    }
}

fn generate_then_restart(prefix: [u8; PREFIX_LEN], pt: &[u8], ct: &mut [u8]) {
    let Ok((gcm, ledger)) = Gcm::generate() else { return };
    proof { lemma_fresh_ledger(ledger@, prefix@); }
    // The caller persists 1024 as the high-water mark first (trusted step).
    let tracked mark = DurableMark::assume_persisted(gcm.key(), prefix@, 1024);
    let Ok(mut s) = CounterSealer::new(gcm, ledger, prefix, 0, 1024, 1u64 << 32, Tracked(mark))
        else { return };
    let _ = s.seal(&[], pt, ct);
    // ... process restarts; key bytes and the mark (1024) are read back ...
    let mut key = [7u8; 32];
    let Ok((gcm2, ledger2)) = Gcm::resume(&mut key, &prefix, 1024) else { return };
    let tracked mark2 = DurableMark::assume_persisted(gcm2.key(), prefix@, 2048);
    let Ok(mut s2) = CounterSealer::resume(gcm2, ledger2, prefix, 1024, 2048, 1u64 << 32, Tracked(mark2))
        else { return };
    if let Ok((n, _)) = s2.seal(&[], pt, ct) {
        // Resumed nonces are never below the persisted mark.
        assert(n@ == counter_nonce(prefix@, 1024));
    }
}

#[cfg(feature = "negative-check")]
fn nonce_reuse_rejected(gcm: &mut Gcm, Tracked(ledger): Tracked<&mut NonceLedger>, pt: &[u8], ct: &mut [u8])
    requires
        old(ledger).key() == old(gcm).key(),
        old(ledger).used() == Set::<Seq<u8>>::empty(),
        pt@.len() == old(ct)@.len(),
        pt@.len() <= 16,
{
    let nonce = [0u8; NONCE_LEN];
    let _ = gcm.seal_raw(Tracked(&mut *ledger), &nonce, &[], pt, ct);
    let _ = gcm.seal_raw(Tracked(&mut *ledger), &nonce, &[], pt, ct); // must fail
}

} // verus!
