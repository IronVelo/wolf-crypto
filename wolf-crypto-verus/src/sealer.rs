//! Counter-based sealing with a proved nonce-uniqueness discipline (VERIFIED,
//! except [`DurableMark::assume_persisted`]).
//!
//! A [`CounterSealer`] owns a key's [`Gcm`] context and its [`NonceLedger`].
//! Its type invariant says that no counter at or above `next` has been used;
//! every successful or failed seal uses `counter_nonce(prefix, next)` and then
//! increments `next`. Proved consequences:
//!
//! - every nonce handed to wolfCrypt is fresh for the key (the precondition of
//!   the trusted `seal_raw` is discharged on every call);
//! - at most `limit <= MAX_INVOCATIONS` invocations per (key, prefix), with
//!   `Exhausted` returned, and no wraparound, once the bound is reached;
//! - counters are only used below `reserved`, a value the caller has made
//!   durable, so a restart that resumes from the persisted high-water mark
//!   cannot reuse a nonce.
//!
//! Restart protocol (caller's obligation, see [`Gcm::resume`]):
//!
//! 1. before sealing with counters in `[reserved, new_mark)`, durably write
//!    `new_mark` for this key (write + fsync, or a monotonic hardware
//!    counter), then call [`DurableMark::assume_persisted`] and
//!    [`CounterSealer::extend_reservation`];
//! 2. after a restart, read the mark back and pass it as `high_water` to
//!    [`Gcm::resume`], then start a sealer at `start = high_water`
//!    ([`CounterSealer::resume`]).
//!
//! Counters in `[next, reserved)` at crash time are skipped, never reused.
//! Reserving in blocks (e.g. 2^20) amortises the durable writes.

use vstd::prelude::*;
use crate::ffi::{slice_len, CryptoError, Gcm, NonceLedger};
use crate::nonce::{encode_counter_nonce, PREFIX_LEN};
#[cfg(verus)]
use crate::nonce::{counter_nonce, lemma_counter_nonce_injective_forall, MAX_INVOCATIONS};
#[cfg(verus)]
use crate::spec::*;
use crate::spec::{MAX_MSG_LEN, NONCE_LEN, TAG_LEN};

verus! {

/// Ghost witness that the caller has durably recorded `value` as the
/// high-water mark of the counter context `(key, prefix)`.
// Ghost state is erased outside Verus.
#[cfg_attr(not(verus), allow(dead_code))]
pub tracked struct DurableMark {
    ghost key: Seq<u8>,
    ghost prefix: Seq<u8>,
    ghost value: u64,
}

impl DurableMark {
    pub closed spec fn key(self) -> Seq<u8> {
        self.key
    }

    pub closed spec fn prefix(self) -> Seq<u8> {
        self.prefix
    }

    pub closed spec fn value(self) -> u64 {
        self.value
    }

    /// TRUSTED (persistence obligation): the caller asserts that `value` has
    /// been durably and monotonically stored as the high-water mark for
    /// `(key, prefix)` before this call. This is the single trust point of
    /// the restart argument; grep for it in review.
    #[verifier::external_body]
    pub proof fn assume_persisted(key: Seq<u8>, prefix: Seq<u8>, value: u64) -> (tracked m: DurableMark)
        ensures
            m.key() == key,
            m.prefix() == prefix,
            m.value() == value,
    {
        unimplemented!()
    }
}

/// Why [`CounterSealer::seal`] did not produce a ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// `pt.len() != ct.len()`, or a length exceeds [`MAX_MSG_LEN`]. No nonce
    /// was used.
    InvalidLength,
    /// `next == reserved`: persist a higher mark and call
    /// [`CounterSealer::extend_reservation`]. No nonce was used.
    NeedsReservation,
    /// `next == limit`: the invocation bound for this key is reached; rotate
    /// the key. No nonce was used.
    Exhausted,
    /// wolfCrypt failed. The nonce was consumed and will not be reused.
    Crypto,
}

/// Why a sealer could not be constructed or extended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// Requires `start <= reserved <= limit`.
    InvalidBounds,
}

/// AES-GCM sealer with deterministic counter nonces (SP 800-38D 8.2.1).
// Ghost state is erased outside Verus.
#[cfg_attr(not(verus), allow(dead_code))]
pub struct CounterSealer {
    gcm: Gcm,
    prefix: [u8; PREFIX_LEN],
    next: u64,
    reserved: u64,
    limit: u64,
    ledger: Tracked<NonceLedger>,
}

impl CounterSealer {
    #[verifier::type_invariant]
    spec fn inv(self) -> bool {
        &&& self.ledger@.key() == self.gcm.key()
        &&& self.next <= self.reserved
        &&& self.reserved <= self.limit
        &&& self.limit <= MAX_INVOCATIONS
        &&& forall|c: u64|
            c >= self.next ==> !self.ledger@.used().contains(#[trigger] counter_nonce(self.prefix@, c))
    }

    pub closed spec fn key(self) -> Seq<u8> {
        self.gcm.key()
    }

    pub closed spec fn prefix(self) -> Seq<u8> {
        self.prefix@
    }

    pub closed spec fn next(self) -> u64 {
        self.next
    }

    pub closed spec fn reserved(self) -> u64 {
        self.reserved
    }

    pub closed spec fn limit(self) -> u64 {
        self.limit
    }

    /// All nonces ever used under this sealer's key (ghost).
    pub closed spec fn used(self) -> Set<Seq<u8>> {
        self.ledger@.used()
    }

    /// The type invariant, in terms of the public ghost model.
    pub proof fn use_type_invariant(tracked &self)
        ensures
            self.next() <= self.reserved(),
            self.reserved() <= self.limit(),
            self.limit() <= MAX_INVOCATIONS,
            self.prefix().len() == PREFIX_LEN,
            forall|c: u64|
                c >= self.next() ==> !self.used().contains(#[trigger] counter_nonce(self.prefix(), c)),
    {
        use_type_invariant(self);
    }

    /// Start a sealer at counter `start` with `mark` as the durable bound.
    ///
    /// Use `start = 0` with a ledger from [`Gcm::generate`] (see
    /// [`lemma_fresh_ledger`]) or `start = high_water` with a ledger from
    /// [`Gcm::resume`] (see [`CounterSealer::resume`]).
    pub fn new(
        gcm: Gcm,
        ledger: Tracked<NonceLedger>,
        prefix: [u8; PREFIX_LEN],
        start: u64,
        reserved: u64,
        limit: u64,
        Tracked(mark): Tracked<DurableMark>,
    ) -> (r: Result<CounterSealer, ConfigError>)
        requires
            ledger@.key() == gcm.key(),
            forall|c: u64| c >= start ==> !ledger@.used().contains(#[trigger] counter_nonce(prefix@, c)),
            mark.key() == gcm.key(),
            mark.prefix() == prefix@,
            mark.value() == reserved,
        ensures
            r is Err <==> !(start <= reserved && reserved <= limit),
            r matches Ok(s) ==> {
                &&& s.key() == gcm.key()
                &&& s.prefix() == prefix@
                &&& s.next() == start
                &&& s.reserved() == reserved
                &&& s.limit() == limit
                &&& s.used() == ledger@.used()
            },
        opens_invariants none
        no_unwind
    {
        if !(start <= reserved && reserved <= limit) {
            return Err(ConfigError::InvalidBounds);
        }
        Ok(CounterSealer { gcm, prefix, next: start, reserved, limit, ledger })
    }

    /// Restart path: start at the persisted high-water mark of a key
    /// re-opened with [`Gcm::resume`] (same `prefix`, same `high_water`).
    pub fn resume(
        gcm: Gcm,
        ledger: Tracked<NonceLedger>,
        prefix: [u8; PREFIX_LEN],
        high_water: u64,
        reserved: u64,
        limit: u64,
        mark: Tracked<DurableMark>,
    ) -> (r: Result<CounterSealer, ConfigError>)
        requires
            ledger@.key() == gcm.key(),
            forall|n: Seq<u8>| #[trigger] ledger@.used().contains(n)
                ==> exists|c: u64| c < high_water && n == counter_nonce(prefix@, c),
            mark@.key() == gcm.key(),
            mark@.prefix() == prefix@,
            mark@.value() == reserved,
        ensures
            r is Err <==> !(high_water <= reserved && reserved <= limit),
            r matches Ok(s) ==> {
                &&& s.key() == gcm.key()
                &&& s.prefix() == prefix@
                &&& s.next() == high_water
                &&& s.reserved() == reserved
                &&& s.limit() == limit
            },
        opens_invariants none
        no_unwind
    {
        proof {
            lemma_resumed_ledger(ledger@, prefix@, high_water);
        }
        CounterSealer::new(gcm, ledger, prefix, high_water, reserved, limit, mark)
    }

    /// Raise the durable bound after persisting `new_reserved`.
    pub fn extend_reservation(&mut self, new_reserved: u64, Tracked(mark): Tracked<DurableMark>)
        -> (r: Result<(), ConfigError>)
        requires
            mark.key() == old(self).key(),
            mark.prefix() == old(self).prefix(),
            mark.value() == new_reserved,
        ensures
            r is Err <==> !(old(self).reserved() <= new_reserved && new_reserved <= old(self).limit()),
            final(self).reserved() == if r is Ok { new_reserved } else { old(self).reserved() },
            final(self).key() == old(self).key(),
            final(self).prefix() == old(self).prefix(),
            final(self).next() == old(self).next(),
            final(self).limit() == old(self).limit(),
            final(self).used() == old(self).used(),
        opens_invariants none
        no_unwind
    {
        proof { use_type_invariant(&*self); }
        if !(self.reserved <= new_reserved && new_reserved <= self.limit) {
            return Err(ConfigError::InvalidBounds);
        }
        self.reserved = new_reserved;
        Ok(())
    }

    /// Seal `pt` into `ct` under the next counter nonce. Returns the nonce
    /// (to be transmitted with the ciphertext) and the tag.
    pub fn seal(&mut self, aad: &[u8], pt: &[u8], ct: &mut [u8])
        -> (r: Result<([u8; NONCE_LEN], [u8; TAG_LEN]), SealError>)
        ensures
            final(self).key() == old(self).key(),
            final(self).prefix() == old(self).prefix(),
            final(self).reserved() == old(self).reserved(),
            final(self).limit() == old(self).limit(),
            final(ct)@.len() == old(ct)@.len(),
            match r {
                Ok((nonce, tag)) => {
                    &&& nonce@ == counter_nonce(old(self).prefix(), old(self).next())
                    &&& !old(self).used().contains(nonce@)
                    &&& final(self).used() == old(self).used().insert(nonce@)
                    &&& final(self).next() == old(self).next() + 1
                    &&& (final(ct)@, tag@) == aes_gcm_seal(final(self).key(), nonce@, aad@, pt@)
                },
                Err(SealError::Crypto) => {
                    let nonce = counter_nonce(old(self).prefix(), old(self).next());
                    &&& !old(self).used().contains(nonce)
                    &&& final(self).used() == old(self).used().insert(nonce)
                    &&& final(self).next() == old(self).next() + 1
                },
                Err(e) => {
                    &&& final(self).used() == old(self).used()
                    &&& final(self).next() == old(self).next()
                    &&& (e is InvalidLength <==> (pt@.len() != old(ct)@.len()
                        || pt@.len() > MAX_MSG_LEN || aad@.len() > MAX_MSG_LEN))
                    &&& (e is Exhausted ==> old(self).next() == old(self).limit())
                    &&& (e is NeedsReservation
                        ==> old(self).next() == old(self).reserved() && old(self).reserved() < old(self).limit())
                },
            },
        opens_invariants none
        no_unwind
    {
        proof { use_type_invariant(&*self); }
        if slice_len(pt) != slice_len(ct) || slice_len(pt) > MAX_MSG_LEN || slice_len(aad) > MAX_MSG_LEN {
            return Err(SealError::InvalidLength);
        }
        if self.next >= self.limit {
            return Err(SealError::Exhausted);
        }
        if self.next >= self.reserved {
            return Err(SealError::NeedsReservation);
        }
        // Advance the counter first (the invariant only gets stronger), then
        // use the old value: the nonce is retired even if wolfCrypt fails.
        let counter = self.next;
        self.next = counter + 1;
        let nonce = encode_counter_nonce(&self.prefix, counter);
        proof {
            lemma_counter_nonce_injective_forall();
        }
        let res = self.gcm.seal_raw(Tracked(self.ledger.borrow_mut()), &nonce, aad, pt, ct);
        match res {
            Ok(tag) => Ok((nonce, tag)),
            Err(CryptoError) => Err(SealError::Crypto),
        }
    }

    /// Decrypt with this sealer's key (see [`Gcm::open`]).
    pub fn open(
        &mut self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
        tag: &[u8; TAG_LEN],
        out: &mut [u8],
    ) -> (r: Result<(), crate::gcm::OpenError>)
        ensures
            final(self).key() == old(self).key(),
            final(self).prefix() == old(self).prefix(),
            final(self).next() == old(self).next(),
            final(self).reserved() == old(self).reserved(),
            final(self).limit() == old(self).limit(),
            final(self).used() == old(self).used(),
            final(out)@.len() == old(out)@.len(),
            r is Ok ==> aes_gcm_seal(final(self).key(), nonce@, aad@, final(out)@) == (ct@, tag@),
            r is Err ==> forall|i: int| 0 <= i < final(out)@.len() ==> final(out)@[i] == 0u8,
        opens_invariants none
        no_unwind
    {
        proof { use_type_invariant(&*self); }
        self.gcm.open(nonce, aad, ct, tag, out)
    }
}

/// A freshly generated key's ledger admits starting at counter 0.
pub proof fn lemma_fresh_ledger(ledger: NonceLedger, prefix: Seq<u8>)
    requires
        ledger.used() == Set::<Seq<u8>>::empty(),
    ensures
        forall|c: u64| c >= 0 ==> !ledger.used().contains(#[trigger] counter_nonce(prefix, c)),
{
}

/// A resumed key's ledger admits starting at its high-water mark.
pub proof fn lemma_resumed_ledger(ledger: NonceLedger, prefix: Seq<u8>, high_water: u64)
    requires
        prefix.len() == PREFIX_LEN,
        forall|n: Seq<u8>| #[trigger] ledger.used().contains(n)
            ==> exists|c: u64| c < high_water && n == counter_nonce(prefix, c),
    ensures
        forall|c: u64| c >= high_water ==> !ledger.used().contains(#[trigger] counter_nonce(prefix, c)),
{
    lemma_counter_nonce_injective_forall();
    assert forall|c: u64| c >= high_water implies !ledger.used().contains(#[trigger] counter_nonce(prefix, c)) by {
        if ledger.used().contains(counter_nonce(prefix, c)) {
            let c2 = choose|c2: u64| c2 < high_water && counter_nonce(prefix, c) == counter_nonce(prefix, c2);
            assert(c == c2);
        }
    }
}

} // verus!
