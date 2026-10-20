//! Deterministic 96-bit nonce construction (VERIFIED).
//!
//! SP 800-38D 8.2.1: `nonce = fixed (4 bytes) || invocation counter (8 bytes,
//! big-endian)`. The fixed field identifies the encrypting context (device,
//! process role or direction) and must be unique per key among all contexts
//! that seal under that key; the counter is never repeated within a context.
//!
//! Proved here: the encoding is injective in the counter for a fixed prefix,
//! and the executable encoder computes exactly the specified bytes.

use vstd::prelude::*;

verus! {

/// Length of the fixed field of the nonce.
pub const PREFIX_LEN: usize = 4;

/// The counter is a `u64`; the largest usable invocation limit is `u64::MAX`
/// (counter values `0 ..= u64::MAX - 1`), so a sealer can represent its
/// exhausted state `next == limit` without overflow.
pub const MAX_INVOCATIONS: u64 = 0xffff_ffff_ffff_ffff;

/// Byte `i` (0 = most significant) of the big-endian encoding of `c`.
pub open spec fn be_byte(c: u64, i: int) -> u8 {
    ((c >> ((56 - 8 * i) as u64)) & 0xff) as u8
}

/// The 8-byte big-endian encoding of `c`.
pub open spec fn be_bytes(c: u64) -> Seq<u8> {
    seq![
        be_byte(c, 0), be_byte(c, 1), be_byte(c, 2), be_byte(c, 3),
        be_byte(c, 4), be_byte(c, 5), be_byte(c, 6), be_byte(c, 7),
    ]
}

/// The nonce used for invocation `c` of the context with fixed field `prefix`.
pub open spec fn counter_nonce(prefix: Seq<u8>, c: u64) -> Seq<u8> {
    prefix + be_bytes(c)
}

proof fn lemma_be_bytes_injective(a: u64, b: u64)
    requires
        be_bytes(a) == be_bytes(b),
    ensures
        a == b,
{
    assert(be_bytes(a)[0] == be_bytes(b)[0]);
    assert(be_bytes(a)[1] == be_bytes(b)[1]);
    assert(be_bytes(a)[2] == be_bytes(b)[2]);
    assert(be_bytes(a)[3] == be_bytes(b)[3]);
    assert(be_bytes(a)[4] == be_bytes(b)[4]);
    assert(be_bytes(a)[5] == be_bytes(b)[5]);
    assert(be_bytes(a)[6] == be_bytes(b)[6]);
    assert(be_bytes(a)[7] == be_bytes(b)[7]);
    assert(a == b) by (bit_vector)
        requires
            ((a >> 56u64) & 0xff) as u8 == ((b >> 56u64) & 0xff) as u8,
            ((a >> 48u64) & 0xff) as u8 == ((b >> 48u64) & 0xff) as u8,
            ((a >> 40u64) & 0xff) as u8 == ((b >> 40u64) & 0xff) as u8,
            ((a >> 32u64) & 0xff) as u8 == ((b >> 32u64) & 0xff) as u8,
            ((a >> 24u64) & 0xff) as u8 == ((b >> 24u64) & 0xff) as u8,
            ((a >> 16u64) & 0xff) as u8 == ((b >> 16u64) & 0xff) as u8,
            ((a >> 8u64) & 0xff) as u8 == ((b >> 8u64) & 0xff) as u8,
            ((a >> 0u64) & 0xff) as u8 == ((b >> 0u64) & 0xff) as u8,
    ;
}

/// Distinct counters give distinct nonces under the same fixed field, and
/// nonces with different fixed fields never collide.
pub proof fn lemma_counter_nonce_injective(p: Seq<u8>, a: u64, q: Seq<u8>, b: u64)
    requires
        p.len() == PREFIX_LEN,
        q.len() == PREFIX_LEN,
        counter_nonce(p, a) == counter_nonce(q, b),
    ensures
        p == q,
        a == b,
{
    let na = counter_nonce(p, a);
    let nb = counter_nonce(q, b);
    assert(p =~= na.subrange(0, 4));
    assert(q =~= nb.subrange(0, 4));
    assert(be_bytes(a) =~= na.subrange(4, 12));
    assert(be_bytes(b) =~= nb.subrange(4, 12));
    lemma_be_bytes_injective(a, b);
}

/// Universally quantified form of [`lemma_counter_nonce_injective`].
pub proof fn lemma_counter_nonce_injective_forall()
    ensures
        forall|p: Seq<u8>, a: u64, q: Seq<u8>, b: u64|
            p.len() == PREFIX_LEN && q.len() == PREFIX_LEN
                && #[trigger] counter_nonce(p, a) == #[trigger] counter_nonce(q, b)
                ==> p == q && a == b,
{
    assert forall|p: Seq<u8>, a: u64, q: Seq<u8>, b: u64|
        p.len() == PREFIX_LEN && q.len() == PREFIX_LEN
            && #[trigger] counter_nonce(p, a) == #[trigger] counter_nonce(q, b)
        implies p == q && a == b by {
        lemma_counter_nonce_injective(p, a, q, b);
    }
}

pub proof fn lemma_counter_nonce_len(p: Seq<u8>, c: u64)
    requires
        p.len() == PREFIX_LEN,
    ensures
        counter_nonce(p, c).len() == 12,
{
}

/// Build `prefix || be64(counter)`.
pub fn encode_counter_nonce(prefix: &[u8; PREFIX_LEN], counter: u64) -> (n: [u8; 12])
    ensures
        n@ == counter_nonce(prefix@, counter),
    opens_invariants none
    no_unwind
{
    let n: [u8; 12] = [
        prefix[0],
        prefix[1],
        prefix[2],
        prefix[3],
        (counter >> 56u64) as u8,
        (counter >> 48u64) as u8,
        (counter >> 40u64) as u8,
        (counter >> 32u64) as u8,
        (counter >> 24u64) as u8,
        (counter >> 16u64) as u8,
        (counter >> 8u64) as u8,
        counter as u8,
    ];
    proof {
        assert(((counter >> 56u64) as u8) == ((counter >> 56u64) & 0xff) as u8) by (bit_vector);
        assert(((counter >> 48u64) as u8) == ((counter >> 48u64) & 0xff) as u8) by (bit_vector);
        assert(((counter >> 40u64) as u8) == ((counter >> 40u64) & 0xff) as u8) by (bit_vector);
        assert(((counter >> 32u64) as u8) == ((counter >> 32u64) & 0xff) as u8) by (bit_vector);
        assert(((counter >> 24u64) as u8) == ((counter >> 24u64) & 0xff) as u8) by (bit_vector);
        assert(((counter >> 16u64) as u8) == ((counter >> 16u64) & 0xff) as u8) by (bit_vector);
        assert(((counter >> 8u64) as u8) == ((counter >> 8u64) & 0xff) as u8) by (bit_vector);
        assert((counter as u8) == ((counter >> 0u64) & 0xff) as u8) by (bit_vector);
        assert(n@ =~= counter_nonce(prefix@, counter));
    }
    n
}

} // verus!
