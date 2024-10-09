//! Constant-Time Programming Utilities

#[cfg(llvm_ir_check)]
extern crate core;

use core::hint::black_box;
#[cfg(not(llvm_ir_check))]
use crate::opaque_res::Res;

#[cfg(llvm_ir_check)]
pub struct Res(pub bool);
#[cfg(not(llvm_ir_check))]
use crate::buf::InvalidSize;
#[cfg(llvm_ir_check)]
pub struct InvalidSize;

macro_rules! smear {
    ($b:ident) => {{
        $b |= $b >> 1;
        $b |= $b >> 2;
        $b |= $b >> 4;
        $b |= $b >> 8;
        $b |= $b >> 16;
    }};
}

/// Performs a constant-time greater-than comparison.
///
/// # Arguments
///
/// * `left` - The left-hand side operand.
/// * `right` - The right-hand side operand.
///
/// # Returns
///
/// Returns `1` if `left > right`, otherwise `0`.
///
/// # Constant Time Verification
///
/// To verify that this function is truly constant-time we leveraged `haybale-pitchfork` by
/// UCSD `PLSysSec`.
///
/// ## Debug Build
///
/// This project only supports llvm-14, so the original llvm-18 bitcode required slight manual
/// modifications. These modifications were only in removing LLVM's opaque pointer, replacing it
/// with the associated LLVM 15 and below pointer type (i32*).
///
/// You can find the original LLVM and the translation which we verified in the llvm directory in
/// this crate's manifest directory.
///
/// ### Results
///
/// ```txt
/// Results for gt:
///
/// verified paths: 1
/// constant-time violations found: 0
///
/// Coverage stats:
///
/// Block coverage of toplevel function (gt): 100.0%
///
///
/// gt is constant-time
/// ```
///
/// ## Optimized Build
///
/// In the optimized build, the LLVM IR contained no usage of opaque pointers, though the return
/// type was unsupported. So, the returning of the result was removed. Though in a separate check
/// this was confirmed to be constant time on its own.
///
/// ### Results
///
/// ```txt
/// Results for gt:
///
/// verified paths: 1
/// constant-time violations found: 0
///
/// Coverage stats:
///
///   Block coverage of toplevel function (gt): 100.0%
///
///
/// gt is constant-time
/// ```
///
/// # Functional Correctness
///
/// This was verified to be correct using `kani` with the assurance of completeness. You can
/// find the associated proof at the bottom of this file.
#[cfg_attr(llvm_ir_check, no_mangle)]
pub const fn gt(left: u32, right: u32) -> u32 {
    let gtb = left & !right;
    let mut ltb = !left & right;

    smear!(ltb);

    let mut bit = gtb & !ltb;
    // smear the highest set bit
    smear!(bit);

    bit & 1
}

#[inline(always)]
const fn create_mask(overflow: u32) -> u32 {
    !overflow.wrapping_neg()
}

#[inline(always)]
const fn mask_add(left: u32, right: u32, mask: u32) -> u32 {
    left.wrapping_add(right & mask)
}

/// Performs constant-time addition without wrapping on overflow.
///
/// # Arguments
///
/// * `a` - The first operand.
/// * `b` - The second operand.
///
/// # Returns
///
/// A tuple containing the sum and a `Res` indicating if there was no overflow.
///
/// # Constant Time Verification
///
/// See the above [`gt`] functions Constant Time Verification section for more details regarding
/// the setup, as the process is equivalent.
///
/// ## Results
///
/// ```txt
/// Results for add_no_wrap:
///
/// verified paths: 1
/// constant-time violations found: 0
///
/// Coverage stats:
///
///   Block coverage of toplevel function (add_no_wrap): 100.0%
///
///
/// add_no_wrap is constant-time
/// ```
#[cfg_attr(not(llvm_ir_check), inline)]
#[cfg_attr(llvm_ir_check, no_mangle)]
pub fn add_no_wrap(a: u32, b: u32) -> (u32, Res) {
    let overflow = gt(b, u32::MAX.wrapping_sub(a));

    // LLVM and rustc is ridiculous
    //
    // So, this:
    //   let sum = a.wrapping_add(b & (!overflow.wrapping_neg()));
    //
    // Got "optimized" (if you want to call pipeline bubbles optimization) into LLVM's select.
    // LLVM's select WITHOUT optimizations (what??) was performed with the bitmask as I wrote.
    //
    // Now, WITH optimizations LLVM's select got "optimized" into the following instructions:
    //   - testl   $65537, %ecx
    //   - cmovel  %esi, %eax
    //   - sete    %dl
    //
    // Great optimizations! Violated all constant time properties, and there isn't a chance in
    // hell that this is faster.
    //
    // black_box fixed this, there is no longer any select instruction in the IR, but this is still
    // quite annoying.
    let sum = mask_add(a, b, black_box(create_mask(overflow)));
    (sum, Res(overflow as u8 == 0))
}

#[inline(always)]
fn volatile(byte: u8) -> u8 {
    unsafe { core::ptr::read_volatile(&byte) }
}

#[inline(always)]
fn eq_hsb(xor: u8) -> u8 {
    volatile(xor | volatile(xor.wrapping_neg())) >> 7
}

#[cfg_attr(not(llvm_ir_check), inline(always))]
#[cfg_attr(llvm_ir_check, no_mangle)]
pub fn byte_eq(a: u8, b: u8) -> u8 {
    // LLVM IR without optimizations:
    //   ; Function Attrs: nonlazybind uwtable
    //   define i8 @byte_eq(i8 %a, i8 %b) unnamed_addr #1 {
    //   start:
    //     %xor = xor i8 %a, %b
    //     %_0.i = sub i8 0, %xor
    //     %_5 = or i8 %xor, %_0.i
    //     %set_hsb = lshr i8 %_5, 7
    //     %_0 = xor i8 %set_hsb, 1
    //     ret i8 %_0
    //   }
    //
    // LLVM IR with optimizations:
    //   ; Function Attrs: mustprogress nofree norecurse nosync nounwind nonlazybind willreturn memory(none) uwtable
    //   define noundef i8 @byte_eq(i8 noundef %a, i8 noundef %b) unnamed_addr #0 {
    //   start:
    //     %0 = icmp eq i8 %a, %b
    //     %_0 = zext i1 %0 to i8
    //     ret i8 %_0
    //   }
    //
    // OK so with optimizations it seems our constant time properties are being violated, that's
    // obviously unacceptable.
    //
    // Issue was in the original inlined:
    //
    //   (xor | xor.wrapping_neg()) >> 7
    //
    // Using a volatile read on the result of (xor | xor.wrapping_neg()) prevented our constant
    // time properties from being violated.
    //
    // Output assembly is also constant time:
    //
    //    xorl    %esi, %edi
    //    movl    %edi, %eax
    //    negb    %al
    //    orb %dil, %al
    //    movb    %al, -1(%rsp)
    //    movzbl  -1(%rsp), %eax
    //    notb    %al
    //    shrb    $7, %al
    //    retq
    //
    // Most concerning instruction to me is MOVZLB, but this is in general considered constant
    // time.
    //
    // Output assembly for debug builds is constant time as well:
    //
    //    movb    %sil, %al
    //    movb    %dil, %cl
    //    xorb    %cl, %al
    //    xorl    %ecx, %ecx
    //    subb    %al, %cl
    //    orb %cl, %al
    //    movb    %al, 7(%rsp)
    //    leaq    7(%rsp), %rdi
    //    callq   *_ZN4core3ptr13read_volatile17h7014fc51810b013aE@GOTPCREL(%rip)
    //    shrb    $7, %al
    //    xorb    $1, %al
    //    popq    %rcx
    //
    // OK, we are ready for verification of these constant time properties.

    eq_hsb(b ^ a) ^ volatile(1)
}

macro_rules! unroll_ct_cmp {
    (g2 $start:expr, $result:ident, $left:ident, $right:ident) => {{
        // I am using unchecked operations so that I can focus on what matters in the assembly for
        // debug builds without all of the noise of bounds checking. My usage is sound, and the
        // caller must wrap this macro in unsafe.
        $result &= byte_eq(*$left.get_unchecked($start), *$right.get_unchecked($start));
        $result &= byte_eq(
            *$left.get_unchecked($start.wrapping_add(1)),
            *$right.get_unchecked($start.wrapping_add(1))
        );
    }};
    (g4 $start:expr, $result:ident, $left:ident, $right:ident) => {
        unroll_ct_cmp!(g2 $start, $result, $left, $right);
        unroll_ct_cmp!(g2 $start.wrapping_add(2) as usize, $result, $left, $right);
    };
    (g8 $start:expr, $result:ident, $left:ident, $right:ident) => {{
        unroll_ct_cmp!(g4 $start, $result, $left, $right);
        unroll_ct_cmp!(g4 $start + 4, $result, $left, $right);
    }};
    (g16 $start:expr, $result:ident, $left:ident, $right:ident) => {{
        unroll_ct_cmp!(g8 $start, $result, $left, $right);
        unroll_ct_cmp!(g8 $start + 8, $result, $left, $right);
    }}
}

#[cfg_attr(llvm_ir_check, no_mangle)]
pub unsafe fn cmp_bytes_4_unchecked(mut res: u8, a: &[u8], b: &[u8]) -> u8 {
    unroll_ct_cmp!(g4 0usize, res, a, b);
    res
}

/// Compare two slices in constant-time.
///
/// # Note
///
/// If the length of slice `a` and slice `b` are not equivalent, this will exit early. In short,
/// there is variable timing on length comparisons.
///
/// # Warning
///
/// Constant-time programming is nuanced, this implementation provides a *best-effort*
/// constant-time equivalence check. While tools for verifying constant time properties over LLVM
/// bitcode, a great deal of testing, paired with manual review of the output assembly,
/// build some degree of confidence, there is still no guarantee of constant-time properties across
/// all existing hardware.
///
/// # Returns
///
/// * `0`: `a != b`
/// * `1`: `a == b`
#[cfg_attr(llvm_ir_check, no_mangle)]
#[must_use]
pub fn cmp_slice(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() { return 0 }

    let mut rem = a.len();
    let mut res = volatile(1u8);

    while rem >= 4 {
        // loop invariant (added post ct analysis).
        debug_assert!(rem <= a.len());

        let next = rem.wrapping_sub(4);
        // Again, bounds checking branches in debug builds are quite noisy, they get in the way
        // of reviewing the assembly for genuine constant-time violations. My usage is sound,
        // see the tests below if you are curious.
        res &= unsafe {
            cmp_bytes_4_unchecked(
                res,
                a.get_unchecked(next..rem),
                b.get_unchecked(next..rem)
            )
        };

        rem = next;
    }

    match rem {
        3 => unsafe {
            res &= byte_eq(*a.get_unchecked(0), *b.get_unchecked(0));
            unroll_ct_cmp!(g2 rem.wrapping_sub(2), res, a, b);
        }
        2 => unsafe { unroll_ct_cmp!(g2 rem.wrapping_sub(2), res, a, b) },
        1 => unsafe { res &= byte_eq(*a.get_unchecked(0), *b.get_unchecked(0)) },
        _ => {}
    }

    res
}

/// Compare two slices in constant-time.
///
/// # Arguments
///
/// The two arguments being compared in constant-time, both of these arguments must implement
/// `AsRef<[u8]>` (such as `&str`, `&[u8]` itself, etc.)
///
/// # Note
///
/// If the length of slice `a` and slice `b` are not equivalent, this will exit early. In short,
/// there is variable timing on length comparisons.
///
/// # Warning
///
/// Constant-time programming is nuanced, this implementation provides a *best-effort*
/// constant-time equivalence check. While tools for verifying constant time properties over LLVM
/// bitcode, a great deal of testing, paired with manual review of the output assembly,
/// build some degree of confidence, there is still no guarantee of constant-time properties across
/// all existing hardware.
///
/// # Returns
///
/// `true` if `a == b`, `false` otherwise.
#[must_use]
pub fn ct_eq<A: AsRef<[u8]>, B: AsRef<[u8]>>(a: A, b: B) -> bool {
    cmp_slice(a.as_ref(), b.as_ref()) != 0
}

#[must_use]
#[inline]
pub const fn hex_encode_len(len: usize) -> usize {
    len << 1
}

#[inline]
fn encode_byte(byte: u8, output: &mut [u8]) {
    let lower = (byte & 0xf) as u32;
    let upper = (byte >> 4) as u32;

    let h =
        87u32.wrapping_add(lower)
            .wrapping_add(lower.wrapping_sub(10u32).wrapping_shr(8) & !38u32)
            .wrapping_shl(8)
            |
            87u32.wrapping_add(upper)
                .wrapping_add(upper.wrapping_sub(10u32).wrapping_shr(8) & !38u32);

    // truncate
    output[0] = h as u8;
    // get highest byte
    output[1] = h.wrapping_shr(8) as u8;
}

/*
    Hex Encode to the str Type Considerations.

    While we are certain we are always producing valid utf8, using str::from_utf8 is still risky
    due to its data dependent branches.

    So, it is best to avoid this in favor of the unsafe alternative, though this comes with risks,
    and these risks must be addressed via verification. While we already have a property test which
    checks that the hex_encode function always produces utf8 with 1 million inputs, this is simply
    not enough.

    The challenge with using a CBMC approach with some degree of completeness is unwinding. If we
    were to verify for all slices that hex_encode produces utf8 this would be incredibly
    resource intensive, and a consumer grade PC simply cannot hold up here.

    But this is thinking about the problem incorrectly, as what really matters is does the encoding
    of a single byte always produce valid utf8. If that is guaranteed, then the correctness of
    hex_encode can be guaranteed via structural induction over the input slice.

    The inductive argument would be as follows:
    1. Base case: Prove that encoding a single byte always produces valid UTF-8.
    2. Inductive step: Assume encoding n bytes produces valid UTF-8, then prove that
       encoding n+1 bytes also produces valid UTF-8.

    This approach allows us to reason about the correctness of hex_encode for inputs
    of arbitrary length without needing to verify all possible inputs exhaustively.
*/

/// Constant-time Hex Encoding
///
/// # Arguments
///
/// * `input`  - A slice of bytes to be hex-encoded.
/// * `output` - The buffer to write the hex string into.
///
/// # Returns
///
/// The number of bytes written to the `output` buffer (which will always be twice the length of
/// the input).
///
/// # Errors
///
/// This function returns `Err(InvalidSize)` if the `output` buffer has a length less than
/// `input.len() * 2`.
///
/// # Security
///
/// This function is designed to operate in constant-time, avoiding data-dependent branches that
/// could lead to timing side-channel attacks. The encoding process uses arithmetic and bitwise
/// operations to guarantee uniform execution time regardless of the input values.
///
/// # UTF-8 Considerations
///
/// Rust's `str::from_utf8` is discouraged in contexts that require constant-time execution due
/// to the presence of data-dependent branches plus lookup tables in its implementation.
///
/// **It is safe to use `str::from_utf8_unchecked` on the output of this function**, however,
/// **it is only safe over the encoded region of the output buffer** (up until the returned
/// length). If you need a `str` representation, consider the less error-prone [`encode_str`]
/// function.
///
/// If you are curious / skeptical of the safety in this recommendation, please read the
/// verification section below.
///
/// # Example
///
/// ```
/// use wolf_crypto::{hex, ct_eq};
///
/// let mut output = [0u8; 22]; // 11 * 2
/// let len = hex::encode_into(b"hello world", &mut output).unwrap();
///
/// assert_eq!(len, 22);
/// assert!(
///     // since we are using a constant-time encoding, we probably also want
///     // to use a constant-time comparison.
///     ct_eq(
///         // SAFETY: The encoded output is formally guaranteed to be valid
///         // UTF-8. This is just for example, ct_eq can of course compare slices.
///         unsafe { core::str::from_utf8_unchecked(&output[..len]) },
///         "68656c6c6f20776f726c64"
///     )
/// );
///
/// // or use the `encode_str` function, which is simply a less error-prone variant of this
/// // if `str` representation is a requirement.
///
/// let mut output = [0u8; 22];
/// let str_repr = hex::encode_str(b"hello world", &mut output).unwrap();
///
/// // ...
/// ```
///
/// # Verification
///
/// The correctness and safety of the `encode_into` function have been rigorously verified using a
/// combination of formal methods and property-based testing. This multi-faceted approach ensures
/// a high degree of confidence in the function's behavior and its adherence to the specified
/// properties.
///
/// ## Formal Verification
///
/// We employed formal verification techniques using the Kani Rust Verifier to prove key properties
/// of the `encode_into` function and its components.
///
/// ### Inductive Proof Strategy
///
/// The verification process follows an inductive proof strategy:
///
/// 1. Base Case: We prove that encoding a single byte always produces valid UTF-8.
/// 2. Inductive Step: We prove that if encoding n bytes produces valid UTF-8, then encoding
///    n+1 bytes also produces valid UTF-8.
///
/// This approach allows us to reason about the correctness of `encode_into` for inputs of arbitrary
/// length without needing to verify all possible inputs exhaustively.
///
/// ### Key Proofs
///
/// 1. Single Byte Encoding:
///    The `encode_byte_is_always_utf8` proof verifies that for any input byte, the output of
///    encode_byte is always valid hexadecimal (and thus valid UTF-8).
///
/// 2. Inductive Step:
///    - The `verify_encode_n_plus_1_bytes_symbolic` proof demonstrates that if encoding n bytes
///      produces valid UTF-8, encoding an additional byte preserves this property.
///    - The `verify_hex_encode_inductive_step_symbolic` proof applies this principle to the
///      hex_encode function itself, verifying that the UTF-8 validity is maintained for
///      arbitrary input lengths.
///
/// [`encode_str`]: crate::hex::encode_str
#[cfg_attr(llvm_ir_check, no_mangle)]
pub fn hex_encode(input: &[u8], output: &mut [u8]) -> Result<usize, InvalidSize> {
    let hex_len = hex_encode_len(input.len());

    #[cfg(any(check, kani, test))] {
        ensure!((hex_len == 0) <==> (input.len() == 0));
        ensure!((hex_len != 0) <==> (input.len() != 0));
    }

    if output.len() < hex_len { return Err(InvalidSize) }

    #[cfg(any(check, kani, test))]
    let mut post_len = 0usize;

    for (pos, byte) in input.iter().enumerate() {
        let o_pos = pos.wrapping_shl(1);

        #[cfg(any(check, kani, test))] {
            ensure!((pos != 0) ==> (is_valid_hex_2(output[o_pos - 2], output[o_pos - 1])));
            post_len = o_pos + 1;
        }

        encode_byte(*byte, &mut output[o_pos..o_pos + 2]);
    }

    #[cfg(any(check, kani, test))] {
        ensure!((hex_len != 0) ==> (is_valid_hex_2(output[post_len - 1], output[post_len])));
        ensure!((hex_len != 0) ==> (post_len + 1 == hex_len));
    }

    Ok(hex_len)
}

/// Constant-time Hex Encoding to a `&str`
///
/// # Arguments
///
/// * `input`  - A slice of bytes to be hex-encoded.
/// * `output` - A mutable byte buffer where the encoded string will be written.
///
/// # Returns
///
/// The encoded string slice (`&str`).
///
/// # Errors
///
/// If the `output` buffer is less than the encoded length (`input.len() * 2`), this returns
/// `InvalidSize`.
///
/// # Notes
///
/// This function is a convenience wrapper around [`encode_into`], which handles the
/// encoding process, this simply returns the `str` representation in a safe manner.
///
/// For full details on the underlying encoding and security/safety guarantees, see [`encode_into`].
///
/// # Example
///
/// ```
/// use wolf_crypto::{hex, ct_eq};
///
/// let mut output = [0u8; 22]; // 11 * 2
/// let str_repr = hex::encode_str(b"hello world", &mut output).unwrap();
///
/// assert!(ct_eq(str_repr, "68656c6c6f20776f726c64"));
/// ```
///
/// [`encode_into`]: crate::hex::encode_into
#[inline]
pub fn hex_encode_str<'o>(input: &[u8], output: &'o mut [u8]) -> Result<&'o str, InvalidSize> {
    hex_encode(input, output)
        // SAFETY: See the verification section of `hex_encode` and the proofs at the bottom
        // of this module.
        .map(move |len| unsafe { core::str::from_utf8_unchecked(&output[..len]) })
}

#[cfg(not(llvm_ir_check))]
alloc! {
    /// Constant-Time Hex Encoding
    ///
    /// # Arguments
    ///
    /// * `input`  - A slice of bytes to be hex-encoded.
    ///
    /// # Returns
    ///
    /// The hex-encoded `String`
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{hex, ct_eq};
    ///
    /// let encoded = hex::encode(b"hello world");
    /// let decoded = hex::decode(encoded.as_bytes()).unwrap();
    ///
    /// assert!(ct_eq(b"hello world", decoded));
    /// ```
    pub fn hex_encode_alloc(input: &[u8]) -> alloc::string::String {
        let mut output = vec![0u8; hex_encode_len(input.len())];
        hex_encode(input, output.as_mut_slice()).unwrap(/* Infallible */);
        // We may ignore the returned output length, as we provided a vector with the exact size
        // of the output
        unsafe {
            alloc::string::String::from_utf8_unchecked(output)
        }
    }
}

#[inline]
const fn decode_nibble(first: u8) -> u16 {
    let byte = first as i16;
    let mut ret: i16 = -1;

    ret = ret.wrapping_add(
        (0x2fi16.wrapping_sub(byte) & byte.wrapping_sub(0x3a)).wrapping_shr(8)
            & byte.wrapping_sub(47)
    );

    ret = ret.wrapping_add(
        (0x60i16.wrapping_sub(byte) & byte.wrapping_sub(0x67)).wrapping_shr(8)
            & byte.wrapping_sub(86)
    );

    ret as u16
}

#[must_use]
const fn decode_predicate(inp_len: usize, out_len: usize) -> (bool, usize) {
    let dec_len = inp_len >> 1;
    (inp_len & 1 == 0 && out_len >= dec_len, dec_len)
}

/// Possible errors while decoding a hex string.
pub enum HexError {
    /// An invalid character was encountered or the length of the hex-encoded data was invalid.
    Encoding,
    /// The output size was not large enough.
    Size
}

impl From<InvalidSize> for HexError {
    fn from(_value: InvalidSize) -> Self {
        Self::Size
    }
}

#[cfg(not(llvm_ir_check))]
impl From<HexError> for crate::Unspecified {
    fn from(_value: HexError) -> Self {
        Self
    }
}

#[cfg(not(llvm_ir_check))]
impl core::fmt::Display for HexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Size => f.write_str("HexError::Size"),
            Self::Encoding => f.write_str("HexError::Encoding")
        }
    }
}

#[cfg(not(llvm_ir_check))]
impl core::fmt::Debug for HexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        <Self as core::fmt::Display>::fmt(self, f)
    }
}

#[cfg(not(llvm_ir_check))]
std! { impl std::error::Error for HexError {} }

/// Constant-Time Hex Decoding
///
/// # Arguments
///
/// * `input`  - The hex-encoded slice to decode into `output`.
/// * `output` - The output buffer which the `input` is decoded into. This must be at least
///   `input.len() / 2` in size.
///
/// # Errors
///
/// - [`HexError::Size`]: The output could not fit the decoded input, or the input was of invalid
///   length.
/// - [`HexError::Encoding`]: An invalid character was encountered.
///
/// # Returns
///
/// The amount of data which was decoded (`input.len() / 2`).
pub fn hex_decode(input: &[u8], output: &mut [u8]) -> Result<usize, HexError> {
    let (valid_len, dec_len) = decode_predicate(input.len(), output.len());
    if !valid_len { return Err(HexError::Size) }

    let mut err: u16 = 0;

    // `take` to guard against the length being zero
    for (pos, o_byte) in output.iter_mut().enumerate().take(dec_len) {
        let src_pos = pos << 1;

        let byte = decode_nibble(input[src_pos]).wrapping_shl(4)
            | decode_nibble(input[src_pos + 1]);

        err |= byte >> 8;

        *o_byte = byte as u8;
    }

    if err == 0 {
        Ok(dec_len)
    } else {
        Err(HexError::Encoding)
    }
}

#[cfg(not(llvm_ir_check))]
alloc! {
    /// Constant-Time Hex Decoding
    ///
    /// # Arguments
    ///
    /// * `input`  - The hex-encoded slice to decode.
    ///
    /// # Errors
    ///
    /// - [`HexError::Size`]: The `input` length was not an even number.
    /// - [`HexError::Encoding`]: An invalid character was encountered.
    ///
    /// # Returns
    ///
    /// The decoded bytes.
    pub fn hex_decode_alloc(input: &[u8]) -> Result<Vec<u8>, HexError> {
        let mut output = vec![0u8; input.len() >> 1];
        hex_decode(input, output.as_mut_slice()).map(move |_| output)
    }
}

#[cfg(any(test, kani, check))]
const fn is_valid_hex(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z'
        | b'a'..=b'z'
        | b'0'..=b'9'
    )
}

#[cfg(any(test, kani, check))]
const fn is_valid_hex_2(first: u8, second: u8) -> bool {
    is_valid_hex(first) && is_valid_hex(second)
}

#[cfg(any(kani, check))]
const fn is_valid_hex_4(a: u8, b: u8, c: u8, d: u8) -> bool {
    is_valid_hex_2(a, b) && is_valid_hex_2(c, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmp_slice_eq_smoke() {
        let a = [3u8; 17];
        let b = [3u8; 17];

        assert_eq!(cmp_slice(a.as_slice(), b.as_slice()), 1);
    }

    macro_rules! str {
        ($expr:expr) => {
            core::str::from_utf8($expr).unwrap()
        };
    }

    #[test]
    fn hex_encode_works() {
        let mut out = [0u8; 22];
        let len = hex_encode(b"hello world", &mut out).unwrap();
        assert_eq!(len, 22);
        assert_eq!(str!(&out), "68656c6c6f20776f726c64");
    }

    #[test]
    fn hex_encode_to_decode() {
        let mut out = [0u8; 22];
        let _len = hex_encode(b"hello world", &mut out).unwrap();

        let mut dec = [0u8; 11];
        let read = hex_decode(&out, &mut dec).unwrap();

        assert_eq!(read, 11);
        assert_eq!(&dec, b"hello world");
    }

    #[test]
    fn invalid_hex() {
        let mut out = [0; 69];
        assert!(hex_decode(b"hello world I am not valid hex !!!", &mut out).is_err());
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use crate::aes::test_utils::BoundList;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100_000))]

        #[test]
        fn enusre_ct_add_no_wrap(a in any::<u32>(), b in any::<u32>()) {
            let (out, res) = add_no_wrap(a, b);

            ensure!(( res.is_err() ) <==> ( a.checked_add(b).is_none() ));
            ensure!(( out == a )     <==> ( res.is_err() || b == 0 ));
            ensure!(( res.is_ok() )  <==> ( out != a || b == 0 ));
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10_000))]

        #[test]
        fn ensure_cmp_slice(a in any::<BoundList<1024>>(), b in any::<BoundList<1024>>()) {
            let ct_res = cmp_slice(a.as_slice(), b.as_slice()) == 1;
            let res = a.as_slice() == b.as_slice();
            
            ensure!((ct_res) <==> (res));
            ensure!((!ct_res) <==> (!res));
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50_000))]

        #[test]
        fn hex_encode_is_hex_crate(
            bin in any::<BoundList<1024>>()
        ) {
            let output_len = hex_encode_len(bin.len());
            let mut output = BoundList::<2048>::new_zeroes(output_len);

            let res = hex::encode(bin.as_slice());
            let len = hex_encode(bin.as_slice(), output.as_mut_slice()).unwrap();

            prop_assert_eq!(res.len(), len);
            prop_assert_eq!(res.as_bytes(), output.as_slice());
        }

        #[test]
        fn hex_is_bijective(
            bin in any::<BoundList<1024>>()
        ) {
            let output_len = hex_encode_len(bin.len());
            let mut output = BoundList::<2048>::new_zeroes(output_len);

            let len = hex_encode(bin.as_slice(), output.as_mut_slice()).unwrap();

            prop_assert_eq!(len, output.len());

            let mut decoded = bin.create_self();
            let len = hex_decode(output.as_slice(), decoded.as_mut_slice()).unwrap();

            prop_assert_eq!(len, bin.len());
            prop_assert_eq!(decoded.as_slice(), bin.as_slice());
        }
    }

    // I'd run tests in release.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1_000_000))]

        #[test]
        fn hex_encode_is_valid_utf8(
            bin in any::<BoundList<256>>()
        ) {
            let output_len = hex_encode_len(bin.len());
            let mut output = BoundList::<512>::new_zeroes(output_len);

            hex_encode(bin.as_slice(), output.as_mut_slice()).unwrap();

            prop_assert!(core::str::from_utf8(output.as_slice()).is_ok());
        }
    }
}

#[cfg(kani)]
mod verify {
    use super::*;
    use kani::proof;

    #[proof]
    fn check_ct_add_no_wrap() {
        let a = kani::any();
        let b = kani::any();

        let (out, res) = add_no_wrap(a, b);

        ensure!(( res.is_err() ) <==> ( a.checked_add(b).is_none() ));
        ensure!(( out == a )     <==> ( res.is_err() || b == 0 ));
        ensure!(( res.is_ok() )  <==> ( out != a || b == 0 ));
    }

    #[proof]
    fn check_ct_gt() {
        let a = kani::any();
        let b = kani::any();

        let is_gt = gt(a, b) == 1;

        ensure!((is_gt) <==> (a > b));
        ensure!((!is_gt) <==> (a <= b));
    }

    // This has crashed my computer multiple times due to kani using something like 160gb of memory.
    // Had to dial it down significantly.
    #[proof]
    #[kani::unwind(12)]
    fn check_slice_cmp() {
        let a = kani::vec::any_vec::<u8, 7>();
        let b = kani::vec::any_vec::<u8, 7>();

        let res = a == b;
        let ct_res = cmp_slice(a.as_slice(), b.as_slice()) == 1;

        ensure!((res) <==> (ct_res));
        ensure!((!res) <==> (!ct_res));
    }

    #[proof]
    fn encode_byte_is_always_utf8() {
        let byte: u8 = kani::any();
        let mut out = [0u8; 2];

        encode_byte(byte, &mut out);

        kani::assert(
            is_valid_hex_2(out[0], out[1]),
            "For all bytes, the output must always be valid UTF8"
        );
    }

    #[proof]
    fn verify_encode_n_plus_1_bytes_symbolic() {
        // This proof symbolically represents the inductive step:
        // If encoding n bytes produces valid UTF-8, then encoding n+1 bytes also produces valid
        // UTF-8.

        let byte: u8 = kani::any();
        let mut out = [0u8; 4];

        encode_byte(byte, &mut out);

        let byte: u8 = kani::any();
        encode_byte(byte, &mut out[2..]);

        kani::assert(
            is_valid_hex_2(out[0], out[1]) && is_valid_hex_2(out[2], out[3]),
            "Encoding an additional byte preserves UTF-8 validity"
        );
    }

    // Now, we simply re-apply what we have done using encode byte individually to symbolically
    // prove the inductive step to the actual hex_encode function. This function already has
    // postconditions which are checked via kani, so we do not need to rewrite any part of the
    // specification here.
    //
    // Again, this is a symbolic proof, as for all slices would crash a computer and is logically
    // equivalent to symbolically proving the inductive step.
    #[proof]
    fn verify_hex_encode_inductive_step_symbolic() {
        // no real harm in doing more as long as our PC can handle it. However, there is no benefit
        // to this.
        let input: [u8; 6] = kani::any();
        let mut output = [0u8; 12];

        hex_encode(&input, &mut output).unwrap();

        kani::assert(
            is_valid_hex_4(output[0], output[1], output[2], output[3])
                && is_valid_hex_4(output[4], output[5], output[6], output[7])
                && is_valid_hex_4(output[8], output[9], output[10], output[11]),
            "Encoding an additional byte preserves UTF-8 validity"
        )
    }
}