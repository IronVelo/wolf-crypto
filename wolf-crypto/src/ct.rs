//! Constant-Time Programming Utilities

#[cfg(llvm_ir_check)]
extern crate core;

use core::hint::black_box;
#[cfg(not(llvm_ir_check))]
use crate::opaque_res::Res;

#[cfg(llvm_ir_check)]
pub struct Res(pub bool);

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

    // LLVM or rustc is ridiculous
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
        2 => unsafe { unroll_ct_cmp!(g2 rem.wrapping_sub(2), res, a, b) },
        1 => unsafe { res &= byte_eq(*a.get_unchecked(0), *b.get_unchecked(0)) },
        _ => {}
    }

    res
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
        #![proptest_config(ProptestConfig::with_cases(10000))]

        #[test]
        fn ensure_cmp_slice(a in any::<BoundList<1028>>(), b in any::<BoundList<1028>>()) {
            let ct_res = cmp_slice(a.as_slice(), b.as_slice()) == 1;
            let res = a.as_slice() == b.as_slice();
            
            ensure!((ct_res) <==> (res));
            ensure!((!ct_res) <==> (!res));
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
}