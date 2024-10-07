//! Constant-Time Programming Utilities

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
/// UCSD PLSysSec.
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
    let sum = mask_add(a, b, core::hint::black_box(create_mask(overflow)));
    (sum, Res(overflow as u8 == 0))
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

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
}