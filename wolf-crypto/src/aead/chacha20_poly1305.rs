pub mod states;

use wolf_crypto_sys::{
    wc_ChaCha20Poly1305_Init,
    ChaChaPoly_Aead,
    wc_ChaCha20Poly1305_UpdateData, wc_ChaCha20Poly1305_UpdateAad,
    wc_ChaCha20Poly1305_Final,
    CHACHA20_POLY1305_AEAD_DECRYPT, CHACHA20_POLY1305_AEAD_ENCRYPT,

    wc_ChaCha20Poly1305_Decrypt, wc_ChaCha20Poly1305_Encrypt,
};

use states::{
    State, Init, CanUpdate, CanSetAad, CanUpdateAad,
    Updating, UpdatingAad,

    EncryptMaybeAad, DecryptMaybeAad,
    EncryptAad, DecryptAad,
};

#[doc(inline)]
pub use states::{Decrypt, Encrypt};

use core::mem::MaybeUninit;
use core::marker::PhantomData;
use core::ptr::addr_of_mut;
use crate::aead::{Aad, Tag};
use crate::buf::{GenericIv, U12};
use crate::mac::poly1305::GenericKey;
use crate::opaque_res::Res;
use crate::{can_cast_u32, Unspecified};

opaque_dbg! { ChaCha20Poly1305<Init> }
opaque_dbg! { ChaCha20Poly1305<EncryptMaybeAad> }
opaque_dbg! { ChaCha20Poly1305<DecryptMaybeAad> }
opaque_dbg! { ChaCha20Poly1305<EncryptAad> }
opaque_dbg! { ChaCha20Poly1305<DecryptAad> }
opaque_dbg! { ChaCha20Poly1305<Encrypt> }
opaque_dbg! { ChaCha20Poly1305<Decrypt> }

#[inline(always)]
#[must_use]
fn oneshot_predicate<A: Aad>(plain: &[u8], out: &[u8], aad: &A) -> bool {
    can_cast_u32(plain.len()) && out.len() >= plain.len() && aad.is_valid_size()
}

pub fn encrypt<K, IV, A>(
    key: K, iv: IV,
    plain: &[u8], out: &mut [u8],
    aad: A
) -> Result<Tag, Unspecified>
    where
        K: GenericKey,
        IV: GenericIv<Size = U12>,
        A: Aad
{
    if !oneshot_predicate(plain, out, &aad) { return Err(Unspecified) }
    let mut res = Res::new();
    let mut tag = Tag::new_zeroed();

    unsafe {
        res.ensure_0(wc_ChaCha20Poly1305_Encrypt(
            key.ptr(),
            iv.as_slice().as_ptr(),
            aad.ptr(),
            aad.size(),
            plain.as_ptr(),
            plain.len() as u32,
            out.as_mut_ptr(),
            tag.as_mut_ptr()
        ));
    }

    res.unit_err(tag)
}

pub fn encrypt_in_place<K, IV, A>(key: K, iv: IV, in_out: &mut [u8], aad: A) -> Result<Tag, Unspecified>
    where
        K: GenericKey,
        IV: GenericIv<Size = U12>,
        A: Aad
{
    if !(can_cast_u32(in_out.len()) && aad.is_valid_size()) { return Err(Unspecified) }
    let mut res = Res::new();
    let mut tag = Tag::new_zeroed();

    unsafe {
        res.ensure_0(wc_ChaCha20Poly1305_Encrypt(
            key.ptr(),
            iv.as_slice().as_ptr(),
            aad.ptr(),
            aad.size(),
            in_out.as_ptr(),
            in_out.len() as u32,
            in_out.as_ptr().cast_mut(),
            tag.as_mut_ptr()
        ));
    }

    res.unit_err(tag)
}

pub fn decrypt<K, IV, A>(
    key: K, iv: IV,
    cipher: &[u8], out: &mut [u8],
    aad: A, tag: Tag
) -> Result<(), Unspecified>
    where
        K: GenericKey,
        IV: GenericIv<Size = U12>,
        A: Aad
{
    if !oneshot_predicate(cipher, out, &aad) { return Err(Unspecified) }
    let mut res = Res::new();

    unsafe {
        res.ensure_0(wc_ChaCha20Poly1305_Decrypt(
            key.ptr(),
            iv.as_slice().as_ptr(),
            aad.ptr(),
            aad.size(),
            cipher.as_ptr(),
            cipher.len() as u32,
            tag.as_ptr(),
            out.as_mut_ptr()
        ));
    }

    res.unit_err(())
}

pub fn decrypt_in_place<K, IV, A>(
    key: K, iv: IV,
    in_out: &mut [u8],
    aad: A, tag: Tag
) -> Result<(), Unspecified>
where
    K: GenericKey,
    IV: GenericIv<Size = U12>,
    A: Aad
{
    if !(can_cast_u32(in_out.len()) && aad.is_valid_size()) { return Err(Unspecified) }
    let mut res = Res::new();

    unsafe {
        res.ensure_0(wc_ChaCha20Poly1305_Decrypt(
            key.ptr(),
            iv.as_slice().as_ptr(),
            aad.ptr(),
            aad.size(),
            in_out.as_ptr(),
            in_out.len() as u32,
            tag.as_ptr(),
            in_out.as_ptr().cast_mut()
        ));
    }

    res.unit_err(())
}
#[must_use]
#[repr(transparent)]
pub struct ChaCha20Poly1305<S: State = Init> {
    inner: ChaChaPoly_Aead,
    _state: PhantomData<S>
}

impl ChaCha20Poly1305<Init> {
    fn new_with_dir<K, IV, S>(key: K, iv: IV, dir: core::ffi::c_int) -> ChaCha20Poly1305<S>
        where
            K: GenericKey,
            IV: GenericIv<Size = U12>,
            S: State
    {
        debug_assert!(matches!(
            dir as core::ffi::c_uint,
            CHACHA20_POLY1305_AEAD_ENCRYPT | CHACHA20_POLY1305_AEAD_DECRYPT
        ));

        let mut inner = MaybeUninit::<ChaChaPoly_Aead>::uninit();

        unsafe {
            let _res = wc_ChaCha20Poly1305_Init(
                inner.as_mut_ptr(),
                key.ptr(),
                iv.as_slice().as_ptr(),
                dir
            );

            debug_assert_eq!(_res, 0);

            ChaCha20Poly1305::<S> {
                inner: inner.assume_init(),
                _state: PhantomData
            }
        }
    }

    pub fn new<Mode: Updating>(
        key: impl GenericKey,
        iv: impl GenericIv<Size = U12>
    ) -> ChaCha20Poly1305<Mode::InitState> {
        Self::new_with_dir(key, iv, Mode::direction())
    }
}

impl<S: State> ChaCha20Poly1305<S> {
    #[inline]
    const fn with_state<N: State>(self) -> ChaCha20Poly1305<N> {
        // SAFETY: we're just updating the phantom data state, same everything
        unsafe { core::mem::transmute(self) }
    }
}

impl<S: CanUpdateAad> ChaCha20Poly1305<S> {
    #[inline]
    unsafe fn update_aad_unchecked<A: Aad>(&mut self, aad: A) {
        let _res = wc_ChaCha20Poly1305_UpdateAad(
            addr_of_mut!(self.inner),
            aad.ptr(),
            aad.size()
        );

        debug_assert_eq!(_res, 0);
    }

    #[inline]
    pub fn update_aad<A: Aad>(mut self, aad: A) -> Result<ChaCha20Poly1305<S::Updating>, Self> {
        if !aad.is_valid_size() { return Err(self) }
        unsafe { self.update_aad_unchecked(aad); }
        Ok(self.with_state())
    }
}

impl<S: CanUpdate> ChaCha20Poly1305<S> {
    #[inline]
    unsafe fn update_in_place_unchecked(&mut self, data: &mut [u8]) -> Res {
        debug_assert!(can_cast_u32(data.len()));

        let mut res = Res::new();

        res.ensure_0(wc_ChaCha20Poly1305_UpdateData(
            addr_of_mut!(self.inner),
            // See comment at:
            // https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/chacha20_poly1305.c#L246
            // if you were wondering if it is safe to have the in and out ptr be the same.
            data.as_ptr(),
            data.as_ptr().cast_mut(),
            data.len() as u32
        ));

        res
    }

    #[inline]
    unsafe fn update_unchecked(&mut self, data: &[u8], output: &mut [u8]) -> Res {
        debug_assert!(data.len() <= output.len());
        debug_assert!(can_cast_u32(data.len()));

        let mut res = Res::new();

        res.ensure_0(wc_ChaCha20Poly1305_UpdateData(
            addr_of_mut!(self.inner),
            data.as_ptr(),
            output.as_mut_ptr(),
            data.len() as u32
        ));

        res
    }

    #[inline]
    #[must_use]
    const fn update_predicate(input: &[u8], output: &[u8]) -> bool {
        can_cast_u32(input.len()) && output.len() >= input.len()
    }

    pub fn update_in_place(mut self, data: &mut [u8]) -> Result<ChaCha20Poly1305<S::Mode>, Self> {
        if !can_cast_u32(data.len()) { return Err(self) }

        into_result! (unsafe { self.update_in_place_unchecked(data) },
            ok => self.with_state(),
            err => self
        )
    }

    pub fn update(mut self, data: &[u8], output: &mut [u8]) -> Result<ChaCha20Poly1305<S::Mode>, Self> {
        if !Self::update_predicate(data, output) { return Err(self) }

        into_result!(unsafe { self.update_unchecked(data, output) },
            ok => self.with_state(),
            err => self
        )
    }
}

impl<S: CanSetAad> ChaCha20Poly1305<S> {
    #[inline]
    pub fn set_aad<A: Aad>(
        mut self,
        aad: A
    ) -> Result<ChaCha20Poly1305<<S as CanSetAad>::Mode>, Self>
    {
        if !aad.is_valid_size() { return Err(self) }

        unsafe { self.update_aad_unchecked(aad); }
        Ok(self.with_state())
    }
}

impl<S: UpdatingAad> ChaCha20Poly1305<S> {
    pub const fn finish(self) -> ChaCha20Poly1305<S::Mode> {
        self.with_state()
    }
}

impl<S: Updating> ChaCha20Poly1305<S> {
    pub fn finalize(mut self) -> Result<Tag, Unspecified> {
        let mut tag = Tag::new_zeroed();
        let mut res = Res::new();

        unsafe {
            res.ensure_0(wc_ChaCha20Poly1305_Final(
                addr_of_mut!(self.inner),
                tag.as_mut_ptr()
            ));
        }

        res.unit_err(tag)
    }
}

#[cfg(test)]
mod tests {
    use crate::mac::poly1305::Key;
    use core::{
        slice,
        ptr
    };
    use super::*;

    #[test]
    fn type_state_machine() {
        let key = Key::new([0u8; 32]);

        let mut cipher = [69, 69, 69, 69];

        let tag = ChaCha20Poly1305::new::<Encrypt>(key.as_ref(), [0u8; 12])
            .set_aad(Some(Some(Some(())))).unwrap()
            .update_in_place(cipher.as_mut_slice()).unwrap()
            .finalize().unwrap();

        let new_tag = ChaCha20Poly1305::new::<Decrypt>(key.as_ref(), [0u8; 12])
            .set_aad(()).unwrap()
            .update_in_place(cipher.as_mut_slice()).unwrap()
            .finalize().unwrap();

        assert_eq!(tag, new_tag);
        assert_eq!(cipher, [69, 69, 69, 69]);
    }

    macro_rules! bogus_slice {
        ($size:expr) => {{
            let src = b"hello world";
            unsafe { slice::from_raw_parts(src.as_ptr(), $size) }
        }};
    }

    #[test]
    fn oneshot_size_predicate_fail() {
        // I am not allocating the maximum number for u32
        let slice = bogus_slice!(u32::MAX as usize + 1);
        let out = slice;
        assert!(!oneshot_predicate(slice, out, &()))
    }

    #[test]
    fn oneshot_size_predicate() {
        let slice = bogus_slice!(u32::MAX as usize - 1);
        let out = slice;
        assert!(oneshot_predicate(slice, out, &()))
    }

    #[test]
    fn oneshot_size_predicate_too_small_out() {
        let slice = bogus_slice!(u32::MAX as usize - 1);
        let out = bogus_slice!(u32::MAX as usize - 2);
        assert!(!oneshot_predicate(slice, out, &()));
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use crate::aes::test_utils::{BoundList};
    use crate::buf::Nonce;
    use crate::mac::poly1305::Key;
    use proptest::{prelude::*, proptest};

    proptest! {
        // these take some time. I ran with 50k cases once, but I cannot wait for these to pass
        // each time I run the tests.
        #![proptest_config(ProptestConfig::with_cases(5_000))]

        #[test]
        fn bijectivity(
            input in any::<BoundList<1024>>(),
            key in any::<Key>(),
            iv in any::<Nonce>()
        ) {
            let mut output = input.create_self();
            let tag = ChaCha20Poly1305::new::<Encrypt>(key.as_ref(), iv.copy())
                .update(input.as_slice(), output.as_mut_slice()).unwrap()
                .finalize().unwrap();

            if output.len() >= 6 {
                prop_assert_ne!(output.as_slice(), input.as_slice());
            }

            let mut decrypted = output.create_self();
            let d_tag = ChaCha20Poly1305::new::<Decrypt>(key.as_ref(), iv)
                .update(output.as_slice(), decrypted.as_mut_slice()).unwrap()
                .finalize().unwrap();

            prop_assert_eq!(tag, d_tag);
            prop_assert_eq!(decrypted.as_slice(), input.as_slice());
        }

        #[test]
        fn bijectivity_with_aad(
            input in any::<BoundList<1024>>(),
            key in any::<Key>(),
            iv in any::<Nonce>(),
            aad in any::<Option<String>>()
        ) {
            let mut output = input.create_self();
            let tag = ChaCha20Poly1305::new::<Encrypt>(key.as_ref(), iv.copy())
                .set_aad(aad.as_ref()).unwrap()
                .update(input.as_slice(), output.as_mut_slice()).unwrap()
                .finalize().unwrap();

            if output.len() >= 6 {
                prop_assert_ne!(output.as_slice(), input.as_slice());
            }

            let mut decrypted = output.create_self();
            let d_tag = ChaCha20Poly1305::new::<Decrypt>(key.as_ref(), iv)
                .set_aad(aad.as_ref()).unwrap()
                .update(output.as_slice(), decrypted.as_mut_slice()).unwrap()
                .finalize().unwrap();

            prop_assert_eq!(tag, d_tag);
            prop_assert_eq!(decrypted.as_slice(), input.as_slice());
        }

        #[test]
        fn oneshot_bijectivity(
            input in any::<BoundList<1024>>(),
            key in any::<Key>(),
            iv in any::<Nonce>()
        ) {
            let mut output = input.create_self();

            let tag = encrypt(
                key.as_ref(), iv.copy(),
                input.as_slice(), output.as_mut_slice(),
                ()
            ).unwrap();

            if output.len() >= 6 {
                prop_assert_ne!(output.as_slice(), input.as_slice());
            }

            let mut decrypted = output.create_self();
            prop_assert!(decrypt(
                key.as_ref(), iv,
                output.as_slice(), decrypted.as_mut_slice(),
                (), tag
            ).is_ok());

            prop_assert_eq!(input.as_slice(), decrypted.as_slice());
        }

        #[test]
        fn oneshot_bijectivity_with_aad(
            input in any::<BoundList<1024>>(),
            key in any::<Key>(),
            iv in any::<Nonce>(),
            aad in any::<Option<String>>()
        ) {
            let mut output = input.create_self();

            let tag = encrypt(
                key.as_ref(), iv.copy(),
                input.as_slice(), output.as_mut_slice(),
                aad.as_ref()
            ).unwrap();

            if output.len() >= 6 {
                prop_assert_ne!(output.as_slice(), input.as_slice());
            }

            let mut decrypted = output.create_self();
            prop_assert!(decrypt(
                key.as_ref(), iv,
                output.as_slice(), decrypted.as_mut_slice(),
                aad.as_ref(), tag
            ).is_ok());

            prop_assert_eq!(input.as_slice(), decrypted.as_slice());
        }
    }
}