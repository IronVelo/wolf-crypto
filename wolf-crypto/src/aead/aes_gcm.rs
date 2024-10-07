use core::ffi::c_int;
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;
use wolf_crypto_sys::{
    Aes as AesLL,
    wc_AesFree, wc_AesGcmDecrypt, wc_AesGcmEncrypt, wc_AesGcmSetKey
};
use crate::buf::GenericIv;
use crate::ptr::ConstPtr;
use crate::{can_cast_u32, Unspecified};
use crate::aead::{Aad, Tag};
use crate::aes::{init_aes, Key};
use crate::opaque_res::Res;

#[inline(always)]
#[must_use]
pub(crate) unsafe fn aes_set_key(aes: *mut AesLL, key: ConstPtr<Key>) -> c_int {
    wc_AesGcmSetKey(
        aes,
        key.as_slice().as_ptr(),
        key.capacity() as u32
    )
}

/// Represents an AES-GCM (Galois/Counter Mode) instance.
#[repr(transparent)]
pub struct AesGcm {
    inner: AesLL,
}

impl AesGcm {
    /// Create a new AES-GCM instance.
    ///
    /// # Arguments
    ///
    /// * `key` - The key material to use.
    ///
    /// # Returns
    ///
    /// A new AES-GCM instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the key setup fails.
    pub fn new(key: &Key) -> Result<Self, Unspecified> {
        unsafe {
            let (mut aes, mut res) = init_aes(MaybeUninit::<AesLL>::uninit());
            res.ensure_0(aes_set_key(aes.as_mut_ptr(), ConstPtr::new(key)));
            res.unit_err_with(|| Self { inner: aes.assume_init() })
        }
    }

    /// Encrypt data using AES-GCM with compile-time known sizes.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The nonce (IV) to use for encryption.
    /// * `input` - The input data to encrypt.
    /// * `output` - The output buffer to store the encrypted data.
    /// * `aad` - Additional Authenticated Data.
    ///
    /// # Errors
    /// 
    /// - The size of `input` is greater than [`u32::MAX`].
    /// - The provided AAD's length is greater than [`u32::MAX`].
    /// 
    /// # Returns
    ///
    /// The associated authentication [`Tag`].
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{aead::{AesGcm, AadSlice}, aes::Key, buf::Nonce};
    ///
    /// let key = Key::Aes256([1u8; 32]);
    /// let nonce: Nonce = [2u8; 12].into();;
    ///
    /// let input = [3u8; 32];
    /// let mut output = [0u8; 32];
    ///
    /// let mut gcm = AesGcm::new(&key).unwrap();
    /// let tag = gcm.encrypt_sized(nonce, &input, &mut output, AadSlice::EMPTY).unwrap();
    ///
    /// assert_ne!(input, output);
    /// ```
    #[inline]
    pub fn encrypt_sized<const C: usize, N: GenericIv, A: Aad>(
        &mut self, nonce: N, input: &[u8; C], output: &mut [u8; C], aad: A
    ) -> Result<Tag, Unspecified> {
        if !aad.is_valid_size() { return Err(Unspecified) }
        unsafe {
            // SAFETY:
            //
            // Since the input and the output are the same size (assured by the type system) there
            // is no risk of going out of bounds on any operation.
            //
            // The Nonce is also ensured to be of the correct size from the type system.
            self.encrypt_unchecked(nonce.as_slice(), input.as_slice(), output.as_mut_slice(), aad)
        }
    }

    #[inline]
    #[must_use]
    fn arg_predicate<A: Aad>(input: &[u8], output: &[u8], aad: &A) -> bool {
        input.len() <= output.len()
            && can_cast_u32(input.len())
            && aad.is_valid_size()
    }

    /// Try to encrypt data using AES-GCM.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The nonce (IV) to use for encryption.
    /// * `input` - The input data to encrypt.
    /// * `output` - The output buffer to store the encrypted data.
    /// * `aad` - Additional Authenticated Data.
    ///
    /// # Returns
    ///
    /// The authentication tag on success, or an error.
    ///
    /// # Errors
    ///
    /// - If the input buffer is larger than the output buffer.
    /// - If the input or AAD size is greater than what can be represented by a u32.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{aead::{AesGcm, AadSlice}, aes::Key, buf::Nonce};
    ///
    /// let key = Key::Aes256([1u8; 32]);
    /// let nonce: Nonce = [2u8; 12].into();
    ///
    /// let mut output = [0u8; 32];
    /// let input = [3u8; 32];
    ///
    /// let mut gcm = AesGcm::new(&key).unwrap();
    /// let tag = gcm.try_encrypt(nonce, &input, &mut output, AadSlice::EMPTY).unwrap();
    ///
    /// assert_ne!(input, output);
    /// ```
    #[inline]
    pub fn try_encrypt<N: GenericIv, A: Aad>(
        &mut self, nonce: N, input: &[u8], output: &mut [u8], aad: A
    ) -> Result<Tag, Unspecified> {
        if !Self::arg_predicate(input, output, &aad) { return Err(Unspecified) }

        unsafe {
            // SAFETY:
            //
            // We've guarded against the output being smaller than the input, the nonce type ensures
            // the correct size is used.
            self.encrypt_unchecked(nonce.as_slice(), input, output, aad)
        }
    }

    panic_api! {
    /// Encrypt data using AES-GCM, panicking on failure.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The nonce (IV) to use for encryption.
    /// * `input` - The input data to encrypt.
    /// * `output` - The output buffer to store the encrypted data.
    /// * `aad` - Additional Authenticated Data.
    ///
    /// # Returns
    ///
    /// The authentication tag.
    ///
    /// # Panics
    ///
    /// - If the input buffer is larger than the output buffer.
    /// - If the input or AAD size is greater than what can be represented by a u32.
    /// - If the encryption operation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{aead::{AesGcm, AadSlice}, aes::Key, buf::Nonce};
    ///
    /// let key = Key::Aes256([1u8; 32]);
    /// let nonce: Nonce = [2u8; 12].into();
    ///
    /// let mut output = [0u8; 32];
    /// let input = [3u8; 32];
    ///
    /// let mut gcm = AesGcm::new(&key).unwrap();
    /// let tag = gcm.encrypt(nonce, &input, &mut output, AadSlice::EMPTY);
    ///
    /// assert_ne!(input, output);
    /// ```
    #[track_caller]
    #[inline]
    pub fn encrypt<N: GenericIv, A: Aad>(
        &mut self, nonce: N, input: &[u8], output: &mut [u8], aad: A
    ) -> Tag {
        self.try_encrypt(nonce, input, output, aad).unwrap()
    }
    }

    pub(crate) unsafe fn encrypt_unchecked<A: Aad>(
        &mut self, nonce: &[u8], input: &[u8], output: &mut [u8], aad: A
    ) -> Result<Tag, Unspecified> {
        let mut tag = Tag::new_zeroed();
        let mut res = Res::new();

        res.ensure_0(wc_AesGcmEncrypt(
            addr_of_mut!(self.inner),
            output.as_mut_ptr(),
            input.as_ptr(),
            input.len() as u32,
            nonce.as_ptr(),
            nonce.len() as u32,
            tag.as_mut_ptr(),
            Tag::CAPACITY as u32,
            aad.ptr(),
            aad.size()
        ));

        res.unit_err(tag)
    }

    /// Decrypt data using AES-GCM with compile-time known sizes.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The nonce (IV) used for encryption.
    /// * `input` - The input data to decrypt.
    /// * `output` - The output buffer to store the decrypted data.
    /// * `aad` - Additional Authenticated Data.
    /// * `tag` - The authentication tag from encryption.
    ///
    /// # Returns
    ///
    /// A `Res` indicating success or failure.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{aead::{AesGcm, AadSlice}, aes::Key, buf::Nonce};
    ///
    /// let key = Key::Aes256([1u8; 32]);
    /// let nonce: Nonce = [2u8; 12].into();
    ///
    /// let mut ciphertext = [0u8; 32];
    /// let plaintext = [3u8; 32];
    /// let aad = AadSlice::EMPTY;
    ///
    /// let mut gcm = AesGcm::new(&key).unwrap();
    /// let tag = gcm.encrypt_sized(nonce.copy(), &plaintext, &mut ciphertext, aad).unwrap();
    ///
    /// let mut decrypted = [0u8; 32];
    /// let result = gcm.decrypt_sized(nonce, &ciphertext, &mut decrypted, aad, &tag);
    ///
    /// assert!(result.is_ok());
    /// assert_eq!(plaintext, decrypted);
    /// ```
    #[inline]
    pub fn decrypt_sized<const C: usize, N: GenericIv, A: Aad>(
        &mut self, nonce: N, input: &[u8; C], output: &mut [u8; C], aad: A, tag: &Tag
    ) -> Res {
        if !aad.is_valid_size() { return Res::ERR }
        unsafe {
            // SAFETY:
            //
            // Since the input and the output are the same size (assured by the type system) there
            // is no risk of going out of bounds on any operation.
            //
            // The Nonce is also ensured to be of the correct size from the type system.
            self.decrypt_unchecked(
                nonce.as_slice(),
                input.as_slice(), output.as_mut_slice(),
                aad, tag
            )
        }
    }

    /// Try to decrypt data using AES-GCM.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The nonce (IV) used for encryption.
    /// * `input` - The input data to decrypt.
    /// * `output` - The output buffer to store the decrypted data.
    /// * `aad` - Additional Authenticated Data.
    /// * `tag` - The authentication tag from encryption.
    ///
    /// # Returns
    ///
    /// A `Res` indicating success or failure.
    ///
    /// # Errors
    ///
    /// - If the input buffer is larger than the output buffer.
    /// - If the input or AAD size is greater than what can be represented by a u32.
    /// - If the decryption operation fails (including authentication failure).
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{aead::AesGcm, aes::Key, buf::Nonce};
    ///
    /// let key = Key::Aes256([1u8; 32]);
    /// let nonce: Nonce = [2u8; 12].into();
    ///
    /// let mut ciphertext = [0u8; 32];
    /// let plaintext = [3u8; 32];
    ///
    /// let mut gcm = AesGcm::new(&key).unwrap();
    /// let tag = gcm.try_encrypt(nonce.copy(), &plaintext, &mut ciphertext, ()).unwrap();
    ///
    /// let mut decrypted = [0u8; 32];
    /// let result = gcm.try_decrypt(nonce, &ciphertext, &mut decrypted, (), &tag);
    ///
    /// assert!(result.is_ok());
    /// assert_eq!(plaintext, decrypted);
    /// ```
    #[inline]
    pub fn try_decrypt<N: GenericIv, A: Aad>(
        &mut self, nonce: N, input: &[u8], output: &mut [u8], aad: A, tag: &Tag
    ) -> Res {
        if !Self::arg_predicate(input, output, &aad) { return Res::ERR }

        unsafe {
            // SAFETY:
            //
            // We've guarded against the output being smaller than the input, the nonce type ensures
            // the correct size is used.
            self.decrypt_unchecked(nonce.as_slice(), input, output, aad, tag)
        }
    }

    panic_api! {
    /// Decrypt data using AES-GCM, panicking on failure.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The nonce (IV) used for encryption.
    /// * `input` - The input data to decrypt.
    /// * `output` - The output buffer to store the decrypted data.
    /// * `aad` - Additional Authenticated Data.
    /// * `tag` - The authentication tag from encryption.
    ///
    /// # Panics
    ///
    /// - If the input buffer is larger than the output buffer.
    /// - If the input or AAD size is greater than what can be represented by a u32.
    /// - If the decryption operation fails (including authentication failure).
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{aead::AesGcm, aes::Key, buf::Nonce};
    ///
    /// let key = Key::Aes256([1u8; 32]);
    /// let nonce: Nonce = [2u8; 12].into();
    ///
    /// let mut ciphertext = [0u8; 32];
    /// let plaintext = [3u8; 32];
    ///
    /// let mut gcm = AesGcm::new(&key).unwrap();
    /// let tag = gcm.encrypt(nonce.copy(), &plaintext, &mut ciphertext, ());
    ///
    /// let mut decrypted = [0u8; 32];
    /// gcm.decrypt(nonce, &ciphertext, &mut decrypted, (), &tag);
    ///
    /// assert_eq!(plaintext, decrypted);
    /// ```
    #[inline]
    #[track_caller]
    pub fn decrypt<N: GenericIv, A: Aad>(
        &mut self, nonce: N, input: &[u8], output: &mut [u8], aad: A, tag: &Tag
    ) {
        if self.try_decrypt(nonce, input, output, aad, tag).is_err() {
            panic!("Decryption failed")
        }
    }
    }

    pub(crate) unsafe fn decrypt_unchecked<A: Aad>(
        &mut self, nonce: &[u8], input: &[u8], output: &mut [u8], aad: A, tag: &Tag
    ) -> Res {
        let mut res = Res::new();

        res.ensure_0(wc_AesGcmDecrypt(
            addr_of_mut!(self.inner),
            output.as_mut_ptr(),
            input.as_ptr(),
            input.len() as u32,
            nonce.as_ptr(),
            nonce.len() as u32,
            tag.as_ptr(),
            Tag::CAPACITY as u32,
            aad.ptr(),
            aad.size()
        ));

        res
    }
}

impl Drop for AesGcm {
    fn drop(&mut self) {
        unsafe {
            // SAFETY:
            //
            // We are in the drop implementation, so we are never going to be using the
            // `Aes` type again. Since we are configured to not malloc, this simply zeroes
            // the secrets that were copied on `wc_AesSetKey` invocation. I wish there
            // was a way to avoid the copying as I do not like secrets living in memory
            // more than once, but I understand the decision to do this for ensuring safety.
            wc_AesFree(addr_of_mut!(self.inner));
        }
    }
}

// SAFETY:
// All methods which mutate the underlying AES instance require a mutable reference,
// the only way to obtain a mutable reference across thread boundaries is via synchronization or
// unsafe in Rust (which then would be the user's responsibility).
unsafe impl Send for AesGcm {}

// SAFETY:
// There is no providing of interior mutability in the `AesGcm`, all methods which mutate the
// underlying AES instance require a mutable reference, thus making this safe to mark `Sync`.
unsafe impl Sync for AesGcm {}

#[cfg(test)]
mod gcm_test_utils {
    use alloc::vec;
    use alloc::vec::Vec;
    use super::*;
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, Aes128Gcm, AesGcm, KeyInit};
    use aes_gcm::aead::consts::{U12, U16};
    use aes_gcm::aes::Aes192;
    use crate::buf::Nonce;

    macro_rules! with_rust_crypto_gcm {
        ($key:expr, |$aead:ident| $do:expr) => {
            match $key {
                Key::Aes256(buf) => {
                    let $aead = Aes256Gcm::new_from_slice(buf.as_slice()).unwrap();
                    $do
                },
                Key::Aes128(buf) => {
                    let $aead = Aes128Gcm::new_from_slice(buf.as_slice()).unwrap();
                    $do
                },
                Key::Aes192(buf) => {
                    let $aead = AesGcm::<Aes192, U12, U16>::new_from_slice(
                        buf.as_slice()
                    ).unwrap();
                    $do
                }
            }
        }
    }

    fn encrypt_rust_crypto_impl(e: impl Aead, nonce: Nonce, plaintext: &[u8]) -> (Vec<u8>, Tag) {
        let mut res = e
            .encrypt(aes_gcm::Nonce::from_slice(nonce.as_slice()), plaintext)
            .unwrap();

        let tag = Tag::new(res.as_slice()[res.len() - 16..].try_into().unwrap());
        res.truncate(res.len() - 16);

        (res, tag)
    }

    pub fn encrypt_rust_crypto(key: &Key, nonce: Nonce, plaintext: &[u8]) -> (Vec<u8>, Tag) {
        with_rust_crypto_gcm!(
            key,
            |e| encrypt_rust_crypto_impl(e, nonce, plaintext)
        )
    }

    fn construct_cipher_payload(cipher: &[u8], tag: &Tag) -> Vec<u8> {
        let mut cipher_space = vec![0u8; cipher.len() + Tag::CAPACITY];
        cipher_space[..cipher.len()].copy_from_slice(cipher);
        cipher_space[cipher.len()..].copy_from_slice(tag.as_slice());
        cipher_space
    }

    fn decrypt_rust_crypto_impl(e: impl Aead, nonce: Nonce, cipher: &[u8], tag: &Tag) -> Vec<u8> {
        let cipher_space = construct_cipher_payload(cipher, tag);
        e.decrypt(aes_gcm::Nonce::from_slice(nonce.as_slice()), cipher_space.as_slice()).unwrap()
    }

    pub fn decrypt_rust_crypto(key: &Key, nonce: Nonce, cipher: &[u8], tag: &Tag) -> Vec<u8> {
        with_rust_crypto_gcm!(
            key,
            |e| decrypt_rust_crypto_impl(e, nonce, cipher, tag)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{Aes256Gcm, KeyInit};
    use aes_gcm::aead::{Aead};
    use aes_gcm::aead::consts::{U12, U16};
    use crate::aead::AadSlice;
    use crate::buf::{Iv, Nonce};

    fn encrypt_rust_crypto(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> (Vec<u8>, Tag) {
        let mut res = Aes256Gcm::new_from_slice(key).unwrap()
            .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
            .unwrap();

        let tag = Tag::new(res.as_slice()[res.len() - 16..].try_into().unwrap());
        res.truncate(res.len() - 16);

        (
            res,
            tag
        )
    }

    fn decrypt_rust_crypto(key: &[u8], nonce: &[u8], ciphertext: &[u8], tag: &Tag) -> Vec<u8> {
        let mut cipher_space = vec![0u8; ciphertext.len() + Tag::CAPACITY];
        cipher_space[..ciphertext.len()].copy_from_slice(ciphertext);
        cipher_space[ciphertext.len()..].copy_from_slice(tag.as_slice());

        Aes256Gcm::new_from_slice(key).unwrap()
            .decrypt(nonce.try_into().unwrap(), cipher_space.as_slice())
            .unwrap()
    }

    #[allow(dead_code)]
    #[derive(Debug, Clone)]
    enum COut<const S: usize> {
        GcmCrate {
            ciphertext: Vec<u8>,
            tag: Tag
        },
        Wolf {
            ciphertext: [u8; S],
            tag: Tag
        }
    }

    impl<const S: usize> COut<S> {
        fn slice(&self) -> &[u8] {
            match self {
                Self::Wolf { ciphertext, ..} => ciphertext.as_slice(),
                Self::GcmCrate { ciphertext, ..} => ciphertext.as_slice()
            }
        }
    }

    fn compare<const S: usize>(input: &[u8; S]) -> (COut<S>, COut<S>) {
        let mut out_buf = [0u8; S];
        let key = Key::Aes256([7; 32]);
        let nonce = Nonce::new([3; 12]);
        let aad = AadSlice::EMPTY;

        let tag = AesGcm::new(&key)
            .unwrap()
            .encrypt_sized(nonce, input, &mut out_buf, aad).unwrap();

        let (o_out, o_tag) = encrypt_rust_crypto(
            key.as_slice(), [3; 12].as_slice(), input.as_slice()
        );

        (COut::Wolf { ciphertext: out_buf, tag }, COut::GcmCrate { ciphertext: o_out, tag: o_tag })
    }

    fn find_dif_index(left: &[u8], right: &[u8]) -> Option<usize> {
        left.iter().zip(right.iter()).position(|(l, r)| l != r)
    }

    #[test]
    fn encrypt_smoke() {
        let input = b"hello world";
        let (wolf, cmp) = compare(input);
        assert!(find_dif_index(wolf.slice(), cmp.slice()).is_none());
    }

    #[test]
    fn encrypt_not_block_multiple() {
        let input = [7u8; 69];
        let (wolf, cmp) = compare(&input);
        assert!(find_dif_index(wolf.slice(), cmp.slice()).is_none());
    }

    #[test]
    fn self_bijective_smoke() {
        let plain = b"hello world";
        let mut out_buf = [0u8; 11];

        let key = Key::Aes256([7; 32]);
        let nonce = Nonce::new([3; 12]);
        let aad = AadSlice::EMPTY;

        let mut aes = AesGcm::new(&key).unwrap();

        let tag = aes
            .encrypt_sized(nonce.copy(), plain, &mut out_buf, aad)
            .unwrap();

        let mut de_out = [0u8; 11];

        assert!(aes.decrypt_sized(nonce.copy(), &out_buf, &mut de_out, aad, &tag).is_ok());
        assert_eq!(&de_out, plain);

        assert!(aes.decrypt_sized(nonce, &out_buf, &mut de_out, aad, &Tag::new_zeroed()).is_err());
    }

    #[test]
    fn aes_gcm_crate_bijective_smoke() {
        let plain = b"hello world";
        let mut out_buf = [0u8; 11];

        let key = Key::Aes256([7; 32]);
        let nonce = Nonce::new([3; 12]);
        let aad = AadSlice::EMPTY;

        let mut aes = AesGcm::new(&key).unwrap();

        let tag = aes
            .encrypt_sized(nonce.copy(), plain, &mut out_buf, aad)
            .unwrap();

        let de = decrypt_rust_crypto(
            key.as_slice(), nonce.as_slice(), out_buf.as_slice(), &tag
        );

        assert_eq!(de.as_slice(), plain.as_slice());

        let (cipher, tag) = encrypt_rust_crypto(
            key.as_slice(), nonce.as_slice(), plain.as_slice()
        );

        assert_eq!(cipher.as_slice(), out_buf.as_slice());

        let mut de_out = [0u8; 11];
        assert!(aes.try_decrypt(nonce, cipher.as_slice(), &mut de_out, aad, &tag).is_ok());

        assert_eq!(&de_out, plain);
    }

    #[test]
    fn nonce_16_byte_smoke() {
        let plain = b"hello world";
        let mut out_buf = [0u8; 11];

        let key = Key::Aes256([7; 32]);
        let nonce = Iv::new([3; 16]);
        let aad = AadSlice::EMPTY;

        let mut aes = AesGcm::new(&key).unwrap();

        let tag = aes
            .encrypt_sized(nonce.copy(), plain, &mut out_buf, aad)
            .unwrap();

        let mut de_out = [0u8; 11];

        assert!(aes.decrypt_sized(nonce.copy(), &out_buf, &mut de_out, aad, &tag).is_ok());
        assert_eq!(&de_out, plain);

        assert!(aes.decrypt_sized(nonce, &out_buf, &mut de_out, aad, &Tag::new_zeroed()).is_err());
    }

    #[test]
    fn always_equal() {
        let key = Key::Aes192([
            255, 185, 147, 176, 141, 224, 225, 32, 221, 209, 0, 108, 155, 152, 162, 134, 141, 167,
            81, 87, 13, 115, 13, 165
        ]);
        let nonce = Nonce::new([73, 54, 180, 151, 137, 229, 233, 133, 150, 169, 13, 99]);
        let aad = AadSlice::EMPTY;
        let mut aes = AesGcm::new(&key).unwrap();

        for i in 0..255u8 {
            let input = [i; 1];
            let mut output = [0u8; 1];

            let out = aes_gcm::AesGcm::<aes::Aes192, U12, U16>::new_from_slice(
                key.as_slice()
            )
                .unwrap()
                .encrypt(nonce.as_slice().try_into().unwrap(), input.as_slice())
                .unwrap();

            // encrypting 1 byte, ignore the tag, ciphertext is always equal to the plaintext.
            assert_eq!(input[0], out[0]);

            let tag = aes.encrypt(nonce.copy(), input.as_slice(), output.as_mut_slice(), aad);

            assert_eq!(input, output);

            let mut plain = [0u8; 1];
            aes.decrypt(nonce.copy(), output.as_slice(), plain.as_mut_slice(), aad, &tag);

            assert_eq!(plain, input);
        }
    }
}

#[cfg(all(test, not(miri)))]
mod property_tests {
    use proptest::prelude::*;
    use crate::aead::AadSlice;
    use super::*;
    use crate::aes::test_utils::*;
    use super::gcm_test_utils::{encrypt_rust_crypto, decrypt_rust_crypto};
    use crate::buf::Nonce;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10000))]

        #[test]
        fn self_bijectivity(
            input in any::<BoundList<1028>>(),
            key in any::<Key>(),
            nonce in any::<Nonce>()
        ) {
            let mut output = BoundList::<1028>::new_zeroes(input.len());

            let mut aes = AesGcm::new(&key).unwrap();
            let tag = aes.encrypt(nonce.copy(), input.as_slice(), output.as_mut_slice(), AadSlice::EMPTY);

            // 1 byte the probability of a specific key and nonce that retains equivalent plaintext
            // in ciphertext is too high. see the always_equal test for a nice example of this.
            if input.len() >= 2 {
                prop_assert_ne!(input, output);
            }

            let mut plain = BoundList::<1028>::new_zeroes(input.len());
            aes.decrypt(nonce.copy(), output.as_slice(), plain.as_mut_slice(), AadSlice::EMPTY, &tag);

            prop_assert_eq!(plain.as_slice(), input.as_slice());
        }
    }

    // Ensure bijective with rust-crypto
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10000))]

        #[test]
        fn rust_crypto_to_wolf(
            input in any::<BoundList<1028>>(),
            key in any::<Key>(),
            nonce in any::<Nonce>()
        ) {
            let (cipher, tag) = encrypt_rust_crypto(&key, nonce.copy(), input.as_slice());

            let mut plain = BoundList::<1028>::new_zeroes(input.len());
            AesGcm::new(&key).unwrap()
                .decrypt(nonce, cipher.as_slice(), plain.as_mut_slice(), AadSlice::EMPTY, &tag);

            prop_assert_eq!(plain, input);
        }

        #[test]
        fn wolf_to_rust_crypto(
            input in any::<BoundList<1028>>(),
            key in any::<Key>(),
            nonce in any::<Nonce>()
        ) {
            let mut output = BoundList::<1028>::new_zeroes(input.len());

            let mut aes = AesGcm::new(&key).unwrap();
            let tag = aes.encrypt(nonce.copy(), input.as_slice(), output.as_mut_slice(), AadSlice::EMPTY);

            // 1 byte the probability of a specific key and nonce that retains equivalent plaintext
            // in ciphertext is too high. see the always_equal test for a nice example of this.
            if input.len() >= 2 {
                prop_assert_ne!(input, output);
            }

            let plain = decrypt_rust_crypto(&key, nonce, output.as_slice(), &tag);
            prop_assert_eq!(plain.as_slice(), input.as_slice());
        }
    }
}

// I suppose these will be nice once kani has better support for c ffi, right now kani is not
// working. I'll be tracking the issues regarding c ffi support and see what I can do to get
// these working in the future. For now, property testing among unit tests are the direction
// forward.
// #[cfg(kani)]
// mod proofs {
//     use kani::proof;
//     use super::*;
//     use crate::aes::test_utils::*;
//
//     #[proof]
//     fn self_bijectivity() {
//         let input: BoundList<1028> = kani::any();
//         let mut output = BoundList::<1028>::new_zeroes(input.len());
//
//         let key: Key = kani::any();
//         let nonce: Nonce = kani::any();
//
//         let mut aes = AesGcm::new(&key).unwrap();
//         let tag = aes.encrypt(nonce.copy(), input.as_slice(), output.as_mut_slice(), Aad::EMPTY);
//
//         assert_ne!(input, output);
//
//         let mut plain = BoundList::<1028>::new_zeroes(input.len());
//         aes.decrypt(nonce.copy(), output.as_slice(), plain.as_mut_slice(), Aad::EMPTY, &tag);
//
//         assert_eq!(plain, input);
//     }
// }
