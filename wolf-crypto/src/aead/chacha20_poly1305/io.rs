use crate::aead::chacha20_poly1305::{ChaCha20Poly1305, states::UpdatingAad};
use crate::aead::Aad as _;
use crate::aead::chacha20_poly1305::states::Updating;
use crate::{can_cast_u32, Unspecified};

#[must_use]
pub struct Aad<S: UpdatingAad, IO> {
    aad: ChaCha20Poly1305<S>,
    io: IO
}

impl<S: UpdatingAad, IO> Aad<S, IO> {
    pub const fn new(aad: ChaCha20Poly1305<S>, io: IO) -> Self {
        Self { aad, io }
    }

    /// Signals that no more Additional Authenticated Data (AAD) will be provided, transitioning the
    /// cipher to the data processing state.
    ///
    /// This method finalizes the AAD input phase. After calling `finish`, you may [`finalize`] the
    /// state machine, or begin updating the cipher with data to be encrypted / decrypted.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::aead::chacha20_poly1305::{ChaCha20Poly1305, Key};
    /// use wolf_crypto::MakeOpaque;
    #[cfg_attr(all(feature = "embedded-io", not(feature = "std")), doc = "use embedded_io::Write;")]
    #[cfg_attr(feature = "std", doc = "use std::io::Write;")]
    ///
    #[cfg_attr(
        all(feature = "embedded-io", not(feature = "std")),
        doc = "# fn main() -> Result<(), wolf_crypto::Unspecified> {"
    )]
    #[cfg_attr(feature = "std", doc = "# fn main() -> Result<(), Box<dyn std::error::Error>> {")]
    /// let (key, iv) = (Key::new([7u8; 32]), [42; 12]);
    /// let mut some_io_write_implementor = [7u8; 64];
    ///
    /// let mut io = ChaCha20Poly1305::new_encrypt(key, iv)
    ///     .aad_io(some_io_write_implementor.as_mut_slice());
    ///
    /// let read = io.write(b"hello world")?;
    /// // _my_writer in this case is the remaining unwritten bytes...
    /// let (aead, _my_writer) = io.finish();
    ///
    /// assert_eq!(&some_io_write_implementor[..read], b"hello world");
    ///
    /// let tag = aead.finalize()?;
    /// # assert_ne!(tag, wolf_crypto::aead::Tag::new_zeroed()); // no warnings
    /// # Ok(()) }
    /// ```
    ///
    /// [`finalize`]: ChaCha20Poly1305::finalize
    #[inline]
    pub fn finish(self) -> (ChaCha20Poly1305<S::Mode>, IO) {
        (self.aad.finish(), self.io)
    }
}

std! {
    use std::io as std_io;

    impl<S, IO> std_io::Write for Aad<S, IO>
        where
            S: UpdatingAad,
            IO: std_io::Write
    {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> std_io::Result<usize> {
            if !buf.is_valid_size() { return Err(std_io::Error::other(Unspecified)) }
            self.io.write(buf).map(
                // SAFETY: We ensured the AAD meets the required preconditions with checking
                // is_valid_size.
                |amount| unsafe { self.aad.update_aad_unchecked(&buf[..amount]); amount }
            )
        }

        #[inline]
        fn write_all(&mut self, buf: &[u8]) -> std_io::Result<()> {
            if !buf.is_valid_size() { return Err(std_io::Error::other(Unspecified)) }
            // SAFETY: We ensured the AAD meets the required preconditions with checking
            // is_valid_size.
            self.io.write_all(buf).map(|()| unsafe { self.aad.update_aad_unchecked(buf) })
        }

        #[inline]
        fn flush(&mut self) -> std_io::Result<()> {
            self.io.flush()
        }
    }

    impl<S, IO> std_io::Read for Aad<S, IO>
        where
            S: UpdatingAad,
            IO: std_io::Read
    {
        #[inline]
        fn read(&mut self, buf: &mut [u8]) -> std_io::Result<usize> {
            // we must ensure we are infallible prior to writing to the buffer
            if !buf.is_valid_size() { return Err(std_io::Error::other(Unspecified)) }
            match self.io.read(buf) {
                Ok(read) => {
                    // SAFETY: We ensured the AAD meets the required preconditions with checking
                    // is_valid_size.
                    unsafe { self.aad.update_aad_unchecked(&buf[..read]); }
                    Ok(read)
                },
                res @ Err(_) => res
            }
        }

        #[inline]
        fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std_io::Result<usize> {
            // we must ensure we are infallible prior to writing to the buffer
            if !buf.is_valid_size() { return Err(std_io::Error::other(Unspecified)) }

            let init_len = buf.len();
            match self.io.read_to_end(buf) {
                Ok(read) => {
                    unsafe {
                        // SAFETY: We ensured the AAD meets the required preconditions with checking
                        // is_valid_size.
                        self.aad.update_aad_unchecked(&buf.as_mut_slice()[init_len..init_len + read])
                    };
                    Ok(read)
                },
                res @ Err(_) => res
            }
        }
    }
}

no_std_io! {
    use embedded_io::{self as eio, ErrorType};

    impl<S: UpdatingAad, IO> ErrorType for Aad<S, IO> {
        type Error = Unspecified;
    }

    impl<S, IO> eio::Write for Aad<S, IO>
        where
            S: UpdatingAad,
            IO: eio::Write
    {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            if !buf.is_valid_size() { return Err(Unspecified) }
            match self.io.write(buf) {
                Ok(amount) => {
                    // SAFETY: We ensured the AAD meets the required preconditions with checking
                    // is_valid_size.
                    unsafe { self.aad.update_aad_unchecked(&buf[..amount]); }
                    Ok(amount)
                },
                Err(_) => Err(Unspecified)
            }
        }

        #[inline]
        fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
            if !buf.is_valid_size() { return Err(Unspecified) }
            match self.io.write_all(buf) {
                Ok(()) => {
                    // SAFETY: We ensured the AAD meets the required preconditions with checking
                    // is_valid_size.
                    unsafe { self.aad.update_aad_unchecked(buf); }
                    Ok(())
                },
                Err(_) => Err(Unspecified)
            }
        }

        #[inline]
        fn flush(&mut self) -> Result<(), Self::Error> {
            self.io.flush().map_err(|_| Unspecified)
        }
    }

    impl<S, IO> eio::Read for Aad<S, IO>
        where
            S: UpdatingAad,
            IO: eio::Read
    {
        #[inline]
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            // we must ensure we are infallible prior to writing to the buffer
            if !buf.is_valid_size() { return Err(Unspecified) }
            match self.io.read(buf) {
                Ok(read) => {
                    // SAFETY: We ensured the AAD meets the required preconditions with checking
                    // is_valid_size.
                    unsafe { self.aad.update_aad_unchecked(&buf[..read]); }
                    Ok(read)
                },
                Err(_) => Err(Unspecified)
            }
        }
    }
}

#[must_use]
pub struct Data<S: Updating, IO> {
    aead: ChaCha20Poly1305<S>,
    io: IO
}

impl<S: Updating, IO> Data<S, IO> {
    pub const fn new(aead: ChaCha20Poly1305<S>, io: IO) -> Self {
        Self { aead, io }
    }

    #[inline]
    pub fn finish(self) -> (ChaCha20Poly1305<S>, IO) {
        (self.aead, self.io)
    }
}

std! {
    impl<S, IO> std_io::Read for Data<S, IO>
        where
            S: Updating,
            IO: std_io::Read
    {
        #[inline]
        fn read(&mut self, buf: &mut [u8]) -> std_io::Result<usize> {
            // We will do our safety checks in advance, we read from the io type we're wrapping,
            // and then we fail encrypt, potentially leaking sensitive data. So, doing these
            // checks in advance is necessary.
            if !can_cast_u32(buf.len()) { return Err(std_io::Error::other(Unspecified)) }

            self.io.read(buf).map(|amount| unsafe {
                self.aead.update_in_place_unchecked(&mut buf[..amount]);
                amount
            })
        }
    }
}

no_std_io! {
    impl<S: Updating, IO: ErrorType> ErrorType for Data<S, IO> {
        type Error = Unspecified;
    }

    impl<S, IO> eio::Read for Data<S, IO>
        where
            S: Updating,
            IO: eio::Read
    {
        #[inline]
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            if !can_cast_u32(buf.len()) { return Err(Unspecified) }

            match self.io.read(buf) {
                Ok(amount) => {
                    unsafe { self.aead.update_in_place_unchecked(&mut buf[..amount]) };
                    Ok(amount)
                },
                Err(_) => Err(Unspecified)
            }
        }
    }
}