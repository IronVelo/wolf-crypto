//! Convenient Error Handling and Accumulation
//!
//! This module provides a simple, opaque error type (`Res`) designed to prevent
//! side-channel attacks through timing or error messages. It allows for
//! accumulation of error states without revealing specific error details.
use core::ffi::c_int;
use crate::error::Unspecified;

/// An opaque result type for error handling without exposing error details.
///
/// This type is designed to prevent side-channel attacks by not revealing
/// specific error information. It only indicates success or failure.
#[must_use = "You must handle the potential error"]
#[repr(transparent)]
pub struct Res(bool);

impl Default for Res {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Res {
    /// Represents a successful result.
    pub const OK: Self = Self(true);
    /// Represents an error result.
    pub const ERR: Self = Self(false);

    /// Creates a new `Res` instance initialized to `OK`.
    ///
    /// # Returns
    ///
    /// A new `Res` instance representing success.
    pub const fn new() -> Self {
        Self::OK
    }

    /// Checks if the result is OK (successful).
    ///
    /// # Returns
    ///
    /// `true` if the result is OK, `false` otherwise.
    #[inline]
    pub const fn is_ok(&self) -> bool {
        self.0
    }


    /// Checks if the result is an error.
    ///
    /// # Returns
    ///
    /// `true` if the result is an error, `false` otherwise.
    #[inline]
    pub const fn is_err(&self) -> bool {
        !self.0
    }

    /// Updates the result based on a boolean condition.
    ///
    /// If `res` is `false`, this method will set the `Res` to an error state.
    ///
    /// # Arguments
    ///
    /// * `res` - A boolean representing a condition to check.
    #[inline]
    pub fn check(&mut self, res: bool) {
        self.0 &= res;
    }


    /// Ensures that a C integer result is equal to 1.
    ///
    /// Sets the `Res` to an error state if the input is not 1.
    ///
    /// # Arguments
    ///
    /// * `res` - A C integer to check.
    #[inline]
    pub fn ensure_1(&mut self, res: c_int) {
        self.0 &= (res as u8) == 1u8;
    }

    /// Ensures that a C integer result is equal to 0.
    ///
    /// Sets the `Res` to an error state if the input is not 0.
    ///
    /// # Arguments
    ///
    /// * `res` - A C integer to check.
    #[inline]
    pub fn ensure_0(&mut self, res: c_int) {
        self.0 &= (res as u8) == 0u8;
    }

    /// Ensures that a C integer result is positive.
    ///
    /// Sets the `Res` to an error state if the input is not positive.
    ///
    /// # Arguments
    ///
    /// * `res` - A C integer to check.
    #[inline]
    pub fn ensure_pos(&mut self, res: c_int) {
        const R_SHR: c_int = (core::mem::size_of::<c_int>() * 8 - 1) as c_int;
        self.0 &= (!(res >> R_SHR) as u8) & 1 == 1;
    }

    /// Combines this `Res` with another `Res`.
    ///
    /// The result will be OK only if both `Res` instances are OK.
    ///
    /// # Arguments
    ///
    /// * `res` - Another `Res` instance to combine with this one.
    #[inline]
    pub fn ensure(&mut self, res: Self) {
        self.0 &= res.0;
    }

    /// Converts the `Res` into a `Result<OK, Unspecified>`.
    ///
    /// # Warning
    ///
    /// This method is not constant time and should be used carefully in
    /// security-sensitive contexts.
    ///
    /// # Arguments
    ///
    /// * `ok` - The value to return in the `Ok` variant if the `Res` is OK.
    ///
    /// # Returns
    ///
    /// `Ok(ok)` if the `Res` is OK, `Err(Unspecified)` otherwise.
    #[allow(clippy::missing_errors_doc)]
    #[inline(always)]
    pub fn unit_err<OK>(self, ok: OK) -> Result<OK, Unspecified> {
        if self.is_ok() {
            Ok(ok)
        } else {
            Err(Unspecified)
        }
    }

    /// Converts the `Res` into a `Result<OK, Unspecified>`, with a closure for the OK case.
    ///
    /// # Warning
    ///
    /// This method is not constant time and should be used carefully in
    /// security-sensitive contexts.
    ///
    /// # When to Use
    ///
    /// Use this method when the creation of the `OK` value depends on the result
    /// being OK for safety reasons. The closure is only called if the `Res` is OK,
    /// ensuring that any preconditions for the OK value's creation are met.
    ///
    /// # Arguments
    ///
    /// * `ok` - A closure that returns the value for the `Ok` variant if the `Res` is OK.
    ///
    /// # Returns
    ///
    /// `Ok(ok())` if the `Res` is OK, `Err(Unspecified)` otherwise.
    #[inline(always)]
    #[allow(clippy::missing_errors_doc)]
    pub fn unit_err_with<F, OK>(self, ok: F) -> Result<OK, Unspecified>
        where F: FnOnce() -> OK
    {
        if self.is_ok() {
            Ok(ok())
        } else {
            Err(Unspecified)
        }
    }

    /// Unwraps the `Res`, panicking if it's an error.
    ///
    /// # Panics
    ///
    /// Panics if the `Res` is an error.
    ///
    /// # Warning
    ///
    /// This method should generally be avoided in production code, as it can lead
    /// to program termination. It's primarily useful for testing or in situations
    /// where an error truly represents an unrecoverable state.
    #[inline]
    #[track_caller]
    pub fn unwrap(self) {
        self.unit_err(()).unwrap();
    }
}
