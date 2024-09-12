//! Convenient Error Handling and Accumulation

use core::ffi::c_int;

#[must_use = "You must handle the potential error"]
#[repr(transparent)]
pub struct Res(bool);

impl Res {
    pub const OK: Res = Res(true);
    pub const ERR: Res = Res(false);

    pub const fn new() -> Self {
        Self::OK
    }

    #[inline]
    pub const fn is_ok(&self) -> bool {
        self.0
    }

    #[inline]
    pub const fn is_err(&self) -> bool {
        !self.0
    }

    #[inline]
    pub fn check(&mut self, res: bool) {
        self.0 &= res;
    }

    #[inline]
    pub fn ensure_1(&mut self, res: c_int) {
        self.0 &= (res as u8) == 1u8;
    }

    #[inline]
    pub fn ensure_0(&mut self, res: c_int) {
        self.0 &= (res as u8) == 0u8;
    }

    #[inline]
    pub fn ensure_pos(&mut self, res: c_int) {
        const R_SHR: c_int = (core::mem::size_of::<c_int>() * 8 - 1) as c_int;
        self.0 &= (!(res >> R_SHR) as u8) & 1 == 1;
    }

    #[inline]
    pub fn ensure(&mut self, res: Self) {
        self.0 &= res.0;
    }

    /// Not constant time
    #[inline(always)]
    pub fn unit_err<OK>(self, ok: OK) -> Result<OK, ()> {
        if self.is_ok() {
            Ok(ok)
        } else {
            Err(())
        }
    }

    /// Not constant time
    ///
    /// ### When to Use
    ///
    /// [`unit_err`] and `unit_err_with` are very similar in behavior but serve different purpose,
    /// for example, say the initiation of the `OK` result type depends on the previous result being
    /// OK for the safety of the program. In this case `unit_err_with` should be used to ensure that
    /// said unsafe function is only ever invoked if the preconditions to its existence are
    /// fulfilled.
    ///
    /// [`unit_err`]: Self::unit_err
    #[inline(always)]
    pub fn unit_err_with<F, OK>(self, ok: F) -> Result<OK, ()>
        where F: FnOnce() -> OK
    {
        if self.is_ok() {
            Ok(ok())
        } else {
            Err(())
        }
    }
}
