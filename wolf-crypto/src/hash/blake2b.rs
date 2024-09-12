use wolf_crypto_sys::{
    Blake2b as wc_Blake2b, wc_InitBlake2b, wc_Blake2bUpdate, wc_Blake2bFinal
};
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;
use crate::opaque_res::Res;
use crate::{const_lte, const_can_cast_u32, can_cast_u32, gte, const_gte};

#[repr(transparent)]
pub struct Blake2b<const C: usize> {
    inner: wc_Blake2b
}

impl<const C: usize> Blake2b<C> {
    pub fn new() -> Result<Self, ()> {
        if !const_lte::<C, 64>() { return Err(()); }
        let mut res = Res::new();

        unsafe {
            let mut inner = MaybeUninit::<wc_Blake2b>::uninit();
            res.ensure_0(wc_InitBlake2b(inner.as_mut_ptr(), C as u32));
            res.unit_err_with(|| Self { inner: inner.assume_init() })
        }
    }

    #[inline]
    pub unsafe fn update_unchecked(&mut self, data: &[u8]) -> Res {
        let mut res = Res::new();

        res.ensure_0(wc_Blake2bUpdate(
            addr_of_mut!(self.inner),
            data.as_ptr(),
            data.len() as u32
        ));

        res
    }

    #[inline]
    pub fn try_update(&mut self, data: &[u8]) -> Res {
        if !can_cast_u32(data.len()) { return Res::ERR }
        unsafe { self.update_unchecked(data) }
    }

    #[inline]
    pub fn update_sized<const OC: usize>(&mut self, data: &[u8; OC]) -> Res {
        if !const_can_cast_u32::<{ OC }>() { return Res::ERR }
        unsafe { self.update_unchecked(data) }
    }

    #[cfg(feature = "panic-api")]
    #[track_caller]
    pub fn update(&mut self, data: &[u8]) {
        self.try_update(data).unit_err(()).expect("Failed to update hash in `Blake2b`")
    }

    #[inline]
    pub unsafe fn finalize_unchecked(mut self, output: &mut [u8]) -> Res {
        let mut res = Res::new();

        res.ensure_0(wc_Blake2bFinal(
            addr_of_mut!(self.inner),
            output.as_mut_ptr(),
            C as u32
        ));

        res
    }

    #[inline]
    pub fn finalize_into(self, output: &mut [u8]) -> Res {
        if !gte::<C>(output.len()) { return Res::ERR }
        unsafe { self.finalize_unchecked(output) }
    }

    #[inline]
    pub fn finalize_into_sized<const OC: usize>(self, output: &mut [u8; OC]) -> Res {
        if !const_gte::<OC, C>() { return Res::ERR }
        unsafe { self.finalize_unchecked(output) }
    }

    #[inline]
    pub fn finalize_into_exact(self, output: &mut [u8; C]) -> Res {
        unsafe { self.finalize_unchecked(output) }
    }

    #[inline]
    pub fn try_finalize(self) -> Result<[u8; C], ()> {
        let mut buf = [0u8; C];
        self.finalize_into_exact(&mut buf).unit_err(buf)
    }

    #[cfg(feature = "panic-api")]
    #[track_caller]
    pub fn finalize(self) -> [u8; C] {
        self.try_finalize().expect("Failed to finalize in `Blake2b`")
    }
}