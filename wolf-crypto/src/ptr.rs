#![allow(dead_code)] // WIP

use core::ops;
use core::fmt;

#[repr(transparent)]
pub struct MutPtr<T> {
    inner: *mut T
}

impl<T> MutPtr<T> {
    #[cfg(debug_assertions)]
    #[inline]
    #[track_caller]
    pub fn new(inner: *mut T) -> Self {
        assert!(!inner.is_null(), "`MutPtr` initialized with null pointer");
        Self { inner }
    }

    #[cfg(not(debug_assertions))]
    #[inline]
    pub const fn new(inner: *mut T) -> Self {
        unsafe { core::mem::transmute(inner) }
    }

    #[cfg(debug_assertions)]
    #[inline]
    #[track_caller]
    pub fn assert_not_null(&self) {
        assert!(
            !self.inner.is_null(),
            "`MutPtr` was null under safe operation, this is not allowed"
        )
    }

    #[cfg(not(debug_assertions))]
    #[inline(always)]
    pub const fn assert_not_null(&self) {}

    #[inline]
    pub const unsafe fn null() -> Self {
        Self { inner: core::ptr::null_mut() }
    }

    #[inline]
    pub const unsafe fn get_unchecked(&self) -> *mut T {
        self.inner
    }

    #[cfg(debug_assertions)]
    #[inline]
    #[track_caller]
    pub fn get(&self) -> *mut T {
        self.assert_not_null();
        self.inner
    }

    #[cfg(not(debug_assertions))]
    #[inline]
    pub const fn get(&self) -> *mut T {
        self.inner
    }

    // Not unsafe as MutPtr copy is unsafe, we consume the type to prevent any further aliasing.
    #[inline]
    #[cfg_attr(debug_assertions, track_caller)]
    pub fn into_const(self) -> ConstPtr<T> {
        ConstPtr::new(self.inner.cast_const())
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    #[cfg_attr(debug_assertions, track_caller)]
    pub unsafe fn copy(&self) -> Self {
        Self::new(self.inner)
    }
}

impl<T> ops::Deref for MutPtr<T> {
    type Target = T;

    #[cfg_attr(debug_assertions, track_caller)]
    #[inline]
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.get() }
    }
}

impl<T> ops::DerefMut for MutPtr<T> {
    #[cfg_attr(debug_assertions, track_caller)]
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.get() }
    }
}

impl<T> fmt::Debug for MutPtr<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MutPtr {{ is_null: {} }}", self.inner.is_null())
    }
}

#[repr(transparent)]
pub struct ConstPtr<T> {
    inner: *const T
}

impl<T> ConstPtr<T> {
    #[cfg(debug_assertions)]
    #[inline]
    #[track_caller]
    pub fn new(inner: *const T) -> Self {
        assert!(!inner.is_null(), "`ConstPtr` initialized with null pointer");
        Self { inner }
    }

    #[cfg(not(debug_assertions))]
    #[inline]
    pub const fn new(inner: *const T) -> Self {
        unsafe { core::mem::transmute(inner) }
    }

    #[cfg(debug_assertions)]
    #[inline]
    #[track_caller]
    pub fn assert_not_null(&self) {
        assert!(
            !self.inner.is_null(),
            "`ConstPtr` was null under safe operation, this is not allowed"
        )
    }

    #[cfg(not(debug_assertions))]
    #[inline(always)]
    pub const fn assert_not_null(&self) {}

    #[inline]
    pub const unsafe fn null() -> Self {
        Self { inner: core::ptr::null() }
    }

    #[inline]
    pub const unsafe fn get_unchecked(&self) -> *const T {
        self.inner
    }

    #[cfg(debug_assertions)]
    #[inline]
    #[track_caller]
    pub fn get(&self) -> *const T {
        self.assert_not_null();
        self.inner
    }

    #[cfg(not(debug_assertions))]
    #[inline]
    pub const fn get(&self) -> *const T {
        self.inner
    }

    // unsafe as copy for ConstPtr is not unsafe, mutable aliasing invariant.
    #[inline]
    #[cfg_attr(debug_assertions, track_caller)]
    pub unsafe fn into_mut(self) -> MutPtr<T> {
        MutPtr::new(self.inner.cast_mut())
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    #[cfg_attr(debug_assertions, track_caller)]
    pub fn copy(&self) -> Self {
        Self::new(self.inner)
    }
}

impl<T> ops::Deref for ConstPtr<T> {
    type Target = T;

    #[cfg_attr(debug_assertions, track_caller)]
    #[inline]
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.get() }
    }
}

impl<T> fmt::Debug for ConstPtr<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ConstPtr {{ is_null: {} }}", self.inner.is_null())
    }
}
