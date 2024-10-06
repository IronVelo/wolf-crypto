use core::ops;
use core::marker::PhantomData;
use proptest::arbitrary::{any, Arbitrary};
use proptest::{array, prop_oneof};
use proptest::collection::vec;
use proptest::num::u8::Any;
use proptest::strategy::{BoxedStrategy, Strategy};
use crate::aes::Key;

/// An arbitrary byte vector limited in size.
#[repr(transparent)]
#[derive(Debug, Clone)]
pub struct BoundVec<const C: usize> {
    inner: Vec<u8>,
    _phantom: PhantomData<[u8; C]>
}

impl<const C: usize> ops::Deref for BoundVec<C> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.inner.as_slice()
    }
}

impl<const C: usize> ops::DerefMut for BoundVec<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut_slice()
    }
}

impl<const C: usize> BoundVec<C> {
    /// **Note:** This does not check the size of the vec
    #[inline]
    const fn new_with_unchecked(vec: Vec<u8>) -> Self {
        Self { inner: vec, _phantom: PhantomData }
    }

    #[inline]
    pub fn new_zeroes() -> Self {
        Self::new_with_unchecked(vec![0u8; C])
    }

    #[track_caller]
    #[inline]
    pub fn new_with(vec: Vec<u8>) -> Self {
        assert!(vec.len() <= C);
        Self::new_with_unchecked(vec)
    }

    #[cfg_attr(debug_assertions, track_caller)]
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        // debug assertion as has nothing to do with invariant, just inefficient
        debug_assert!(capacity <= C, "New with capacity had capacity over bounded size");
        Self::new_with_unchecked(Vec::with_capacity(capacity))
    }

    #[inline]
    pub const fn new() -> Self {
        Self::new_with_unchecked(Vec::new())
    }
}

impl<const C: usize> PartialEq for BoundVec<C> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.inner.as_slice() == other.inner.as_slice()
    }
}

impl<const C: usize> Default for BoundVec<C> {
    fn default() -> Self {
        Self::with_capacity(C)
    }
}

#[cfg(kani)]
impl<const C: usize> kani::Arbitrary for BoundVec<C> {
    fn any() -> Self {
        let length: usize = kani::any();
        kani::assume(length <= C);
        Self::new_with((0..length).map(|_| kani::any::<u8>()).collect())
    }
}

impl<const C: usize> Arbitrary for BoundVec<C> {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        vec(any::<u8>(), 0..=C)
            .prop_map(BoundVec::new_with)
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

#[derive(Clone, Copy)]
pub struct BoundList<const C: usize> {
    inner: [u8; C],
    len: usize
}

use core::fmt;
use core::mem::MaybeUninit;

impl<const C: usize> fmt::Debug for BoundList<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut dbg = f.debug_struct("BoundList");
        dbg.field("len", &self.len());

        if C <= 32 {
            dbg.field("inner", &self.as_slice());
        }

        dbg.finish()
    }
}

impl<const C: usize> BoundList<C> {
    pub const fn new_with_unchecked(inner: [u8; C], len: usize) -> Self {
        Self {
            inner,
            len
        }
    }

    #[inline]
    pub const fn new_zeroes_unchecked(len: usize) -> Self {
        Self::new_with_unchecked([0u8; C], len)
    }

    #[inline]
    pub const fn new() -> Self {
        Self::new_zeroes_unchecked(0)
    }

    #[inline]
    #[track_caller]
    pub fn new_zeroes(len: usize) -> Self {
        assert!(len <= C, "New zeroes provided len greater than capacity");
        Self::new_zeroes_unchecked(len)
    }

    #[inline]
    pub const fn create_self(&self) -> Self {
        Self::new_zeroes_unchecked(self.len)
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[track_caller]
    #[inline]
    pub fn push(&mut self, byte: u8) {
        assert!(self.len + 1 <= C, "Attempted to push beyond capacity");

        self.inner[self.len] = byte;
        self.len += 1;
    }

    #[track_caller]
    #[inline]
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        assert!(self.len + slice.len() <= C, "Attempted to extend beyond capacity");

        self.inner[self.len..].copy_from_slice(slice);
        self.len += slice.len();
    }

    #[track_caller]
    #[inline]
    pub fn new_with(inner: [u8; C], len: usize) -> Self {
        assert!(len <= C, "Attempted to create `BoundList` with length greater than capacity");
        Self::new_with_unchecked(inner, len)
    }

    #[track_caller]
    #[inline]
    pub fn new_from_slice(slice: &[u8]) -> Self {
        assert!(slice.len() <= C, "Attempted to create `BoundList` from slice too large");
        let mut buf = [0u8; C];
        buf[..slice.len()].copy_from_slice(slice);

        Self::new_with_unchecked(buf, slice.len())
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.inner.as_slice()[..self.len()]
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let len = self.len();
        &mut self.inner.as_mut_slice()[..len]
    }
}

impl<const C: usize> PartialEq for BoundList<C> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const C: usize> ops::Deref for BoundList<C> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<const C: usize> ops::DerefMut for BoundList<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

#[cfg(kani)]
impl<const C: usize> kani::Arbitrary for BoundList<C> {
    fn any() -> Self {
        let len: usize = kani::any();
        kani::assume(len <= C);

        let buf: [u8; C] = kani::any();
        Self::new_with_unchecked(buf, len)
    }
}

impl<const C: usize> Arbitrary for BoundList<C> {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (0..=C, array::uniform::<Any, C>(any::<u8>()))
            .prop_map(|(len, buf)| {
                BoundList::new_with_unchecked(buf, len)
            })
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

#[derive(Copy, Clone)]
pub struct AnyList<const C: usize, T: Copy> {
    inner: [MaybeUninit<T>; C],
    len: usize
}

impl<const C: usize, T: fmt::Debug + Copy> fmt::Debug for AnyList<C, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut dbg = f.debug_struct("AnyList");
        dbg.field("len", &self.len());

        if C <= 32 {
            dbg.field("inner", &self.as_slice());
        }

        dbg.finish()
    }
}

impl<const C: usize, T: Copy> AnyList<C, T> {
    pub fn new_with_slice(slice: &[T]) -> Self {
        debug_assert!(slice.len() <= C);

        let mut inner = [const { MaybeUninit::<T>::uninit() }; C];
        inner[..slice.len()].copy_from_slice( unsafe { core::mem::transmute(slice) });

        Self {
            inner,
            len: slice.len()
        }
    }
}

impl<const C: usize, T: Copy> AnyList<C, T> {
    pub const fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn as_slice(&self) -> &[T] {
        unsafe { core::mem::transmute(&self.inner[..self.len]) }
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { core::mem::transmute(&mut self.inner[..self.len]) }
    }
}

impl<const C: usize, const B: usize> AnyList<C, BoundList<B>> {
    pub fn create_self(&self) -> Self {
        let mut copied = *self;

        for c in copied.as_mut_slice() {
            *c = c.create_self();
        }

        copied
    }

    pub fn join(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity((C * B) / 2);

        for e in self.as_slice() {
            out.extend_from_slice(e.as_slice());
        }

        out
    }
}

impl<const C: usize, T: PartialEq + Copy> PartialEq for AnyList<C, T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const C: usize, T: Copy> ops::Deref for AnyList<C, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<const C: usize, T: Copy> ops::DerefMut for AnyList<C, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl<const C: usize, T: Arbitrary + Copy + 'static> Arbitrary for AnyList<C, T>
    where <T as Arbitrary>::Strategy: 'static
{
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (0..=C, array::uniform::<<T as Arbitrary>::Strategy, C>(any::<T>()))
            .prop_map(|(len, buf)| {
                Self::new_with_slice(&buf.as_slice()[..len])
            })
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

#[cfg(kani)]
impl kani::Arbitrary for Key {
    fn any() -> Self {
        match kani::any::<u8>() % 3 {
            0 => Key::Aes256(kani::any()),
            1 => Key::Aes192(kani::any()),
            _ => Key::Aes128(kani::any()),
        }
    }
}

impl Arbitrary for Key {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<[u8; 32]>().prop_map(Key::Aes256),
            any::<[u8; 24]>().prop_map(Key::Aes192),
            any::<[u8; 16]>().prop_map(Key::Aes128)
        ].boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

#[cfg(kani)]
impl kani::Arbitrary for crate::buf::Nonce {
    fn any() -> Self {
        crate::buf::Nonce::new(kani::any())
    }
}
