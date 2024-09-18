use core::ops;

pub struct Buf<const C: usize> {
    buf: [u8; C],
    len: usize
}

impl<const C: usize> Buf<C> {
    const fn from_parts(buf: [u8; C], len: usize) -> Self {
        Self { buf, len }
    }
    pub const fn zeroed() -> Self {
        Self::zeroed_with_len(0)
    }
    pub const fn zeroed_with_len(len: usize) -> Self {
        Self::from_parts([0u8; C], len)
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        let mut this = Self::zeroed();
        this.extend_from_slice(slice);
        this
    }

    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        assert!(self.len + slice.len() <= C);
        self.buf[self.len..slice.len()].copy_from_slice(slice);
        self.len += slice.len();
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf[..self.len]
    }
}

impl<const C: usize> ops::Deref for Buf<C> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<const C: usize> ops::DerefMut for Buf<C> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl<const C: usize> PartialEq<[u8]> for Buf<C> {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.as_slice() == other
    }
}

impl<const C: usize> PartialEq for Buf<C> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}