use crate::common::parse::{take, take_ignorable, read_ident, take_until};

#[repr(transparent)]
pub struct MonteTest<'t> {
    inner: &'t [u8]
}

impl<'t> MonteTest<'t> {
    pub fn new(raw: &'t [u8]) -> Self {
        // always comments at start
        let mut rem = take_ignorable(raw);

        // then we get this [L = some size], if we don't, just continue anyway

        if let Some(r) = take(b"[")(rem) {
            rem = take_until(b']')(r).1; // ignore interior, denoted via file name
            // take any remainder to ensure we have same perspective as if branch not taken.
            rem = take_ignorable(rem);
        }

        Self { inner: rem }
    }

    /// Returns seed (first elem), and the actual test
    pub fn start(self) -> (&'t [u8], ActiveMonte<'t>) {
        let (seed, rem) = read_ident(b"Seed")(self.inner)
            .expect("Failed to find Seed for Monte Test");
        let rem = take_ignorable(rem);

        (seed, ActiveMonte::new(rem))
    }
}

#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct ActiveMonte<'t> {
    inner: &'t [u8]
}

impl<'t> ActiveMonte<'t> {
    const fn new(inner: &'t [u8]) -> Self {
        Self { inner }
    }

    #[inline]
    pub const fn sized<const C: usize>(&self) -> SizedActiveMonte<'t, C> {
        SizedActiveMonte { inner: *self }
    }

    fn parse_item(&self) -> Option<((&'t [u8], &'t [u8]), &'t [u8])> {
        let rem = take_ignorable(self.inner);

        if rem.is_empty() {
            return None;
        }

        let (count, rem) = read_ident(b"COUNT")(rem)
            .expect("Expected a COUNT field");
        let rem = take_ignorable(rem);
        let (md, rem) = read_ident(b"MD")(rem)
            .expect("Missing the expected output");

        Some(((count, md), rem))
    }

    #[inline]
    pub fn next_item(&mut self) -> Option<(&'t [u8], Vec<u8>)> {
        let ((count, md), rem) = self.parse_item()?;
        self.inner = rem;
        Some((count, hex::decode(md).unwrap()))
    }

    #[inline]
    pub fn next_item_sized<const C: usize>(&mut self) -> Option<(&'t [u8], [u8; C])> {
        let ((count, md), rem) = self.parse_item()?;
        self.inner = rem;

        let mut out = [0u8; C];
        hex::decode_to_slice(md, out.as_mut_slice()).unwrap();

        Some((count, out))
    }
}

impl<'t> Iterator for ActiveMonte<'t> {
    type Item = (&'t [u8], Vec<u8>);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.next_item()
    }
}

#[repr(transparent)]
pub struct SizedActiveMonte<'t, const C: usize> {
    inner: ActiveMonte<'t>
}

impl<'t, const C: usize> Iterator for SizedActiveMonte<'t, C> {
    type Item = (&'t [u8], [u8; C]);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next_item_sized::<C>()
    }
}

#[inline]
pub fn is_monte(name: &str) -> bool {
    name.ends_with("Monte")
}
