use crate::common::buf::Buf;
use crate::common::parse::{
    take_ignorable, parse_assign, ignore_header, parse_u32, parse_until_assign
};

#[repr(transparent)]
pub struct KnownTest<'t> {
    inner: &'t [u8]
}

/// NIST KATs for the **byte** oriented tests. This does not work for the bit oriented tests.
impl<'t> KnownTest<'t> {
    pub fn new(raw: &'t [u8]) -> Self {
        Self { inner: ignore_header(raw) }
    }

    // just for consistency with the KAT impl
    pub const fn start<const C: usize>(self) -> ActiveKnown<'t, C> {
        ActiveKnown::new(self.inner)
    }
}

#[repr(transparent)]
pub struct ActiveKnown<'t, const C: usize> {
    inner: &'t [u8]
}

impl<'t, const C: usize> ActiveKnown<'t, C> {
    const fn new(inner: &'t [u8]) -> Self {
        Self { inner }
    }

    fn parse_item(&self) -> Option<((u32, &'t [u8], &'t [u8]), &'t [u8])> {
        let rem = take_ignorable(self.inner);

        if rem.is_empty() {
            return None
        }

        let (len, rem) = parse_assign(b"Len")(rem)
            .expect("[PARSE] Expected a `Len` field.");
        let mut len = parse_u32(len)
            .expect("[PARSE] `Len` was not a valid UTF8 encoded number.");

        debug_assert_eq!(
            len & 7, 0,
            "`KnownTest` may only be used for the byte oriented tests."
        );

        // translate to byte repr
        len >>= 3;
        // calculate the hex encoded length (len zero is still 2 in len, << 1 alone wouldn't handle)
        let encoded_len = (len + (len == 0) as u32) << 1;
        let rem = take_ignorable(rem);

        let rem = parse_until_assign(b"Msg")(rem)
            .expect("[PARSE] Expected a `Msg` field.");

        let msg = rem.get(0..encoded_len as usize).unwrap_or_else(
            || panic!("[PARSE] Expected length of {} went out of bounds.", encoded_len)
        );

        let rem = take_ignorable(&rem[(encoded_len as usize)..]);

        let (md, rem) = parse_assign(b"MD")(rem)
            .expect("[PARSE] Missing the expected output (`MD` field)");

        Some(((len, msg, md), rem))
    }

    #[inline]
    pub fn next_item_sized<const DS: usize>(&mut self) -> Option<(Buf<C>, [u8; DS])> {
        self.parse_item().map(|((decoded_len, msg, md), rem)| {
            self.inner = rem;

            let de_msg = if decoded_len == 0 {
                Buf::zeroed()
            } else {
                let mut de = Buf::zeroed_with_len(decoded_len as usize);
                hex::decode_to_slice(msg, de.as_mut_slice())
                    .expect("[PARSE] Message (`Msg`) was not properly hex encoded.");
                de
            };

            let mut de_md = [0u8; DS];
            hex::decode_to_slice(md, de_md.as_mut_slice())
                .expect("[PARSE] Expected output (`MD`) was not properly hex encoded.");

            (de_msg, de_md)
        })
    }
}

pub fn is_long_kat(name: &str) -> bool {
    name.ends_with("LongMsg")
}

pub fn is_short_kat(name: &str) -> bool {
    name.ends_with("ShortMsg")
}