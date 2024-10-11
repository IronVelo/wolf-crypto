use crate::common::buf::Buf;
use crate::common::parse::{parse_assign, parse_u32, take_ignorable, take_length};

#[derive(Copy, Clone, Debug)]
pub enum Algo {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512
}

impl Algo {
    /// Create a new `Algo` from the digest length in bytes.
    pub const fn new(len: u32) -> Option<Self> {
        match len {
            20 => Some(Self::Sha1),
            28 => Some(Self::Sha224),
            32 => Some(Self::Sha256),
            48 => Some(Self::Sha384),
            64 => Some(Self::Sha512),
            _ => None
        }
    }
}

pub struct Case {
    pub algo: Algo,
    pub key: Buf<256>,
    pub msg: Buf<256>,
    pub tag: Buf<64>,
}

pub struct Harness<'t> {
    cur_algo: Algo,
    rem: &'t [u8],
    count: u32
}

#[derive(Copy, Clone, Debug)]
pub enum ErrKind {
    Term,
    Unexpected
}

pub type Error = (ErrKind, &'static str, u32);
pub type HResult<T> = Result<T, Error>;

impl<'t> Harness<'t> {
    pub fn new(raw: &'t [u8]) -> Self {
        let (Some(len), rem) = take_length(raw) else {
            panic!("Invalid test data for HMACVS. Missing length specifier at beginning of file.");
        };

        let Some(len) = parse_u32(len) else {
            panic!(
                "Corrupted length specifier {}, was unable to parse as a u32.",
                String::from_utf8_lossy(len)
            );
        };

        let Some(algo) = Algo::new(len) else {
            panic!(
                "Invalid length specifier {}, this does not correspond to any hashing algorithm \
                in this test's scope.",
                len
            );
        };

        Self {
            cur_algo: algo,
            rem,
            count: 0
        }
    }

    pub fn parse_algo(&self) -> (Option<Algo>, &'t [u8]) {
        let (len, rem) = match take_length(self.rem) {
            (Some(len), rem) => (len, rem),
            (None, rem) => return (None, rem)
        };

        // these are cases the test suite should simply crash.
        let Some(len) = parse_u32(len) else {
            panic!(
                "Corrupted length specifier {}, was unable to parse as a u32.",
                String::from_utf8_lossy(len)
            );
        };

        let Some(algo) = Algo::new(len) else {
            panic!(
                "Invalid length specifier {}, this does not correspond to any hashing algorithm \
                in this test's scope.",
                len
            );
        };

        (Some(algo), take_ignorable(rem))
    }

    pub fn parse_case(&self) -> HResult<(Case, u32, &'t [u8])> {
        macro_rules! ok_or {
            ($expr:expr, $msg:literal, $count:expr) => {
                match $expr {
                    Some(__res) => __res,
                    None => return Err((
                        ErrKind::Unexpected, concat!("Corrupted test data for HMACVS: ", $msg), $count
                    ))
                }
            };
            (term, $expr:expr, $msg:literal) => {
                match $expr {
                    Some(__res) => __res,
                    None => return Err((
                        ErrKind::Term, concat!("Failed to parse first item: ", $msg), self.count
                    ))
                }
            };
        }

        // take any ignorable chars / lines
        let (algo, rem) = self.parse_algo();

        // take the Count assignment, we ignore this.
        let (count, rem) = ok_or!(
            term, parse_assign(b"Count")(rem),
            "The `Count` assignment was missing for the current case"
        );

        let count = ok_or!(parse_u32(count), "`Count` was not a valid integer", self.count);

        // take the key length, we use this for the decoded key buffer.
        let (key_len, rem) = ok_or!(
            parse_assign(b"Klen")(take_ignorable(rem)),
            "The `Klen` field (expected after `Count`) was missing for the current case.", count
        );

        let key_len = ok_or!(parse_u32(key_len), "The `Klen` field was not a valid integer.", count);
        let mut key_buf = Buf::zeroed_with_len(key_len as usize);

        // take the tag length, used for the decoded tag buffer.
        let (tag_len, rem) = ok_or!(
            parse_assign(b"Tlen")(take_ignorable(rem)),
            "The `Tlen` field (expected after `Klen`) was missing for the current case.", count
        );

        let tag_len = ok_or!(parse_u32(tag_len), "The `Tlen` field was not a valid integer.", count);
        let mut tag_buf = Buf::zeroed_with_len(tag_len as usize);

        let (raw_key, rem) = ok_or!(
            parse_assign(b"Key")(take_ignorable(rem)),
            "The `Key` field (expected after `Tlen`) was missing for the current case.", count
        );

        let (raw_msg, rem) = ok_or!(
            parse_assign(b"Msg")(take_ignorable(rem)),
            "The `Msg` field (expected after `Key`) was missing for the current case.", count
        );

        let (raw_mac, rem) = ok_or!(
            parse_assign(b"Mac")(take_ignorable(rem)),
            "The `Mac` field (expected after `Msg`) was missing for the current state.", count
        );

        ok_or!(
            hex::decode_to_slice(raw_key, key_buf.as_mut_slice()).ok(),
            "Failed to decode into the key buffer, invalid hex.", count
        );

        ok_or!(
            hex::decode_to_slice(raw_mac, tag_buf.as_mut_slice()).ok(),
            "Failed to decode into the tag buffer, invalid hex.", count
        );

        let mut msg_buf = Buf::zeroed_with_len(raw_msg.len() >> 1);
        ok_or!(
            hex::decode_to_slice(raw_msg, msg_buf.as_mut_slice()).ok(),
            "Failed to decode into the msg buffer, invalid hex.", count
        );

        Ok((
            Case {
                algo: algo.unwrap_or(self.cur_algo),
                key: key_buf,
                msg: msg_buf,
                tag: tag_buf
            },
            count,
            rem
        ))
    }

    #[inline]
    pub fn next_case(&mut self) -> HResult<Case> {
        let (case, count, rem) = self.parse_case()?;

        self.cur_algo = case.algo;
        self.rem = rem;
        self.count = count;

        Ok(case)
    }

    pub fn assert_complete(&self) {
        assert_eq!(self.count, 374);
    }
}