
pub fn take_comment(raw: &[u8]) -> usize {
    if !matches!(raw.get(0), Some(b'#')) { return 0 }

    let mut pos: usize = 1;

    loop {
        match raw.get(pos) {
            Some(b'\n') | None => break,
            Some(_) => pos += 1,
        }
    }

    pos
}

pub fn take_ignorable(raw: &[u8]) -> &[u8] {
    let mut pos: usize = 0;

    loop {
        match raw.get(pos) {
            Some(b'#') => pos += take_comment(&raw[pos..]),
            Some(b' ' | b'\r' | b'\n') => pos += 1,
            _ => return &raw[pos..]
        }
    }
}

pub const fn take(ident: &[u8]) -> impl FnOnce(&[u8]) -> Option<&[u8]> + '_ {
    move |data: &[u8]| {
        if data.len() >= ident.len() && &data[..ident.len()] == ident {
            Some(&data[ident.len()..])
        } else {
            None
        }
    }
}

macro_rules! take_until {
    ($pat:pat, $data:expr) => {{
        let mut __pos: usize = 0;

        loop {
            match $data.get(__pos) {
                Some($pat) => break,
                Some(_) => __pos += 1,
                // eof
                None => break
            }
        }

        (&$data[..__pos], &$data[__pos + 1..])
    }}
}

#[inline]
pub const fn take_until(until: u8) -> impl FnOnce(&[u8]) -> (&[u8], &[u8]) {
    move |data: &[u8]| {
        let mut pos: usize = 0;

        loop {
            match data.get(pos) {
                Some(byte) if byte == &until => { break },
                Some(_) => pos += 1,
                // eof
                None => break
            }
        }

        (&data[..pos], &data[pos + 1..])
    }
}

#[inline]
pub fn take_until_break(raw: &[u8]) -> (&[u8], &[u8]) {
    take_until!(b'\n' | b'\r', raw)
}

#[inline]
pub const fn parse_until_assign(ident: &[u8]) -> impl FnOnce(&[u8]) -> Option<&[u8]> + '_ {
    let take_fn = take(ident);

    move |data: &[u8]| {
        take_fn(data)
            .map(take_ignorable)
            .and_then(take(b"="))
            .map(take_ignorable)
    }
}

#[inline]
pub const fn parse_assign(ident: &[u8]) -> impl FnOnce(&[u8]) -> Option<(&[u8], &[u8])> + '_ {
    let take_until_ass = parse_until_assign(ident);
    move |data: &[u8]| { take_until_ass(data).map(take_until_break) }
}

#[inline]
pub fn ignore_header(raw: &[u8]) -> &[u8] {
    let mut rem = take_ignorable(raw);

    // then we get this [L = some size], if we don't, just continue anyway

    if let Some(r) = take(b"[")(rem) {
        rem = take_until(b']')(r).1; // ignore interior, denoted via file name
        // take any remainder to ensure we have same perspective as if branch not taken.
        rem = take_ignorable(rem);
    }

    rem
}

#[inline]
const fn ascii_to_digit(byte: u8) -> Option<u32> {
    match byte {
        b'0' => Some(0),
        b'1' => Some(1),
        b'2' => Some(2),
        b'3' => Some(3),
        b'4' => Some(4),
        b'5' => Some(5),
        b'6' => Some(6),
        b'7' => Some(7),
        b'8' => Some(8),
        b'9' => Some(9),
        _ => None
    }
}

pub fn parse_u32(raw: &[u8]) -> Option<u32> {
    if raw.is_empty() { return None }

    let mut i = 0;
    let mut num = 0;

    while i < raw.len() {
        if let Some(digit) = ascii_to_digit(raw[i]) {
            num *= 10;
            num += digit;
            i += 1;
        } else {
            // we expect to be fed only valid numbers
            return None
        }
    }

    Some(num)
}