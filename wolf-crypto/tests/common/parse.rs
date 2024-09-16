
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

pub fn take(ident: &[u8]) -> impl FnOnce(&[u8]) -> Option<&[u8]> + '_ {
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
pub fn take_until(until: u8) -> impl FnOnce(&[u8]) -> (&[u8], &[u8]) {
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

pub fn read_ident(ident: &[u8]) -> impl FnOnce(&[u8]) -> Option<(&[u8], &[u8])> + '_ {
    let take_fn = take(ident);

    move |data: &[u8]| {
        let rem = take_fn(data)?;

        // ignore any whitespace or whatever until eq sign
        let rem = take_ignorable(rem);
        let rem = take(b"=")(rem)?;
        let rem = take_ignorable(rem);

        // general format of all of these files is newline sep
        Some(take_until_break(rem))
    }
}
