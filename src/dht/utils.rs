use std::net::SocketAddr;

pub fn strip(raw: &[u8]) -> String {
    let mut string = String::with_capacity(raw.len() * 2);
    for &b in raw.iter() {
        if b == 0 {
            // substitute NUL with the control pictures block
            string.push('\u{2400}');
        } else if b.is_ascii() && !b.is_ascii_control() {
            string.push(b as char);
        } else {
            string.push(braillify(b));
        }
        // if b > 127 as char {
        //     b = '�';
        // }
        // // substitute control characters with the control pictures block
        // if b < ' ' {
        //     b = char::from_u32 ('\u{2400}' as u32 + b as u32).unwrap();
        // }
        // // DEL
        // if b == 127 as char {
        //     b = '\u{2421}';
        // }
        // string.push(b);
    }
    string
}

fn braillify(byte: u8) -> char {
    // braille cell:
    // base address: 0x2800
    // 1 4
    // 2 5
    // 3 6
    // 7 8
    //
    // we want:
    //
    // 8 4
    // 7 3
    // 6 2
    // 5 1
    //
    // in column order:
    // 1 2 3 7 4 5 6 8
    // 8 6 5 4 7 3 2 1 (rev)
    // 8 7 6 5 4 3 2 1 (shuffled)
    //
    let rev = byte.reverse_bits();
    let shuffled = (rev & 0b1000_0111) | (rev & 0b0111_0000) >> 1 | (rev & 0b0000_1000) << 3;

    char::from_u32(0x2800u32 + shuffled as u32).unwrap()
}