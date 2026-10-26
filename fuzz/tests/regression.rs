use phantom_secrets_fuzz::{body_injection, placeholder_parsing, PLACEHOLDER};

#[test]
fn parser_prefix_boundaries_and_binary() {
    for data in [
        b"".as_slice(),
        b"phm",
        b"PHM_",
        b" phm_",
        b"phm_",
        b"phm_\0\xff",
        "phm_🦀é\r\n".as_bytes(),
        PLACEHOLDER.as_bytes(),
    ] {
        placeholder_parsing(data);
    }
    for end in 0..=PLACEHOLDER.len() {
        placeholder_parsing(&PLACEHOLDER.as_bytes()[..end]);
    }
    placeholder_parsing(&vec![0xff; 16_384]);
}

#[test]
fn client_body_boundaries_all_modes_and_mime_types() {
    // Each constructor, MIME branch, route selector and chunk width.
    for mode in 0..3 {
        for mime in 0..7 {
            for route in 0..3 {
                for width in 0..=68 {
                    let mut data = vec![mode, mime, route, width, 0, 0];
                    data.extend_from_slice(PLACEHOLDER.as_bytes());
                    data.extend_from_slice(b"\xff\0\r\n{secret}");
                    body_injection(&data);
                }
            }
        }
    }
}

#[test]
fn streaming_carry_at_every_mapping_byte() {
    for mode in 0..3 {
        for split in 0..=160u16 {
            let mut data = vec![mode, 1, 0, 1];
            data.extend_from_slice(&split.to_le_bytes());
            data.extend_from_slice(PLACEHOLDER.as_bytes());
            body_injection(&data);
        }
    }
}

#[test]
fn empty_binary_and_large_bodies() {
    for data in [b"".as_slice(), b"\xff\0\xfe", b"{\"nested\":[\"phm_\"]}"] {
        let mut input = vec![0; 6];
        input.extend_from_slice(data);
        body_injection(&input);
    }
    body_injection(&vec![0xff; 16_384]);
}
