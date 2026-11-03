use super::*;

#[test]
fn hex_image_base_matches_big_integer_long_value() {
    assert_eq!(parse_hex_i64("140000000").unwrap(), 0x1_4000_0000);
    assert_eq!(parse_hex_i64("-1000").unwrap(), -0x1000);
    assert_eq!(parse_hex_i64("ffffffffffffffff").unwrap(), -1);
    assert_eq!(parse_hex_i64("1ffffffffffffffff").unwrap(), -1);
    assert!(parse_hex_i64("zz").is_err());
}

#[test]
fn address_display_matches_the_oracle_format() {
    let a = Address::Space {
        space: "ram".into(),
        offset: 0x1_4000_1000,
    };
    assert_eq!(a.to_string(), "ram:140001000");
    assert_eq!(Address::NoAddress.to_string(), "NO_ADDRESS");
    assert_eq!(Address::ExtFrom.to_string(), "EXT_FROM");
}

#[test]
fn error_messages_name_the_problem() {
    let e = ProgError::UpgradeRequired {
        stored: 18,
        minimum: 19,
    };
    assert!(e.to_string().contains("upgraded by Ghidra"));
    let e = ProgError::NewerVersion {
        stored: 40,
        supported: 33,
    };
    assert!(e.to_string().contains("newer"));
}
