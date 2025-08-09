mod internal {
    // Re-declare the function signature to test via a minimal copy for unit-test scope.
    fn guid_bytes_to_string(g: &[u8]) -> String {
        use byteorder::{ByteOrder, LittleEndian};
        if g.len() < 16 {
            return String::new();
        }
        let d1 = LittleEndian::read_u32(&g[0..4]);
        let d2 = LittleEndian::read_u16(&g[4..6]);
        let d3 = LittleEndian::read_u16(&g[6..8]);
        let d4 = &g[8..10];
        let d5 = &g[10..16];
        format!(
            "{d1:08x}-{d2:04x}-{d3:04x}-{}-{}",
            hex::encode(d4),
            hex::encode(d5)
        )
    }

    #[test]
    fn guid_conversion_known_value() {
        // 00112233-4455-6677-8899-aabbccddeeff
        let bytes: [u8; 16] = [
            0x33, 0x22, 0x11, 0x00,
            0x55, 0x44,
            0x77, 0x66,
            0x88, 0x99,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let s = guid_bytes_to_string(&bytes);
        assert_eq!(s, "00112233-4455-6677-8899-aabbccddeeff");
    }
}
