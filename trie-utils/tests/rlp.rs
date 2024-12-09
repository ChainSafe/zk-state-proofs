#[cfg(test)]
mod tests {
    use alloy::{
        hex::{self, FromHex},
        primitives::{Address, Bloom},
    };
    use alloy_rlp::Encodable;
    use trie_utils::types::{Log, H256};

    #[test]
    fn test_encode_receipt() {
        let expected = hex::decode("f901668001b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f85ff85d940000000000000000000000000000000000000011f842a0000000000000000000000000000000000000000000000000000000000000deada0000000000000000000000000000000000000000000000000000000000000beef830100ff").unwrap();
        let status = false;
        let cumulative_gas = 0x1u64;
        let bloom = Bloom::new([0; 256]);
        let logs: Vec<Log> = vec![Log {
            address: Address::from_hex("0000000000000000000000000000000000000011").unwrap(),
            topics: vec![
                H256::from_slice(
                    &hex::decode(
                        "000000000000000000000000000000000000000000000000000000000000dead",
                    )
                    .unwrap(),
                ),
                H256::from_slice(
                    &hex::decode(
                        "000000000000000000000000000000000000000000000000000000000000beef",
                    )
                    .unwrap(),
                ),
            ],
            data: hex::decode("0100ff").unwrap().to_vec(),
        }];

        let list_encode: [&dyn Encodable; 4] = [&status, &cumulative_gas, &bloom, &logs];
        let mut out: Vec<u8> = Vec::new();
        alloy_rlp::encode_list::<_, dyn Encodable>(&list_encode, &mut out);

        let mut o: Vec<u8> = Vec::new();
        logs.encode(&mut o);
        assert_eq!(out, expected);
    }
}
