use alloy::primitives::Address;
use alloy_rlp::{Encodable, RlpEncodableWrapper};

use crate::encode;

pub struct Log {
    pub address: Address,
    pub topics: Vec<H256>,
    pub data: Vec<u8>,
}

impl Log {
    fn rlp_header(&self) -> alloy_rlp::Header {
        let payload_length =
            self.address.length() + self.topics.length() + self.data.as_slice().length();
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
    }
}

impl Encodable for Log {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let header = self.rlp_header();
        encode!(out, header, self.address, self.topics, self.data.as_slice());
    }
    fn length(&self) -> usize {
        let rlp_head = self.rlp_header();
        alloy_rlp::length_of_length(rlp_head.payload_length) + rlp_head.payload_length
    }
}

#[derive(Debug, RlpEncodableWrapper, PartialEq, Clone)]
pub struct H256(pub [u8; 32]);

impl H256 {
    pub fn zero() -> Self {
        Self([0u8; 32])
    }
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..slice.len()].copy_from_slice(slice);
        Self(bytes)
    }
}
