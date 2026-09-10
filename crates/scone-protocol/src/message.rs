//! P2P message envelope.
//!
//! Message framing only: `Message = disc u8 || payload`. The transport
//! (length-prefixed framing, libp2p, etc.) is out of scope; a transport
//! frame should not exceed [`limits::MAX_MESSAGE_LEN`]. Deferred on
//! purpose: `GetTransaction`/`TxId` (depend on blockchain-layer
//! decisions).

use scone_core::{DomainId, SignedDnsRecord, Transaction};

use crate::PROTOCOL_VERSION;
use crate::block::{Block, BlockHash};
use crate::codec::{self, Decode, Encode};
use crate::error::{ProtocolError, Result};
use crate::limits;
use crate::varint;

/// Message wire discriminants.
pub mod msg_type {
    /// Handshake: announces the sender's protocol version.
    pub const HELLO: u8 = 0x01;
    /// Liveness probe.
    pub const PING: u8 = 0x02;
    /// Liveness response.
    pub const PONG: u8 = 0x03;
    /// Requests one block by hash.
    pub const GET_BLOCK: u8 = 0x04;
    /// Requests a range of blocks by height.
    pub const GET_BLOCKS: u8 = 0x05;
    /// Carries a block.
    pub const BLOCK: u8 = 0x06;
    /// Announces/relays a transaction.
    pub const TRANSACTION: u8 = 0x07;
    /// DHT get: requests a domain's signed record set.
    pub const GET_RECORD: u8 = 0x08;
    /// DHT put/response: carries a signed record set.
    pub const RECORD: u8 = 0x09;
}

/// A P2P message.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Message {
    /// Handshake. Direction: both ways. Payload: `version.v`.
    /// Expected response: `Hello`.
    Hello {
        /// Protocol version of the sender (1..=[`PROTOCOL_VERSION`]).
        version: u32,
    },
    /// Liveness probe. Direction: both ways. Empty payload.
    /// Expected response: `Pong`.
    Ping,
    /// Response to [`Message::Ping`]. Empty payload.
    Pong,
    /// Requests one block. Direction: both ways. Payload: `hash[32]`.
    /// Expected response: `Block` (or none if unknown).
    GetBlock { hash: BlockHash },
    /// Requests consecutive blocks. Direction: both ways. Payload:
    /// `start_height.v || max.v`. Expected response: up to `max_blocks`
    /// `Block` messages.
    GetBlocks { start_height: u64, max_blocks: u32 },
    /// Carries a block. Direction: both ways.
    Block(Box<Block>),
    /// Announces/relays a transaction. Direction: both ways.
    Transaction(Transaction),
    /// DHT get. Direction: both ways. Payload: `domain_id[32]`.
    /// Expected response: `Record` (or none if unknown).
    GetRecord { domain_id: DomainId },
    /// DHT put/response: carries a signed DNS record set.
    Record(SignedDnsRecord),
}

impl Encode for Message {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Hello { version } => {
                if *version == 0 || *version > PROTOCOL_VERSION {
                    return Err(ProtocolError::UnsupportedVersion(u64::from(*version)));
                }
                out.push(msg_type::HELLO);
                varint::put_u64(u64::from(*version), out);
                Ok(())
            }
            Self::Ping => {
                out.push(msg_type::PING);
                Ok(())
            }
            Self::Pong => {
                out.push(msg_type::PONG);
                Ok(())
            }
            Self::GetBlock { hash } => {
                out.push(msg_type::GET_BLOCK);
                hash.encode(out)
            }
            Self::GetBlocks {
                start_height,
                max_blocks,
            } => {
                if *max_blocks as usize > limits::MAX_BLOCKS_PER_REQUEST {
                    return Err(ProtocolError::LimitExceeded("max_blocks"));
                }
                out.push(msg_type::GET_BLOCKS);
                varint::put_u64(*start_height, out);
                varint::put_u64(u64::from(*max_blocks), out);
                Ok(())
            }
            Self::Block(block) => {
                out.push(msg_type::BLOCK);
                block.encode(out)
            }
            Self::Transaction(tx) => {
                out.push(msg_type::TRANSACTION);
                tx.encode(out)
            }
            Self::GetRecord { domain_id } => {
                out.push(msg_type::GET_RECORD);
                domain_id.encode(out)
            }
            Self::Record(record) => {
                out.push(msg_type::RECORD);
                record.encode(out)
            }
        }
    }
}

impl Decode for Message {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        Ok(match codec::take_u8(input)? {
            msg_type::HELLO => {
                let version = varint::take_u64(input)?;
                if version == 0 || version > u64::from(PROTOCOL_VERSION) {
                    return Err(ProtocolError::UnsupportedVersion(version));
                }
                Self::Hello {
                    version: version as u32,
                }
            }
            msg_type::PING => Self::Ping,
            msg_type::PONG => Self::Pong,
            msg_type::GET_BLOCK => Self::GetBlock {
                hash: BlockHash::decode(input)?,
            },
            msg_type::GET_BLOCKS => {
                let start_height = varint::take_u64(input)?;
                let max_blocks = varint::take_u64(input)?;
                if max_blocks > limits::MAX_BLOCKS_PER_REQUEST as u64 {
                    return Err(ProtocolError::LimitExceeded("max_blocks"));
                }
                Self::GetBlocks {
                    start_height,
                    max_blocks: max_blocks as u32,
                }
            }
            msg_type::BLOCK => Self::Block(Box::new(Block::decode(input)?)),
            msg_type::TRANSACTION => Self::Transaction(Transaction::decode(input)?),
            msg_type::GET_RECORD => Self::GetRecord {
                domain_id: DomainId::decode(input)?,
            },
            msg_type::RECORD => Self::Record(SignedDnsRecord::decode(input)?),
            value => {
                return Err(ProtocolError::UnknownDiscriminant {
                    kind: "message",
                    value,
                });
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockHeader, MerkleRoot};
    use crate::codec::{decode_complete, encode_to_vec};
    use crate::record::tests_fixtures as record_fixtures;
    use scone_core::{DomainName, OwnerId, Proof, RecordHash, Register, Signature, Update};

    fn block_fixture() -> Block {
        Block {
            header: BlockHeader {
                version: PROTOCOL_VERSION,
                height: 42,
                prev_hash: BlockHash::from_bytes([1; 32]),
                tx_root: MerkleRoot::from_bytes([2; 32]),
                timestamp: 1_700_000_000,
                consensus: vec![0xaa; 8],
            },
            transactions: vec![Transaction::Register(Register {
                domain_id: DomainId::from_name(&DomainName::new("example.uip").unwrap()),
                owner: OwnerId::from_bytes([1; 32]),
                timestamp: 1_700_000_000,
                proof: Proof::from_bytes(Vec::new()),
            })],
        }
    }

    fn record_message() -> Message {
        Message::Record(SignedDnsRecord {
            record: record_fixtures::canonical_record(),
            owner: OwnerId::from_bytes([7; 32]),
            signature: Signature::from_bytes(vec![9; 64]),
        })
    }

    fn all_messages() -> Vec<Message> {
        vec![
            Message::Hello {
                version: PROTOCOL_VERSION,
            },
            Message::Ping,
            Message::Pong,
            Message::GetBlock {
                hash: BlockHash::from_bytes([3; 32]),
            },
            Message::GetBlocks {
                start_height: 10,
                max_blocks: limits::MAX_BLOCKS_PER_REQUEST as u32,
            },
            Message::Block(Box::new(block_fixture())),
            Message::Transaction(Transaction::Update(Update {
                domain_id: DomainId::from_name(&DomainName::new("example.uip").unwrap()),
                owner: OwnerId::from_bytes([1; 32]),
                sequence: 2,
                record_hash: RecordHash::from_bytes([9; 32]),
                timestamp: 1_700_000_000,
            })),
            Message::GetRecord {
                domain_id: DomainId::from_name(&DomainName::new("example.uip").unwrap()),
            },
            record_message(),
        ]
    }

    #[test]
    fn all_messages_roundtrip() {
        for message in all_messages() {
            assert_eq!(
                decode_complete::<Message>(&encode_to_vec(&message).unwrap()).unwrap(),
                message,
                "roundtrip failed for {message:?}"
            );
        }
    }

    #[test]
    fn encoding_is_deterministic() {
        for message in all_messages() {
            assert_eq!(
                encode_to_vec(&message).unwrap(),
                encode_to_vec(&message).unwrap()
            );
        }
    }

    #[test]
    fn discriminants_are_stable() {
        assert_eq!(encode_to_vec(&Message::Ping).unwrap(), vec![msg_type::PING]);
        assert_eq!(
            encode_to_vec(&Message::Hello { version: 1 }).unwrap(),
            vec![msg_type::HELLO, 0x01]
        );
        assert_eq!(
            encode_to_vec(&Message::GetRecord {
                domain_id: DomainId::from_bytes([7; 32])
            })
            .unwrap(),
            [vec![msg_type::GET_RECORD], vec![7u8; 32]].concat()
        );
    }

    #[test]
    fn hello_version_rules() {
        assert!(matches!(
            encode_to_vec(&Message::Hello { version: 0 }),
            Err(ProtocolError::UnsupportedVersion(0))
        ));
        assert!(matches!(
            encode_to_vec(&Message::Hello {
                version: PROTOCOL_VERSION + 1
            }),
            Err(ProtocolError::UnsupportedVersion(2))
        ));
        assert!(matches!(
            decode_complete::<Message>(&[msg_type::HELLO, 0x02]),
            Err(ProtocolError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn non_minimal_hello_varint_rejected() {
        assert!(matches!(
            decode_complete::<Message>(&[msg_type::HELLO, 0x80, 0x00]),
            Err(ProtocolError::InvalidVarint(_))
        ));
    }

    #[test]
    fn get_blocks_limit() {
        let mut bytes = Vec::new();
        bytes.push(msg_type::GET_BLOCKS);
        varint::put_u64(0, &mut bytes);
        varint::put_u64(limits::MAX_BLOCKS_PER_REQUEST as u64 + 1, &mut bytes);
        assert!(matches!(
            decode_complete::<Message>(&bytes),
            Err(ProtocolError::LimitExceeded("max_blocks"))
        ));
        assert!(matches!(
            encode_to_vec(&Message::GetBlocks {
                start_height: 0,
                max_blocks: limits::MAX_BLOCKS_PER_REQUEST as u32 + 1,
            }),
            Err(ProtocolError::LimitExceeded("max_blocks"))
        ));
    }

    #[test]
    fn get_blocks_max_value_roundtrips() {
        let message = Message::GetBlocks {
            start_height: u64::MAX,
            max_blocks: limits::MAX_BLOCKS_PER_REQUEST as u32,
        };
        assert_eq!(
            decode_complete::<Message>(&encode_to_vec(&message).unwrap()).unwrap(),
            message
        );
    }

    #[test]
    fn trailing_bytes_rejected() {
        assert_eq!(
            decode_complete::<Message>(&[msg_type::PING, 0x00]),
            Err(ProtocolError::TrailingBytes(1))
        );
    }

    #[test]
    fn unknown_discriminant_rejected() {
        for disc in [0x00u8, 0x0a, 0xff] {
            assert!(matches!(
                decode_complete::<Message>(&[disc]),
                Err(ProtocolError::UnknownDiscriminant {
                    kind: "message",
                    value
                }) if value == disc
            ));
        }
    }

    #[test]
    fn truncated_messages_rejected() {
        for message in all_messages() {
            let bytes = encode_to_vec(&message).unwrap();
            for end in 0..bytes.len() {
                assert!(
                    decode_complete::<Message>(&bytes[..end]).is_err(),
                    "prefix {end} of {:?} must not decode",
                    message
                );
            }
        }
    }

    #[test]
    fn corrupted_messages_never_panic() {
        for message in all_messages() {
            let bytes = encode_to_vec(&message).unwrap();
            for i in 0..bytes.len() {
                for mask in [0x01u8, 0x80, 0xff] {
                    let mut corrupted = bytes.clone();
                    corrupted[i] ^= mask;
                    let _ = decode_complete::<Message>(&corrupted);
                }
            }
        }
    }

    #[test]
    fn random_buffers_never_panic() {
        // Small deterministic LCG fuzz: no dependency, fixed seed.
        fn next(state: &mut u64) -> u64 {
            *state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *state
        }
        let mut state = 0x853c_49e6_748f_ea9b_u64;
        for _ in 0..10_000 {
            let len = (next(&mut state) % 700) as usize;
            let mut buffer = Vec::with_capacity(len);
            for _ in 0..len / 8 + 1 {
                buffer.extend_from_slice(&next(&mut state).to_le_bytes());
            }
            buffer.truncate(len);
            let _ = decode_complete::<Message>(&buffer);
            let _ = decode_complete::<crate::block::Block>(&buffer);
            let _ = decode_complete::<Transaction>(&buffer);
            let _ = decode_complete::<SignedDnsRecord>(&buffer);
            let _ = decode_complete::<crate::block::BlockHeader>(&buffer);
        }
    }
}
