//! Read path of the Ghidra database B-tree nodes (`db.NodeMgr` and the node family).
//!
//! Node types 0-2 (long keys) are in [`longkey`]; types 3-7 (variable-length and fixed-length
//! field keys) are in [`fieldkey`]. Types 8 and 9 are chained buffer nodes (`ghidra-fmt-chain`).
//! Only the read path is implemented.

use std::fmt;

use ghidra_fmt_bytes::BytesError;
use ghidra_fmt_chain::ChainError;
use ghidra_fmt_field::FieldError;
use ghidra_fmt_gbf::GbfError;

pub mod fieldkey;
pub mod keywrite;
pub mod longkey;
pub mod longwrite;
pub mod varwrite;

/// Node type byte stored at offset 0 of every database buffer used by a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NodeType {
    /// Long-key interior node.
    LongKeyInterior = 0,
    /// Long-key variable-length record leaf.
    LongKeyVarRec = 1,
    /// Long-key fixed-length record leaf.
    LongKeyFixedRec = 2,
    /// Variable-length-key interior node.
    VarKeyInterior = 3,
    /// Variable-length-key record leaf.
    VarKeyRec = 4,
    /// Fixed-length-key interior node.
    FixedKeyInterior = 5,
    /// Fixed-length-key variable-length record leaf.
    FixedKeyVarRec = 6,
    /// Fixed-length-key fixed-length record leaf.
    FixedKeyFixedRec = 7,
    /// Chained buffer index node.
    ChainedIndex = 8,
    /// Chained buffer data node.
    ChainedData = 9,
}

impl NodeType {
    /// Decode a node type byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::LongKeyInterior,
            1 => Self::LongKeyVarRec,
            2 => Self::LongKeyFixedRec,
            3 => Self::VarKeyInterior,
            4 => Self::VarKeyRec,
            5 => Self::FixedKeyInterior,
            6 => Self::FixedKeyVarRec,
            7 => Self::FixedKeyFixedRec,
            8 => Self::ChainedIndex,
            9 => Self::ChainedData,
            _ => return None,
        })
    }
}

/// Errors raised while walking a B-tree.
#[derive(Debug)]
pub enum BtreeError {
    /// Block file failure.
    Gbf(GbfError),
    /// Chained buffer failure (indirect records).
    Chain(ChainError),
    /// Offset arithmetic inside a node failed (corrupt offsets or counts).
    Bytes(BytesError),
    /// Field decoding failure.
    Field(FieldError),
    /// Node type byte is not valid for this kind of tree (`AssertException` in Java).
    UnexpectedNodeType {
        /// Type byte found.
        found: u8,
        /// Buffer id of the node.
        buffer_id: i32,
    },
    /// Node type belongs to the other key family (use `fieldkey` for types 3-7).
    UnsupportedNodeType(u8),
    /// Node contents are inconsistent (zero keys in an interior node, negative lengths, ...).
    CorruptNode(&'static str),
    /// The tree is deeper than any valid tree can be (a loop in the child links).
    TooDeep,
    /// A fixed-key node was found but no key type was supplied.
    MissingKeyType,
    /// A fixed-record leaf was found but no record length was supplied.
    MissingFixedLength,
    /// A Java `AssertException` / invariant of the write path was violated.
    Assertion(&'static str),
    /// A record's length does not fit the table (wrong fixed length).
    BadRecordLength {
        /// Length the table requires.
        expected: usize,
        /// Length supplied.
        actual: usize,
    },
}

impl fmt::Display for BtreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gbf(e) => write!(f, "{e}"),
            Self::Chain(e) => write!(f, "{e}"),
            Self::Bytes(e) => write!(f, "{e}"),
            Self::Field(e) => write!(f, "{e}"),
            Self::UnexpectedNodeType { found, buffer_id } => write!(
                f,
                "Unexpected Node Type ({found}) found in buffer {buffer_id}"
            ),
            Self::UnsupportedNodeType(t) => {
                write!(f, "node type {t} belongs to another key family")
            }
            Self::CorruptNode(w) => write!(f, "corrupt node: {w}"),
            Self::TooDeep => write!(f, "B-tree deeper than the supported limit"),
            Self::MissingKeyType => write!(f, "key type required for fixed-key nodes"),
            Self::MissingFixedLength => write!(f, "fixed record length required"),
            Self::Assertion(w) => write!(f, "assertion failed: {w}"),
            Self::BadRecordLength { expected, actual } => {
                write!(f, "record length {actual}, table requires {expected}")
            }
        }
    }
}

impl std::error::Error for BtreeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Gbf(e) => Some(e),
            Self::Chain(e) => Some(e),
            Self::Bytes(e) => Some(e),
            Self::Field(e) => Some(e),
            _ => None,
        }
    }
}

impl From<GbfError> for BtreeError {
    fn from(e: GbfError) -> Self {
        Self::Gbf(e)
    }
}

impl From<ChainError> for BtreeError {
    fn from(e: ChainError) -> Self {
        Self::Chain(e)
    }
}

impl From<FieldError> for BtreeError {
    fn from(e: FieldError) -> Self {
        Self::Field(e)
    }
}

impl From<BytesError> for BtreeError {
    fn from(e: BytesError) -> Self {
        Self::Bytes(e)
    }
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, BtreeError>;
