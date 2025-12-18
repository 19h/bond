//! Bond: HTM-based binary analysis tool for code sequence clustering
//!
//! This crate provides tools for analyzing machine code in binaries using
//! Hierarchical Temporal Memory (HTM) to discover and detect code sequence patterns.

pub mod binary;
pub mod cluster;
pub mod disasm;
pub mod encoding;
pub mod htm;
pub mod persistence;

pub use binary::loader::{load_binary, Architecture, BinaryLoader, CodeSection};
pub use cluster::detector::{Cluster, ClusterDetector};
pub use disasm::decoder::X86Decoder;
pub use disasm::features::{DecodedInstruction, FlowControlType, OpcodeCategory, OperandType, RegisterCategory};
pub use encoding::instruction_encoder::InstructionEncoder;
pub use htm::config::HtmConfig;
pub use htm::pipeline::BondHtmPipeline;
pub use persistence::model_io::TrainedModel;
