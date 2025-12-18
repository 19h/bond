//! Instruction encoding to SDR (Sparse Distributed Representation)
//!
//! This module converts decoded x86/x86-64 instructions into sparse distributed
//! representations suitable for HTM processing.

use mokosh::types::Sdr;

use crate::disasm::features::{
    DecodedInstruction, FlowControlType, FunctionBoundaryHint, MemoryAccessPattern, OpcodeCategory,
    OperandPattern, OperandType, RegisterCategory,
};

/// Total SDR size in bits
pub const SDR_SIZE: usize = 2048;

/// Target sparsity (~2%)
pub const TARGET_ACTIVE_BITS: usize = 41;

/// Encoding configuration for different instruction features
#[derive(Clone, Debug)]
pub struct EncodingConfig {
    /// Bits allocated for opcode category
    pub opcode_bits: usize,
    /// Bits allocated for mnemonic hash (specific opcode)
    pub mnemonic_bits: usize,
    /// Bits allocated for operand pattern
    pub operand_pattern_bits: usize,
    /// Bits allocated for register usage
    pub register_bits: usize,
    /// Bits allocated for flow control
    pub flow_control_bits: usize,
    /// Bits allocated for instruction length
    pub length_bits: usize,
    /// Bits allocated for memory access pattern
    pub memory_access_bits: usize,
    /// Bits for operand types
    pub operand_type_bits: usize,
    /// Bits for function boundary hints (prologue/epilogue)
    pub boundary_bits: usize,
}

impl Default for EncodingConfig {
    fn default() -> Self {
        // Total must equal SDR_SIZE (2048)
        // 128 + 256 + 256 + 512 + 128 + 128 + 256 + 256 + 128 = 2048
        Self {
            opcode_bits: 128,
            mnemonic_bits: 256,
            operand_pattern_bits: 256,
            register_bits: 512,       // Reduced from 640 to make room for boundary
            flow_control_bits: 128,
            length_bits: 128,
            memory_access_bits: 256,
            operand_type_bits: 256,
            boundary_bits: 128,       // NEW: function boundary hints
        }
    }
}

impl EncodingConfig {
    /// Total bits used by this configuration
    pub fn total_bits(&self) -> usize {
        self.opcode_bits
            + self.mnemonic_bits
            + self.operand_pattern_bits
            + self.register_bits
            + self.flow_control_bits
            + self.length_bits
            + self.memory_access_bits
            + self.operand_type_bits
            + self.boundary_bits
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        let total = self.total_bits();
        if total != SDR_SIZE {
            return Err(format!(
                "Total encoding bits ({}) must equal SDR_SIZE ({})",
                total, SDR_SIZE
            ));
        }
        Ok(())
    }
}

/// Encoder for converting instructions to SDRs
pub struct InstructionEncoder {
    config: EncodingConfig,
    /// Precomputed bit offsets for each feature region
    offsets: FeatureOffsets,
}

/// Bit offsets for each feature region in the SDR
#[derive(Clone, Debug)]
struct FeatureOffsets {
    opcode: usize,
    mnemonic: usize,
    operand_pattern: usize,
    register: usize,
    flow_control: usize,
    length: usize,
    memory_access: usize,
    operand_type: usize,
    boundary: usize,
}

impl InstructionEncoder {
    /// Create a new instruction encoder with default configuration
    pub fn new() -> Self {
        Self::with_config(EncodingConfig::default())
    }

    /// Create a new instruction encoder with custom configuration
    pub fn with_config(config: EncodingConfig) -> Self {
        let mut offset = 0;

        let offsets = FeatureOffsets {
            opcode: { let o = offset; offset += config.opcode_bits; o },
            mnemonic: { let o = offset; offset += config.mnemonic_bits; o },
            operand_pattern: { let o = offset; offset += config.operand_pattern_bits; o },
            register: { let o = offset; offset += config.register_bits; o },
            flow_control: { let o = offset; offset += config.flow_control_bits; o },
            length: { let o = offset; offset += config.length_bits; o },
            memory_access: { let o = offset; offset += config.memory_access_bits; o },
            operand_type: { let o = offset; offset += config.operand_type_bits; o },
            boundary: { let _o = offset; offset },
        };

        Self { config, offsets }
    }

    /// Get the SDR size
    pub fn sdr_size(&self) -> usize {
        SDR_SIZE
    }

    /// Encode an instruction to an SDR
    pub fn encode(&self, instr: &DecodedInstruction) -> Sdr {
        let mut active_bits = Vec::with_capacity(TARGET_ACTIVE_BITS + 10);

        // Encode each feature
        self.encode_opcode_category(instr.opcode_category, &mut active_bits);
        self.encode_mnemonic(&instr.mnemonic, &mut active_bits);
        self.encode_operand_pattern(instr.operand_pattern, &mut active_bits);
        self.encode_registers(&instr.registers_read, &instr.registers_written, &mut active_bits);
        self.encode_flow_control(instr.flow_control, &mut active_bits);
        self.encode_length(instr.length, &mut active_bits);
        self.encode_memory_access(instr.memory_access, &mut active_bits);
        self.encode_operand_types(&instr.operand_types, &mut active_bits);
        self.encode_boundary_hint(instr.boundary_hint, &mut active_bits);

        // Sort and deduplicate
        active_bits.sort_unstable();
        active_bits.dedup();

        // Create SDR
        let mut sdr = Sdr::new(&[SDR_SIZE as u32]);
        sdr.set_sparse(&active_bits).expect("valid sparse indices");

        sdr
    }

    /// Encode mnemonic (specific opcode) using a hash for distributed representation
    fn encode_mnemonic(&self, mnemonic: &str, bits: &mut Vec<u32>) {
        let base = self.offsets.mnemonic;
        let region_size = self.config.mnemonic_bits;

        // Use a simple hash to distribute mnemonic bits across the region
        // This ensures similar mnemonics get different but nearby encodings
        let hash = mnemonic.bytes().fold(0u64, |acc, b| {
            acc.wrapping_mul(31).wrapping_add(b as u64)
        });

        // Generate multiple distributed bits from the hash
        for i in 0..8 {
            let bit_idx = ((hash.wrapping_shr(i * 8) as usize) % region_size) + base;
            bits.push(bit_idx as u32);
        }
    }

    /// Encode opcode category into active bits
    fn encode_opcode_category(&self, category: OpcodeCategory, bits: &mut Vec<u32>) {
        let base = self.offsets.opcode;
        let region_size = self.config.opcode_bits;
        let category_idx = category.as_index();
        let bits_per_category = region_size / OpcodeCategory::COUNT;

        // Activate bits for this category (distributed across the region)
        let start = base + category_idx * bits_per_category;
        for i in 0..5 {
            // 5 bits per category
            if start + i * 4 < base + region_size {
                bits.push((start + i * 4) as u32);
            }
        }
    }

    /// Encode operand pattern into active bits
    fn encode_operand_pattern(&self, pattern: OperandPattern, bits: &mut Vec<u32>) {
        let base = self.offsets.operand_pattern;
        let region_size = self.config.operand_pattern_bits;
        let pattern_idx = pattern.as_index();
        let bits_per_pattern = region_size / OperandPattern::COUNT;

        // Activate bits for this pattern
        let start = base + pattern_idx * bits_per_pattern;
        for i in 0..10 {
            // 10 bits per pattern
            if start + i * 3 < base + region_size {
                bits.push((start + i * 3) as u32);
            }
        }
    }

    /// Encode register usage into active bits
    fn encode_registers(
        &self,
        reads: &[RegisterCategory],
        writes: &[RegisterCategory],
        bits: &mut Vec<u32>,
    ) {
        let base = self.offsets.register;
        let region_size = self.config.register_bits;
        let half_region = region_size / 2;

        // First half for reads, second half for writes
        for cat in reads {
            if *cat != RegisterCategory::None {
                let cat_base = base + cat.as_index() * (half_region / RegisterCategory::COUNT);
                for i in 0..3 {
                    if cat_base + i * 5 < base + half_region {
                        bits.push((cat_base + i * 5) as u32);
                    }
                }
            }
        }

        for cat in writes {
            if *cat != RegisterCategory::None {
                let cat_base =
                    base + half_region + cat.as_index() * (half_region / RegisterCategory::COUNT);
                for i in 0..3 {
                    if cat_base + i * 5 < base + region_size {
                        bits.push((cat_base + i * 5) as u32);
                    }
                }
            }
        }
    }

    /// Encode flow control type into active bits
    fn encode_flow_control(&self, flow: FlowControlType, bits: &mut Vec<u32>) {
        let base = self.offsets.flow_control;
        let region_size = self.config.flow_control_bits;
        let flow_idx = flow.as_index();
        let bits_per_type = region_size / FlowControlType::COUNT;

        // Activate bits for this flow control type
        let start = base + flow_idx * bits_per_type;
        for i in 0..3 {
            // 3 bits per type
            if start + i * 4 < base + region_size {
                bits.push((start + i * 4) as u32);
            }
        }
    }

    /// Encode instruction length into active bits
    fn encode_length(&self, length: usize, bits: &mut Vec<u32>) {
        let base = self.offsets.length;
        let region_size = self.config.length_bits;

        // x86 instructions are 1-15 bytes
        // Use scalar encoding: position proportional to length
        let normalized = (length.min(15) as f64 - 1.0) / 14.0;
        let center = base as f64 + normalized * (region_size as f64 - 10.0);

        // Activate a contiguous block of bits around the center
        for i in 0..5 {
            let bit = (center as usize + i * 2).min(base + region_size - 1);
            bits.push(bit as u32);
        }
    }

    /// Encode memory access pattern into active bits
    fn encode_memory_access(&self, access: MemoryAccessPattern, bits: &mut Vec<u32>) {
        let base = self.offsets.memory_access;
        let region_size = self.config.memory_access_bits;
        let access_idx = access.as_index();
        let bits_per_pattern = region_size / MemoryAccessPattern::COUNT;

        // Activate bits for this memory access pattern
        let start = base + access_idx * bits_per_pattern;
        for i in 0..5 {
            // 5 bits per pattern
            if start + i * 8 < base + region_size {
                bits.push((start + i * 8) as u32);
            }
        }
    }

    /// Encode operand types into active bits
    fn encode_operand_types(&self, operand_types: &[OperandType], bits: &mut Vec<u32>) {
        let base = self.offsets.operand_type;
        let region_size = self.config.operand_type_bits;
        let bits_per_type = region_size / (OperandType::COUNT * 4); // up to 4 operands

        for (operand_idx, op_type) in operand_types.iter().enumerate().take(4) {
            let type_idx = op_type.as_index();
            let operand_offset = operand_idx * (region_size / 4);
            let start = base + operand_offset + type_idx * bits_per_type;

            // 3 bits per operand type
            for i in 0..3 {
                if start + i * 2 < base + region_size {
                    bits.push((start + i * 2) as u32);
                }
            }
        }
    }

    /// Encode function boundary hint into active bits
    ///
    /// This encoding is designed to help the HTM recognize function boundaries:
    /// - Prologue patterns get one region of the encoding space
    /// - Epilogue patterns get another region
    /// - The specific hint type is encoded within each region
    fn encode_boundary_hint(&self, hint: FunctionBoundaryHint, bits: &mut Vec<u32>) {
        let base = self.offsets.boundary;
        let region_size = self.config.boundary_bits;

        // Skip encoding for None hints to maintain sparsity
        if hint == FunctionBoundaryHint::None {
            return;
        }

        let hint_idx = hint.as_index();
        let bits_per_hint = region_size / FunctionBoundaryHint::COUNT;

        // Activate bits for this boundary hint
        let start = base + hint_idx * bits_per_hint;

        // Use 6 bits for boundary hints (significant signal)
        for i in 0..6 {
            if start + i * 2 < base + region_size {
                bits.push((start + i * 2) as u32);
            }
        }

        // Additionally, encode a "meta" bit for prologue vs epilogue
        // This helps HTM generalize across specific prologue/epilogue types
        if hint.is_prologue() {
            // Prologue meta-bit: first quarter of boundary region
            let meta_bit = base + region_size / 8;
            bits.push(meta_bit as u32);
        } else if hint.is_epilogue() {
            // Epilogue meta-bit: third quarter of boundary region
            let meta_bit = base + (region_size * 5) / 8;
            bits.push(meta_bit as u32);
        }
    }
}

impl Default for InstructionEncoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::features::OperandType;

    // ========================================================================
    // Helper Functions
    // ========================================================================

    fn make_simple_instruction(
        opcode: OpcodeCategory,
        pattern: OperandPattern,
        flow: FlowControlType,
        memory: MemoryAccessPattern,
    ) -> DecodedInstruction {
        DecodedInstruction {
            address: 0x1000,
            length: 3,
            opcode_category: opcode,
            mnemonic: "test".to_string(),
            operand_types: vec![],
            operand_pattern: pattern,
            registers_read: vec![RegisterCategory::GeneralPurpose64],
            registers_written: vec![RegisterCategory::GeneralPurpose64],
            flow_control: flow,
            memory_access: memory,
            has_immediate: false,
            boundary_hint: FunctionBoundaryHint::None,
        }
    }

    // ========================================================================
    // EncodingConfig Tests
    // ========================================================================

    #[test]
    fn test_config_validation() {
        let config = EncodingConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.total_bits(), SDR_SIZE);
    }

    #[test]
    fn test_config_default_values() {
        let config = EncodingConfig::default();
        assert_eq!(config.opcode_bits, 128);
        assert_eq!(config.mnemonic_bits, 256);
        assert_eq!(config.operand_pattern_bits, 256);
        assert_eq!(config.register_bits, 512);
        assert_eq!(config.flow_control_bits, 128);
        assert_eq!(config.length_bits, 128);
        assert_eq!(config.memory_access_bits, 256);
        assert_eq!(config.operand_type_bits, 256);
        assert_eq!(config.boundary_bits, 128);
    }

    #[test]
    fn test_config_total_equals_sdr_size() {
        let config = EncodingConfig::default();
        assert_eq!(
            config.opcode_bits
                + config.mnemonic_bits
                + config.operand_pattern_bits
                + config.register_bits
                + config.flow_control_bits
                + config.length_bits
                + config.memory_access_bits
                + config.operand_type_bits
                + config.boundary_bits,
            SDR_SIZE
        );
    }

    #[test]
    fn test_config_validation_fails_wrong_total() {
        let config = EncodingConfig {
            opcode_bits: 100,
            mnemonic_bits: 100,
            operand_pattern_bits: 100,
            register_bits: 100,
            flow_control_bits: 100,
            length_bits: 100,
            memory_access_bits: 100,
            operand_type_bits: 100,
            boundary_bits: 100,
        };
        assert!(config.validate().is_err());
    }

    // ========================================================================
    // InstructionEncoder Creation Tests
    // ========================================================================

    #[test]
    fn test_encoder_new() {
        let encoder = InstructionEncoder::new();
        assert_eq!(encoder.sdr_size(), SDR_SIZE);
    }

    #[test]
    fn test_encoder_default() {
        let encoder = InstructionEncoder::default();
        assert_eq!(encoder.sdr_size(), SDR_SIZE);
    }

    #[test]
    fn test_encoder_with_config() {
        let config = EncodingConfig::default();
        let encoder = InstructionEncoder::with_config(config);
        assert_eq!(encoder.sdr_size(), SDR_SIZE);
    }

    // ========================================================================
    // Basic Encoding Tests
    // ========================================================================

    #[test]
    fn test_encode_produces_sparse_sdr() {
        let encoder = InstructionEncoder::new();
        let instr = DecodedInstruction {
            address: 0x1000,
            length: 3,
            opcode_category: OpcodeCategory::DataTransfer,
            mnemonic: "mov".to_string(),
            operand_types: vec![],
            operand_pattern: OperandPattern::RegReg,
            registers_read: vec![RegisterCategory::GeneralPurpose64],
            registers_written: vec![RegisterCategory::GeneralPurpose64],
            flow_control: FlowControlType::Sequential,
            memory_access: MemoryAccessPattern::NoMemory,
            has_immediate: false,
            boundary_hint: FunctionBoundaryHint::None,
        };

        let sdr = encoder.encode(&instr);
        let sparse = sdr.get_sparse();

        // Check sparsity is reasonable
        assert!(!sparse.is_empty());
        assert!(sparse.len() < SDR_SIZE / 10); // Less than 10% active

        // Check all indices are valid
        for &idx in &sparse {
            assert!((idx as usize) < SDR_SIZE);
        }
    }

    #[test]
    fn test_encode_different_instructions_produce_different_sdrs() {
        let encoder = InstructionEncoder::new();

        let mov = make_simple_instruction(
            OpcodeCategory::DataTransfer,
            OperandPattern::RegReg,
            FlowControlType::Sequential,
            MemoryAccessPattern::NoMemory,
        );

        let add = make_simple_instruction(
            OpcodeCategory::Arithmetic,
            OperandPattern::RegReg,
            FlowControlType::Sequential,
            MemoryAccessPattern::NoMemory,
        );

        let sdr_mov = encoder.encode(&mov);
        let sdr_add = encoder.encode(&add);

        // Should be different SDRs
        assert_ne!(sdr_mov.get_sparse(), sdr_add.get_sparse());
    }

    #[test]
    fn test_encode_identical_instructions_produce_same_sdr() {
        let encoder = InstructionEncoder::new();

        let instr1 = make_simple_instruction(
            OpcodeCategory::DataTransfer,
            OperandPattern::RegReg,
            FlowControlType::Sequential,
            MemoryAccessPattern::NoMemory,
        );

        let instr2 = make_simple_instruction(
            OpcodeCategory::DataTransfer,
            OperandPattern::RegReg,
            FlowControlType::Sequential,
            MemoryAccessPattern::NoMemory,
        );

        let sdr1 = encoder.encode(&instr1);
        let sdr2 = encoder.encode(&instr2);

        assert_eq!(sdr1.get_sparse(), sdr2.get_sparse());
    }

    // ========================================================================
    // Opcode Category Encoding Tests
    // ========================================================================

    #[test]
    fn test_encode_all_opcode_categories() {
        let encoder = InstructionEncoder::new();
        let categories = [
            OpcodeCategory::DataTransfer,
            OpcodeCategory::Arithmetic,
            OpcodeCategory::Logic,
            OpcodeCategory::Compare,
            OpcodeCategory::ControlFlow,
            OpcodeCategory::String,
            OpcodeCategory::Stack,
            OpcodeCategory::SystemCall,
            OpcodeCategory::FloatingPoint,
            OpcodeCategory::Simd,
            OpcodeCategory::Nop,
            OpcodeCategory::Other,
        ];

        let sdrs: Vec<_> = categories
            .iter()
            .map(|&cat| {
                let instr = make_simple_instruction(
                    cat,
                    OperandPattern::NoOperands,
                    FlowControlType::Sequential,
                    MemoryAccessPattern::NoMemory,
                );
                encoder.encode(&instr)
            })
            .collect();

        // Each should produce a valid SDR
        for sdr in &sdrs {
            let sparse = sdr.get_sparse();
            assert!(!sparse.is_empty());
        }

        // Adjacent categories should be different
        for i in 0..sdrs.len() - 1 {
            assert_ne!(
                sdrs[i].get_sparse(),
                sdrs[i + 1].get_sparse(),
                "Categories {} and {} produced same SDR",
                i,
                i + 1
            );
        }
    }

    // ========================================================================
    // Operand Pattern Encoding Tests
    // ========================================================================

    #[test]
    fn test_encode_all_operand_patterns() {
        let encoder = InstructionEncoder::new();
        let patterns = [
            OperandPattern::RegReg,
            OperandPattern::RegMem,
            OperandPattern::MemReg,
            OperandPattern::RegImm,
            OperandPattern::MemImm,
            OperandPattern::RegOnly,
            OperandPattern::MemOnly,
            OperandPattern::ImmOnly,
            OperandPattern::NoOperands,
            OperandPattern::RegRegImm,
            OperandPattern::Complex,
            OperandPattern::Other,
        ];

        let sdrs: Vec<_> = patterns
            .iter()
            .map(|&pat| {
                let instr = make_simple_instruction(
                    OpcodeCategory::DataTransfer,
                    pat,
                    FlowControlType::Sequential,
                    MemoryAccessPattern::NoMemory,
                );
                encoder.encode(&instr)
            })
            .collect();

        // Each should produce a valid SDR
        for sdr in &sdrs {
            assert!(!sdr.get_sparse().is_empty());
        }
    }

    // ========================================================================
    // Flow Control Encoding Tests
    // ========================================================================

    #[test]
    fn test_encode_all_flow_control_types() {
        let encoder = InstructionEncoder::new();
        let flows = [
            FlowControlType::Sequential,
            FlowControlType::UnconditionalJump,
            FlowControlType::ConditionalJump,
            FlowControlType::Call,
            FlowControlType::Return,
            FlowControlType::IndirectJump,
            FlowControlType::IndirectCall,
            FlowControlType::Interrupt,
        ];

        let sdrs: Vec<_> = flows
            .iter()
            .map(|&flow| {
                let instr = make_simple_instruction(
                    OpcodeCategory::ControlFlow,
                    OperandPattern::NoOperands,
                    flow,
                    MemoryAccessPattern::NoMemory,
                );
                encoder.encode(&instr)
            })
            .collect();

        for sdr in &sdrs {
            assert!(!sdr.get_sparse().is_empty());
        }
    }

    // ========================================================================
    // Memory Access Encoding Tests
    // ========================================================================

    #[test]
    fn test_encode_all_memory_access_patterns() {
        let encoder = InstructionEncoder::new();
        let patterns = [
            MemoryAccessPattern::NoMemory,
            MemoryAccessPattern::StackAccess,
            MemoryAccessPattern::RipRelative,
            MemoryAccessPattern::DirectMemory,
            MemoryAccessPattern::IndirectMemory,
        ];

        let sdrs: Vec<_> = patterns
            .iter()
            .map(|&mem| {
                let instr = make_simple_instruction(
                    OpcodeCategory::DataTransfer,
                    OperandPattern::RegMem,
                    FlowControlType::Sequential,
                    mem,
                );
                encoder.encode(&instr)
            })
            .collect();

        for sdr in &sdrs {
            assert!(!sdr.get_sparse().is_empty());
        }
    }

    // ========================================================================
    // Register Encoding Tests
    // ========================================================================

    #[test]
    fn test_encode_different_register_categories() {
        let encoder = InstructionEncoder::new();

        let instr_gp64 = DecodedInstruction {
            address: 0x1000,
            length: 3,
            opcode_category: OpcodeCategory::DataTransfer,
            mnemonic: "mov".to_string(),
            operand_types: vec![OperandType::Register, OperandType::Register],
            operand_pattern: OperandPattern::RegReg,
            registers_read: vec![RegisterCategory::GeneralPurpose64],
            registers_written: vec![RegisterCategory::GeneralPurpose64],
            flow_control: FlowControlType::Sequential,
            memory_access: MemoryAccessPattern::NoMemory,
            has_immediate: false,
            boundary_hint: FunctionBoundaryHint::None,
        };

        let instr_xmm = DecodedInstruction {
            address: 0x1000,
            length: 3,
            opcode_category: OpcodeCategory::DataTransfer,
            mnemonic: "mov".to_string(),
            operand_types: vec![OperandType::Register, OperandType::Register],
            operand_pattern: OperandPattern::RegReg,
            registers_read: vec![RegisterCategory::Xmm],
            registers_written: vec![RegisterCategory::Xmm],
            flow_control: FlowControlType::Sequential,
            memory_access: MemoryAccessPattern::NoMemory,
            has_immediate: false,
            boundary_hint: FunctionBoundaryHint::None,
        };

        let sdr_gp64 = encoder.encode(&instr_gp64);
        let sdr_xmm = encoder.encode(&instr_xmm);

        // Should be different
        assert_ne!(sdr_gp64.get_sparse(), sdr_xmm.get_sparse());
    }

    #[test]
    fn test_encode_multiple_registers() {
        let encoder = InstructionEncoder::new();

        let instr_one = DecodedInstruction {
            address: 0x1000,
            length: 3,
            opcode_category: OpcodeCategory::DataTransfer,
            mnemonic: "mov".to_string(),
            operand_types: vec![],
            operand_pattern: OperandPattern::RegReg,
            registers_read: vec![RegisterCategory::GeneralPurpose64],
            registers_written: vec![RegisterCategory::GeneralPurpose64],
            flow_control: FlowControlType::Sequential,
            memory_access: MemoryAccessPattern::NoMemory,
            has_immediate: false,
            boundary_hint: FunctionBoundaryHint::None,
        };

        let instr_many = DecodedInstruction {
            address: 0x1000,
            length: 3,
            opcode_category: OpcodeCategory::DataTransfer,
            mnemonic: "mov".to_string(),
            operand_types: vec![],
            operand_pattern: OperandPattern::RegReg,
            registers_read: vec![
                RegisterCategory::GeneralPurpose64,
                RegisterCategory::StackPointer,
                RegisterCategory::Flags,
            ],
            registers_written: vec![RegisterCategory::GeneralPurpose64],
            flow_control: FlowControlType::Sequential,
            memory_access: MemoryAccessPattern::NoMemory,
            has_immediate: false,
            boundary_hint: FunctionBoundaryHint::None,
        };

        let sdr_one = encoder.encode(&instr_one);
        let sdr_many = encoder.encode(&instr_many);

        // Multiple registers should activate more bits
        assert!(sdr_many.get_sparse().len() >= sdr_one.get_sparse().len());
    }

    // ========================================================================
    // Instruction Length Encoding Tests
    // ========================================================================

    #[test]
    fn test_encode_different_lengths() {
        let encoder = InstructionEncoder::new();
        let mut sdrs = Vec::new();

        for length in [1, 3, 7, 15] {
            let mut instr = make_simple_instruction(
                OpcodeCategory::DataTransfer,
                OperandPattern::RegReg,
                FlowControlType::Sequential,
                MemoryAccessPattern::NoMemory,
            );
            instr.length = length;

            sdrs.push(encoder.encode(&instr));
        }

        // Different lengths should produce different encodings
        for i in 0..sdrs.len() {
            for j in i + 1..sdrs.len() {
                assert_ne!(
                    sdrs[i].get_sparse(),
                    sdrs[j].get_sparse(),
                    "Lengths produced same SDR"
                );
            }
        }
    }

    #[test]
    fn test_encode_length_bounds() {
        let encoder = InstructionEncoder::new();

        // Test minimum length (1 byte)
        let mut instr = make_simple_instruction(
            OpcodeCategory::Nop,
            OperandPattern::NoOperands,
            FlowControlType::Sequential,
            MemoryAccessPattern::NoMemory,
        );
        instr.length = 1;
        let sdr1 = encoder.encode(&instr);
        assert!(!sdr1.get_sparse().is_empty());

        // Test maximum length (15 bytes)
        instr.length = 15;
        let sdr15 = encoder.encode(&instr);
        assert!(!sdr15.get_sparse().is_empty());

        // Test beyond max (should be clamped)
        instr.length = 20;
        let sdr20 = encoder.encode(&instr);
        assert!(!sdr20.get_sparse().is_empty());
    }

    // ========================================================================
    // SDR Properties Tests
    // ========================================================================

    #[test]
    fn test_sdr_indices_sorted_and_unique() {
        let encoder = InstructionEncoder::new();
        let instr = make_simple_instruction(
            OpcodeCategory::DataTransfer,
            OperandPattern::RegReg,
            FlowControlType::Sequential,
            MemoryAccessPattern::NoMemory,
        );

        let sdr = encoder.encode(&instr);
        let sparse = sdr.get_sparse();

        // Check sorted
        for i in 1..sparse.len() {
            assert!(sparse[i - 1] < sparse[i], "SDR indices not sorted");
        }

        // Check unique (implied by sorted and strictly increasing)
        let unique: std::collections::HashSet<_> = sparse.iter().collect();
        assert_eq!(unique.len(), sparse.len(), "SDR indices not unique");
    }

    #[test]
    fn test_sdr_within_bounds() {
        let encoder = InstructionEncoder::new();
        let instr = make_simple_instruction(
            OpcodeCategory::DataTransfer,
            OperandPattern::Complex,
            FlowControlType::IndirectCall,
            MemoryAccessPattern::RipRelative,
        );

        let sdr = encoder.encode(&instr);
        let sparse = sdr.get_sparse();

        for &idx in &sparse {
            assert!(
                (idx as usize) < SDR_SIZE,
                "Index {} out of bounds (SDR_SIZE={})",
                idx,
                SDR_SIZE
            );
        }
    }

    #[test]
    fn test_sdr_reasonable_sparsity() {
        let encoder = InstructionEncoder::new();

        // Test various instruction types
        let instructions = [
            make_simple_instruction(
                OpcodeCategory::Nop,
                OperandPattern::NoOperands,
                FlowControlType::Sequential,
                MemoryAccessPattern::NoMemory,
            ),
            make_simple_instruction(
                OpcodeCategory::ControlFlow,
                OperandPattern::ImmOnly,
                FlowControlType::Call,
                MemoryAccessPattern::StackAccess,
            ),
            make_simple_instruction(
                OpcodeCategory::Simd,
                OperandPattern::Complex,
                FlowControlType::Sequential,
                MemoryAccessPattern::IndirectMemory,
            ),
        ];

        for instr in &instructions {
            let sdr = encoder.encode(instr);
            let sparse = sdr.get_sparse();
            let sparsity = sparse.len() as f64 / SDR_SIZE as f64;

            // Sparsity should be between 0.5% and 10%
            assert!(
                sparsity > 0.005 && sparsity < 0.10,
                "Sparsity {} is outside acceptable range",
                sparsity
            );
        }
    }
}
