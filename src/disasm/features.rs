//! Feature extraction types for disassembled instructions

use serde::{Deserialize, Serialize};

/// Categories of x86 opcodes for encoding
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OpcodeCategory {
    /// MOV, PUSH, POP, XCHG, LEA, CMOVcc
    DataTransfer,
    /// ADD, SUB, MUL, DIV, INC, DEC, NEG
    Arithmetic,
    /// AND, OR, XOR, NOT, SHL, SHR, SAR, ROL, ROR
    Logic,
    /// CMP, TEST
    Compare,
    /// JMP, Jcc, CALL, RET, LOOP
    ControlFlow,
    /// MOVS, CMPS, SCAS, LODS, STOS
    String,
    /// PUSH, POP (when primarily stack-focused)
    Stack,
    /// SYSCALL, INT, SYSENTER
    SystemCall,
    /// FLD, FST, FADD, etc.
    FloatingPoint,
    /// SSE, AVX instructions
    Simd,
    /// NOP, padding
    Nop,
    /// Miscellaneous instructions
    Other,
}

impl OpcodeCategory {
    /// Convert to a numeric index for encoding
    pub fn as_index(&self) -> usize {
        match self {
            OpcodeCategory::DataTransfer => 0,
            OpcodeCategory::Arithmetic => 1,
            OpcodeCategory::Logic => 2,
            OpcodeCategory::Compare => 3,
            OpcodeCategory::ControlFlow => 4,
            OpcodeCategory::String => 5,
            OpcodeCategory::Stack => 6,
            OpcodeCategory::SystemCall => 7,
            OpcodeCategory::FloatingPoint => 8,
            OpcodeCategory::Simd => 9,
            OpcodeCategory::Nop => 10,
            OpcodeCategory::Other => 11,
        }
    }

    /// Number of categories
    pub const COUNT: usize = 12;
}

/// Register categories for encoding
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisterCategory {
    /// AL, BL, CL, DL, AH, BH, CH, DH, etc.
    GeneralPurpose8,
    /// AX, BX, CX, DX, etc.
    GeneralPurpose16,
    /// EAX, EBX, ECX, EDX, etc.
    GeneralPurpose32,
    /// RAX, RBX, RCX, RDX, R8-R15
    GeneralPurpose64,
    /// CS, DS, ES, FS, GS, SS
    Segment,
    /// EFLAGS, RFLAGS
    Flags,
    /// EIP, RIP
    InstructionPointer,
    /// ESP, RSP
    StackPointer,
    /// EBP, RBP
    BasePointer,
    /// XMM0-XMM15
    Xmm,
    /// YMM0-YMM15
    Ymm,
    /// ST0-ST7
    Fpu,
    /// No register
    None,
}

impl RegisterCategory {
    /// Convert to a numeric index for encoding
    pub fn as_index(&self) -> usize {
        match self {
            RegisterCategory::GeneralPurpose8 => 0,
            RegisterCategory::GeneralPurpose16 => 1,
            RegisterCategory::GeneralPurpose32 => 2,
            RegisterCategory::GeneralPurpose64 => 3,
            RegisterCategory::Segment => 4,
            RegisterCategory::Flags => 5,
            RegisterCategory::InstructionPointer => 6,
            RegisterCategory::StackPointer => 7,
            RegisterCategory::BasePointer => 8,
            RegisterCategory::Xmm => 9,
            RegisterCategory::Ymm => 10,
            RegisterCategory::Fpu => 11,
            RegisterCategory::None => 12,
        }
    }

    /// Number of categories
    pub const COUNT: usize = 13;
}

/// Operand types for encoding
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperandType {
    Register,
    Memory,
    Immediate8,
    Immediate16,
    Immediate32,
    Immediate64,
    NearBranch,
    FarBranch,
    None,
}

impl OperandType {
    /// Convert to a numeric index for encoding
    pub fn as_index(&self) -> usize {
        match self {
            OperandType::Register => 0,
            OperandType::Memory => 1,
            OperandType::Immediate8 => 2,
            OperandType::Immediate16 => 3,
            OperandType::Immediate32 => 4,
            OperandType::Immediate64 => 5,
            OperandType::NearBranch => 6,
            OperandType::FarBranch => 7,
            OperandType::None => 8,
        }
    }

    /// Number of types
    pub const COUNT: usize = 9;
}

/// Flow control types
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlowControlType {
    /// Normal instruction, continues to next
    Sequential,
    /// JMP
    UnconditionalJump,
    /// Jcc
    ConditionalJump,
    /// CALL
    Call,
    /// RET
    Return,
    /// JMP [reg] or JMP [mem]
    IndirectJump,
    /// CALL [reg] or CALL [mem]
    IndirectCall,
    /// INT, SYSCALL
    Interrupt,
}

impl FlowControlType {
    /// Convert to a numeric index for encoding
    pub fn as_index(&self) -> usize {
        match self {
            FlowControlType::Sequential => 0,
            FlowControlType::UnconditionalJump => 1,
            FlowControlType::ConditionalJump => 2,
            FlowControlType::Call => 3,
            FlowControlType::Return => 4,
            FlowControlType::IndirectJump => 5,
            FlowControlType::IndirectCall => 6,
            FlowControlType::Interrupt => 7,
        }
    }

    /// Number of types
    pub const COUNT: usize = 8;
}

/// Operand pattern classification
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperandPattern {
    /// mov eax, ebx
    RegReg,
    /// mov eax, [ebx]
    RegMem,
    /// mov [eax], ebx
    MemReg,
    /// mov eax, 42
    RegImm,
    /// mov [eax], 42
    MemImm,
    /// push eax, inc eax
    RegOnly,
    /// inc [eax]
    MemOnly,
    /// push 42, int 0x80
    ImmOnly,
    /// ret, nop
    NoOperands,
    /// imul eax, ebx, 4
    RegRegImm,
    /// Complex addressing modes
    Complex,
    /// Other patterns
    Other,
}

impl OperandPattern {
    /// Convert to a numeric index for encoding
    pub fn as_index(&self) -> usize {
        match self {
            OperandPattern::RegReg => 0,
            OperandPattern::RegMem => 1,
            OperandPattern::MemReg => 2,
            OperandPattern::RegImm => 3,
            OperandPattern::MemImm => 4,
            OperandPattern::RegOnly => 5,
            OperandPattern::MemOnly => 6,
            OperandPattern::ImmOnly => 7,
            OperandPattern::NoOperands => 8,
            OperandPattern::RegRegImm => 9,
            OperandPattern::Complex => 10,
            OperandPattern::Other => 11,
        }
    }

    /// Number of patterns
    pub const COUNT: usize = 12;
}

/// Function boundary hint - indicates likely function prologue/epilogue patterns
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FunctionBoundaryHint {
    /// No boundary indication
    None,
    /// Frame setup: push rbp
    PrologueSaveFrame,
    /// Frame setup: mov rbp, rsp
    PrologueSetFrame,
    /// Stack allocation: sub rsp, N
    PrologueAllocStack,
    /// Save callee-saved register (push rbx, push r12, etc.)
    PrologueSaveReg,
    /// Intel CET: endbr64/endbr32
    PrologueCet,
    /// Frame teardown: pop rbp
    EpilogueRestoreFrame,
    /// Frame teardown: leave
    EpilogueLeave,
    /// Stack deallocation: add rsp, N
    EpilogueDeallocStack,
    /// Restore callee-saved register
    EpilogueRestoreReg,
    /// Function return: ret/retn
    EpilogueReturn,
    /// Tail call: jmp to another function
    EpilogueTailCall,
}

impl FunctionBoundaryHint {
    /// Convert to a numeric index for encoding
    pub fn as_index(&self) -> usize {
        match self {
            FunctionBoundaryHint::None => 0,
            FunctionBoundaryHint::PrologueSaveFrame => 1,
            FunctionBoundaryHint::PrologueSetFrame => 2,
            FunctionBoundaryHint::PrologueAllocStack => 3,
            FunctionBoundaryHint::PrologueSaveReg => 4,
            FunctionBoundaryHint::PrologueCet => 5,
            FunctionBoundaryHint::EpilogueRestoreFrame => 6,
            FunctionBoundaryHint::EpilogueLeave => 7,
            FunctionBoundaryHint::EpilogueDeallocStack => 8,
            FunctionBoundaryHint::EpilogueRestoreReg => 9,
            FunctionBoundaryHint::EpilogueReturn => 10,
            FunctionBoundaryHint::EpilogueTailCall => 11,
        }
    }

    /// Check if this is a prologue hint
    pub fn is_prologue(&self) -> bool {
        matches!(
            self,
            FunctionBoundaryHint::PrologueSaveFrame
                | FunctionBoundaryHint::PrologueSetFrame
                | FunctionBoundaryHint::PrologueAllocStack
                | FunctionBoundaryHint::PrologueSaveReg
                | FunctionBoundaryHint::PrologueCet
        )
    }

    /// Check if this is an epilogue hint
    pub fn is_epilogue(&self) -> bool {
        matches!(
            self,
            FunctionBoundaryHint::EpilogueRestoreFrame
                | FunctionBoundaryHint::EpilogueLeave
                | FunctionBoundaryHint::EpilogueDeallocStack
                | FunctionBoundaryHint::EpilogueRestoreReg
                | FunctionBoundaryHint::EpilogueReturn
                | FunctionBoundaryHint::EpilogueTailCall
        )
    }

    /// Number of boundary hint types
    pub const COUNT: usize = 12;
}

/// Memory access pattern
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryAccessPattern {
    /// No memory access
    NoMemory,
    /// Stack-relative access (ESP/RSP/EBP/RBP based)
    StackAccess,
    /// RIP-relative addressing
    RipRelative,
    /// Direct memory access
    DirectMemory,
    /// Indirect memory access through register
    IndirectMemory,
}

impl MemoryAccessPattern {
    /// Convert to a numeric index for encoding
    pub fn as_index(&self) -> usize {
        match self {
            MemoryAccessPattern::NoMemory => 0,
            MemoryAccessPattern::StackAccess => 1,
            MemoryAccessPattern::RipRelative => 2,
            MemoryAccessPattern::DirectMemory => 3,
            MemoryAccessPattern::IndirectMemory => 4,
        }
    }

    /// Number of patterns
    pub const COUNT: usize = 5;
}

/// A decoded instruction with extracted features
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecodedInstruction {
    /// Address of the instruction
    pub address: u64,
    /// Length in bytes
    pub length: usize,
    /// Opcode category
    pub opcode_category: OpcodeCategory,
    /// Mnemonic string
    pub mnemonic: String,
    /// Operand types
    pub operand_types: Vec<OperandType>,
    /// Operand pattern classification
    pub operand_pattern: OperandPattern,
    /// Registers read by this instruction
    pub registers_read: Vec<RegisterCategory>,
    /// Registers written by this instruction
    pub registers_written: Vec<RegisterCategory>,
    /// Flow control type
    pub flow_control: FlowControlType,
    /// Memory access pattern
    pub memory_access: MemoryAccessPattern,
    /// Whether this instruction has an immediate operand
    pub has_immediate: bool,
    /// Function boundary hint (prologue/epilogue detection)
    pub boundary_hint: FunctionBoundaryHint,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // OpcodeCategory Tests
    // ========================================================================

    #[test]
    fn test_opcode_category_as_index_all_variants() {
        assert_eq!(OpcodeCategory::DataTransfer.as_index(), 0);
        assert_eq!(OpcodeCategory::Arithmetic.as_index(), 1);
        assert_eq!(OpcodeCategory::Logic.as_index(), 2);
        assert_eq!(OpcodeCategory::Compare.as_index(), 3);
        assert_eq!(OpcodeCategory::ControlFlow.as_index(), 4);
        assert_eq!(OpcodeCategory::String.as_index(), 5);
        assert_eq!(OpcodeCategory::Stack.as_index(), 6);
        assert_eq!(OpcodeCategory::SystemCall.as_index(), 7);
        assert_eq!(OpcodeCategory::FloatingPoint.as_index(), 8);
        assert_eq!(OpcodeCategory::Simd.as_index(), 9);
        assert_eq!(OpcodeCategory::Nop.as_index(), 10);
        assert_eq!(OpcodeCategory::Other.as_index(), 11);
    }

    #[test]
    fn test_opcode_category_count() {
        assert_eq!(OpcodeCategory::COUNT, 12);
        // Verify all indices are less than COUNT
        assert!(OpcodeCategory::Other.as_index() < OpcodeCategory::COUNT);
    }

    #[test]
    fn test_opcode_category_unique_indices() {
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

        let mut seen = std::collections::HashSet::new();
        for cat in &categories {
            assert!(seen.insert(cat.as_index()), "Duplicate index: {}", cat.as_index());
        }
        assert_eq!(seen.len(), OpcodeCategory::COUNT);
    }

    // ========================================================================
    // RegisterCategory Tests
    // ========================================================================

    #[test]
    fn test_register_category_as_index_all_variants() {
        assert_eq!(RegisterCategory::GeneralPurpose8.as_index(), 0);
        assert_eq!(RegisterCategory::GeneralPurpose16.as_index(), 1);
        assert_eq!(RegisterCategory::GeneralPurpose32.as_index(), 2);
        assert_eq!(RegisterCategory::GeneralPurpose64.as_index(), 3);
        assert_eq!(RegisterCategory::Segment.as_index(), 4);
        assert_eq!(RegisterCategory::Flags.as_index(), 5);
        assert_eq!(RegisterCategory::InstructionPointer.as_index(), 6);
        assert_eq!(RegisterCategory::StackPointer.as_index(), 7);
        assert_eq!(RegisterCategory::BasePointer.as_index(), 8);
        assert_eq!(RegisterCategory::Xmm.as_index(), 9);
        assert_eq!(RegisterCategory::Ymm.as_index(), 10);
        assert_eq!(RegisterCategory::Fpu.as_index(), 11);
        assert_eq!(RegisterCategory::None.as_index(), 12);
    }

    #[test]
    fn test_register_category_count() {
        assert_eq!(RegisterCategory::COUNT, 13);
        // Verify all indices are less than COUNT
        assert!(RegisterCategory::None.as_index() < RegisterCategory::COUNT);
    }

    #[test]
    fn test_register_category_unique_indices() {
        let categories = [
            RegisterCategory::GeneralPurpose8,
            RegisterCategory::GeneralPurpose16,
            RegisterCategory::GeneralPurpose32,
            RegisterCategory::GeneralPurpose64,
            RegisterCategory::Segment,
            RegisterCategory::Flags,
            RegisterCategory::InstructionPointer,
            RegisterCategory::StackPointer,
            RegisterCategory::BasePointer,
            RegisterCategory::Xmm,
            RegisterCategory::Ymm,
            RegisterCategory::Fpu,
            RegisterCategory::None,
        ];

        let mut seen = std::collections::HashSet::new();
        for cat in &categories {
            assert!(seen.insert(cat.as_index()), "Duplicate index: {}", cat.as_index());
        }
        assert_eq!(seen.len(), RegisterCategory::COUNT);
    }

    // ========================================================================
    // OperandType Tests
    // ========================================================================

    #[test]
    fn test_operand_type_as_index_all_variants() {
        assert_eq!(OperandType::Register.as_index(), 0);
        assert_eq!(OperandType::Memory.as_index(), 1);
        assert_eq!(OperandType::Immediate8.as_index(), 2);
        assert_eq!(OperandType::Immediate16.as_index(), 3);
        assert_eq!(OperandType::Immediate32.as_index(), 4);
        assert_eq!(OperandType::Immediate64.as_index(), 5);
        assert_eq!(OperandType::NearBranch.as_index(), 6);
        assert_eq!(OperandType::FarBranch.as_index(), 7);
        assert_eq!(OperandType::None.as_index(), 8);
    }

    #[test]
    fn test_operand_type_count() {
        assert_eq!(OperandType::COUNT, 9);
        assert!(OperandType::None.as_index() < OperandType::COUNT);
    }

    #[test]
    fn test_operand_type_unique_indices() {
        let types = [
            OperandType::Register,
            OperandType::Memory,
            OperandType::Immediate8,
            OperandType::Immediate16,
            OperandType::Immediate32,
            OperandType::Immediate64,
            OperandType::NearBranch,
            OperandType::FarBranch,
            OperandType::None,
        ];

        let mut seen = std::collections::HashSet::new();
        for t in &types {
            assert!(seen.insert(t.as_index()), "Duplicate index: {}", t.as_index());
        }
        assert_eq!(seen.len(), OperandType::COUNT);
    }

    // ========================================================================
    // FlowControlType Tests
    // ========================================================================

    #[test]
    fn test_flow_control_type_as_index_all_variants() {
        assert_eq!(FlowControlType::Sequential.as_index(), 0);
        assert_eq!(FlowControlType::UnconditionalJump.as_index(), 1);
        assert_eq!(FlowControlType::ConditionalJump.as_index(), 2);
        assert_eq!(FlowControlType::Call.as_index(), 3);
        assert_eq!(FlowControlType::Return.as_index(), 4);
        assert_eq!(FlowControlType::IndirectJump.as_index(), 5);
        assert_eq!(FlowControlType::IndirectCall.as_index(), 6);
        assert_eq!(FlowControlType::Interrupt.as_index(), 7);
    }

    #[test]
    fn test_flow_control_type_count() {
        assert_eq!(FlowControlType::COUNT, 8);
        assert!(FlowControlType::Interrupt.as_index() < FlowControlType::COUNT);
    }

    #[test]
    fn test_flow_control_type_unique_indices() {
        let types = [
            FlowControlType::Sequential,
            FlowControlType::UnconditionalJump,
            FlowControlType::ConditionalJump,
            FlowControlType::Call,
            FlowControlType::Return,
            FlowControlType::IndirectJump,
            FlowControlType::IndirectCall,
            FlowControlType::Interrupt,
        ];

        let mut seen = std::collections::HashSet::new();
        for t in &types {
            assert!(seen.insert(t.as_index()), "Duplicate index: {}", t.as_index());
        }
        assert_eq!(seen.len(), FlowControlType::COUNT);
    }

    // ========================================================================
    // OperandPattern Tests
    // ========================================================================

    #[test]
    fn test_operand_pattern_as_index_all_variants() {
        assert_eq!(OperandPattern::RegReg.as_index(), 0);
        assert_eq!(OperandPattern::RegMem.as_index(), 1);
        assert_eq!(OperandPattern::MemReg.as_index(), 2);
        assert_eq!(OperandPattern::RegImm.as_index(), 3);
        assert_eq!(OperandPattern::MemImm.as_index(), 4);
        assert_eq!(OperandPattern::RegOnly.as_index(), 5);
        assert_eq!(OperandPattern::MemOnly.as_index(), 6);
        assert_eq!(OperandPattern::ImmOnly.as_index(), 7);
        assert_eq!(OperandPattern::NoOperands.as_index(), 8);
        assert_eq!(OperandPattern::RegRegImm.as_index(), 9);
        assert_eq!(OperandPattern::Complex.as_index(), 10);
        assert_eq!(OperandPattern::Other.as_index(), 11);
    }

    #[test]
    fn test_operand_pattern_count() {
        assert_eq!(OperandPattern::COUNT, 12);
        assert!(OperandPattern::Other.as_index() < OperandPattern::COUNT);
    }

    #[test]
    fn test_operand_pattern_unique_indices() {
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

        let mut seen = std::collections::HashSet::new();
        for p in &patterns {
            assert!(seen.insert(p.as_index()), "Duplicate index: {}", p.as_index());
        }
        assert_eq!(seen.len(), OperandPattern::COUNT);
    }

    // ========================================================================
    // MemoryAccessPattern Tests
    // ========================================================================

    #[test]
    fn test_memory_access_pattern_as_index_all_variants() {
        assert_eq!(MemoryAccessPattern::NoMemory.as_index(), 0);
        assert_eq!(MemoryAccessPattern::StackAccess.as_index(), 1);
        assert_eq!(MemoryAccessPattern::RipRelative.as_index(), 2);
        assert_eq!(MemoryAccessPattern::DirectMemory.as_index(), 3);
        assert_eq!(MemoryAccessPattern::IndirectMemory.as_index(), 4);
    }

    #[test]
    fn test_memory_access_pattern_count() {
        assert_eq!(MemoryAccessPattern::COUNT, 5);
        assert!(MemoryAccessPattern::IndirectMemory.as_index() < MemoryAccessPattern::COUNT);
    }

    #[test]
    fn test_memory_access_pattern_unique_indices() {
        let patterns = [
            MemoryAccessPattern::NoMemory,
            MemoryAccessPattern::StackAccess,
            MemoryAccessPattern::RipRelative,
            MemoryAccessPattern::DirectMemory,
            MemoryAccessPattern::IndirectMemory,
        ];

        let mut seen = std::collections::HashSet::new();
        for p in &patterns {
            assert!(seen.insert(p.as_index()), "Duplicate index: {}", p.as_index());
        }
        assert_eq!(seen.len(), MemoryAccessPattern::COUNT);
    }

    // ========================================================================
    // DecodedInstruction Tests
    // ========================================================================

    #[test]
    fn test_decoded_instruction_creation() {
        let instr = DecodedInstruction {
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

        assert_eq!(instr.address, 0x1000);
        assert_eq!(instr.length, 3);
        assert_eq!(instr.opcode_category, OpcodeCategory::DataTransfer);
        assert_eq!(instr.mnemonic, "mov");
        assert!(!instr.has_immediate);
    }

    #[test]
    fn test_decoded_instruction_with_immediate() {
        let instr = DecodedInstruction {
            address: 0x2000,
            length: 5,
            opcode_category: OpcodeCategory::DataTransfer,
            mnemonic: "mov".to_string(),
            operand_types: vec![OperandType::Register, OperandType::Immediate32],
            operand_pattern: OperandPattern::RegImm,
            registers_read: vec![],
            registers_written: vec![RegisterCategory::GeneralPurpose32],
            flow_control: FlowControlType::Sequential,
            memory_access: MemoryAccessPattern::NoMemory,
            has_immediate: true,
            boundary_hint: FunctionBoundaryHint::None,
        };

        assert!(instr.has_immediate);
        assert_eq!(instr.operand_types.len(), 2);
        assert_eq!(instr.operand_types[1], OperandType::Immediate32);
    }

    #[test]
    fn test_decoded_instruction_clone() {
        let instr = DecodedInstruction {
            address: 0x1000,
            length: 2,
            opcode_category: OpcodeCategory::Compare,
            mnemonic: "cmp".to_string(),
            operand_types: vec![OperandType::Register, OperandType::Register],
            operand_pattern: OperandPattern::RegReg,
            registers_read: vec![RegisterCategory::GeneralPurpose64, RegisterCategory::GeneralPurpose64],
            registers_written: vec![RegisterCategory::Flags],
            flow_control: FlowControlType::Sequential,
            memory_access: MemoryAccessPattern::NoMemory,
            has_immediate: false,
            boundary_hint: FunctionBoundaryHint::None,
        };

        let cloned = instr.clone();
        assert_eq!(instr.address, cloned.address);
        assert_eq!(instr.mnemonic, cloned.mnemonic);
        assert_eq!(instr.opcode_category, cloned.opcode_category);
    }

    #[test]
    fn test_decoded_instruction_serialization() {
        let instr = DecodedInstruction {
            address: 0x1000,
            length: 1,
            opcode_category: OpcodeCategory::Nop,
            mnemonic: "nop".to_string(),
            operand_types: vec![],
            operand_pattern: OperandPattern::NoOperands,
            registers_read: vec![],
            registers_written: vec![],
            flow_control: FlowControlType::Sequential,
            memory_access: MemoryAccessPattern::NoMemory,
            has_immediate: false,
            boundary_hint: FunctionBoundaryHint::None,
        };

        // Test JSON serialization roundtrip
        let json = serde_json::to_string(&instr).unwrap();
        let deserialized: DecodedInstruction = serde_json::from_str(&json).unwrap();

        assert_eq!(instr.address, deserialized.address);
        assert_eq!(instr.mnemonic, deserialized.mnemonic);
        assert_eq!(instr.opcode_category, deserialized.opcode_category);
    }

    // ========================================================================
    // Enum Equality and Hash Tests
    // ========================================================================

    #[test]
    fn test_opcode_category_equality() {
        assert_eq!(OpcodeCategory::DataTransfer, OpcodeCategory::DataTransfer);
        assert_ne!(OpcodeCategory::DataTransfer, OpcodeCategory::Arithmetic);
    }

    #[test]
    fn test_register_category_equality() {
        assert_eq!(RegisterCategory::GeneralPurpose64, RegisterCategory::GeneralPurpose64);
        assert_ne!(RegisterCategory::GeneralPurpose64, RegisterCategory::GeneralPurpose32);
    }

    #[test]
    fn test_enum_hashable() {
        use std::collections::HashSet;

        let mut opcodes = HashSet::new();
        opcodes.insert(OpcodeCategory::DataTransfer);
        opcodes.insert(OpcodeCategory::Arithmetic);
        opcodes.insert(OpcodeCategory::DataTransfer); // Duplicate
        assert_eq!(opcodes.len(), 2);

        let mut registers = HashSet::new();
        registers.insert(RegisterCategory::GeneralPurpose64);
        registers.insert(RegisterCategory::StackPointer);
        assert_eq!(registers.len(), 2);
    }
}
