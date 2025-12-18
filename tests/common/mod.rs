//! Shared test utilities and fixtures for Bond tests

use bond::binary::loader::CodeSection;
use bond::cluster::detector::InstructionResult;
use bond::cluster::fingerprint::Fingerprint;
use bond::disasm::features::{
    DecodedInstruction, FlowControlType, FunctionBoundaryHint, MemoryAccessPattern, OpcodeCategory,
    OperandPattern, OperandType, RegisterCategory,
};
use bond::htm::pipeline::ProcessResult;

// ============================================================================
// Real x86-64 Instruction Bytes
// ============================================================================

/// NOP instruction (0x90)
pub const NOP: &[u8] = &[0x90];

/// RET instruction (0xC3)
pub const RET: &[u8] = &[0xC3];

/// INT3 breakpoint (0xCC)
pub const INT3: &[u8] = &[0xCC];

/// SYSCALL (0x0F 0x05)
pub const SYSCALL: &[u8] = &[0x0F, 0x05];

/// MOV RAX, RBX (48 89 D8)
pub const MOV_RAX_RBX: &[u8] = &[0x48, 0x89, 0xD8];

/// MOV RBX, RAX (48 89 C3)
pub const MOV_RBX_RAX: &[u8] = &[0x48, 0x89, 0xC3];

/// MOV EAX, EBX (89 D8)
pub const MOV_EAX_EBX: &[u8] = &[0x89, 0xD8];

/// MOV EAX, 0x12345678 (B8 78 56 34 12)
pub const MOV_EAX_IMM32: &[u8] = &[0xB8, 0x78, 0x56, 0x34, 0x12];

/// ADD RAX, RBX (48 01 D8)
pub const ADD_RAX_RBX: &[u8] = &[0x48, 0x01, 0xD8];

/// ADD EAX, 1 (83 C0 01)
pub const ADD_EAX_1: &[u8] = &[0x83, 0xC0, 0x01];

/// SUB RAX, RBX (48 29 D8)
pub const SUB_RAX_RBX: &[u8] = &[0x48, 0x29, 0xD8];

/// XOR EAX, EAX (31 C0)
pub const XOR_EAX_EAX: &[u8] = &[0x31, 0xC0];

/// XOR RAX, RAX (48 31 C0)
pub const XOR_RAX_RAX: &[u8] = &[0x48, 0x31, 0xC0];

/// AND EAX, 0xFF (25 FF 00 00 00)
pub const AND_EAX_FF: &[u8] = &[0x25, 0xFF, 0x00, 0x00, 0x00];

/// CMP EAX, EBX (39 D8)
pub const CMP_EAX_EBX: &[u8] = &[0x39, 0xD8];

/// CMP RAX, 0 (48 83 F8 00)
pub const CMP_RAX_0: &[u8] = &[0x48, 0x83, 0xF8, 0x00];

/// TEST EAX, EAX (85 C0)
pub const TEST_EAX_EAX: &[u8] = &[0x85, 0xC0];

/// JE rel8 (0x74 0x05 - jump 5 bytes forward)
pub const JE_REL8: &[u8] = &[0x74, 0x05];

/// JNE rel8 (0x75 0x05 - jump 5 bytes forward)
pub const JNE_REL8: &[u8] = &[0x75, 0x05];

/// JMP rel8 (0xEB 0x05 - jump 5 bytes forward)
pub const JMP_REL8: &[u8] = &[0xEB, 0x05];

/// CALL rel32 (E8 xx xx xx xx)
pub const CALL_REL32: &[u8] = &[0xE8, 0x00, 0x00, 0x00, 0x00];

/// PUSH RBP (55)
pub const PUSH_RBP: &[u8] = &[0x55];

/// POP RBP (5D)
pub const POP_RBP: &[u8] = &[0x5D];

/// PUSH RAX (50)
pub const PUSH_RAX: &[u8] = &[0x50];

/// POP RAX (58)
pub const POP_RAX: &[u8] = &[0x58];

/// MOV RBP, RSP (48 89 E5)
pub const MOV_RBP_RSP: &[u8] = &[0x48, 0x89, 0xE5];

/// MOV RSP, RBP (48 89 EC)
pub const MOV_RSP_RBP: &[u8] = &[0x48, 0x89, 0xEC];

/// LEAVE (C9) - equivalent to MOV RSP, RBP; POP RBP
pub const LEAVE: &[u8] = &[0xC9];

/// MOV [RAX], RBX (48 89 18) - memory store
pub const MOV_MEM_RAX_RBX: &[u8] = &[0x48, 0x89, 0x18];

/// MOV RAX, [RBX] (48 8B 03) - memory load
pub const MOV_RAX_MEM_RBX: &[u8] = &[0x48, 0x8B, 0x03];

/// LEA RAX, [RBX+RCX*4] (48 8D 04 8B)
pub const LEA_COMPLEX: &[u8] = &[0x48, 0x8D, 0x04, 0x8B];

/// INC EAX (FF C0)
pub const INC_EAX: &[u8] = &[0xFF, 0xC0];

/// DEC EAX (FF C8)
pub const DEC_EAX: &[u8] = &[0xFF, 0xC8];

// ============================================================================
// Function Prologue/Epilogue Sequences
// ============================================================================

/// Standard function prologue: push rbp; mov rbp, rsp
pub fn standard_prologue() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PUSH_RBP);
    bytes.extend_from_slice(MOV_RBP_RSP);
    bytes
}

/// Standard function epilogue: leave; ret
pub fn standard_epilogue() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(LEAVE);
    bytes.extend_from_slice(RET);
    bytes
}

/// Simple function: prologue + body + epilogue
pub fn simple_function(body: &[u8]) -> Vec<u8> {
    let mut bytes = standard_prologue();
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(&standard_epilogue());
    bytes
}

// ============================================================================
// Test Instruction Helpers
// ============================================================================

/// Create a DecodedInstruction with configurable fields
pub fn make_test_instruction(
    address: u64,
    opcode_category: OpcodeCategory,
    mnemonic: &str,
) -> DecodedInstruction {
    DecodedInstruction {
        address,
        length: 3,
        opcode_category,
        mnemonic: mnemonic.to_string(),
        operand_types: vec![OperandType::Register, OperandType::Register],
        operand_pattern: OperandPattern::RegReg,
        registers_read: vec![RegisterCategory::GeneralPurpose64],
        registers_written: vec![RegisterCategory::GeneralPurpose64],
        flow_control: FlowControlType::Sequential,
        memory_access: MemoryAccessPattern::NoMemory,
        has_immediate: false,
        boundary_hint: FunctionBoundaryHint::None,
    }
}

/// Create a DecodedInstruction with full control over all fields
#[allow(clippy::too_many_arguments)]
pub fn make_instruction_full(
    address: u64,
    length: usize,
    opcode_category: OpcodeCategory,
    mnemonic: &str,
    operand_types: Vec<OperandType>,
    operand_pattern: OperandPattern,
    registers_read: Vec<RegisterCategory>,
    registers_written: Vec<RegisterCategory>,
    flow_control: FlowControlType,
    memory_access: MemoryAccessPattern,
    has_immediate: bool,
) -> DecodedInstruction {
    DecodedInstruction {
        address,
        length,
        opcode_category,
        mnemonic: mnemonic.to_string(),
        operand_types,
        operand_pattern,
        registers_read,
        registers_written,
        flow_control,
        memory_access,
        has_immediate,
        boundary_hint: FunctionBoundaryHint::None,
    }
}

/// Create a MOV reg, reg instruction
pub fn make_mov_reg_reg(address: u64) -> DecodedInstruction {
    make_instruction_full(
        address,
        3,
        OpcodeCategory::DataTransfer,
        "mov",
        vec![OperandType::Register, OperandType::Register],
        OperandPattern::RegReg,
        vec![RegisterCategory::GeneralPurpose64],
        vec![RegisterCategory::GeneralPurpose64],
        FlowControlType::Sequential,
        MemoryAccessPattern::NoMemory,
        false,
    )
}

/// Create an ADD reg, imm instruction
pub fn make_add_reg_imm(address: u64) -> DecodedInstruction {
    make_instruction_full(
        address,
        3,
        OpcodeCategory::Arithmetic,
        "add",
        vec![OperandType::Register, OperandType::Immediate8],
        OperandPattern::RegImm,
        vec![RegisterCategory::GeneralPurpose64],
        vec![RegisterCategory::GeneralPurpose64],
        FlowControlType::Sequential,
        MemoryAccessPattern::NoMemory,
        true,
    )
}

/// Create a CMP instruction
pub fn make_cmp(address: u64) -> DecodedInstruction {
    make_instruction_full(
        address,
        2,
        OpcodeCategory::Compare,
        "cmp",
        vec![OperandType::Register, OperandType::Register],
        OperandPattern::RegReg,
        vec![
            RegisterCategory::GeneralPurpose64,
            RegisterCategory::GeneralPurpose64,
        ],
        vec![RegisterCategory::Flags],
        FlowControlType::Sequential,
        MemoryAccessPattern::NoMemory,
        false,
    )
}

/// Create a conditional jump instruction
pub fn make_je(address: u64) -> DecodedInstruction {
    make_instruction_full(
        address,
        2,
        OpcodeCategory::ControlFlow,
        "je",
        vec![OperandType::NearBranch],
        OperandPattern::ImmOnly,
        vec![RegisterCategory::Flags],
        vec![],
        FlowControlType::ConditionalJump,
        MemoryAccessPattern::NoMemory,
        false,
    )
}

/// Create a CALL instruction
pub fn make_call(address: u64) -> DecodedInstruction {
    make_instruction_full(
        address,
        5,
        OpcodeCategory::ControlFlow,
        "call",
        vec![OperandType::NearBranch],
        OperandPattern::ImmOnly,
        vec![],
        vec![RegisterCategory::StackPointer],
        FlowControlType::Call,
        MemoryAccessPattern::StackAccess,
        false,
    )
}

/// Create a RET instruction
pub fn make_ret(address: u64) -> DecodedInstruction {
    make_instruction_full(
        address,
        1,
        OpcodeCategory::ControlFlow,
        "ret",
        vec![],
        OperandPattern::NoOperands,
        vec![RegisterCategory::StackPointer],
        vec![RegisterCategory::StackPointer],
        FlowControlType::Return,
        MemoryAccessPattern::StackAccess,
        false,
    )
}

/// Create a PUSH instruction
pub fn make_push(address: u64) -> DecodedInstruction {
    make_instruction_full(
        address,
        1,
        OpcodeCategory::Stack,
        "push",
        vec![OperandType::Register],
        OperandPattern::RegOnly,
        vec![
            RegisterCategory::StackPointer,
            RegisterCategory::GeneralPurpose64,
        ],
        vec![RegisterCategory::StackPointer],
        FlowControlType::Sequential,
        MemoryAccessPattern::StackAccess,
        false,
    )
}

/// Create a POP instruction
pub fn make_pop(address: u64) -> DecodedInstruction {
    make_instruction_full(
        address,
        1,
        OpcodeCategory::Stack,
        "pop",
        vec![OperandType::Register],
        OperandPattern::RegOnly,
        vec![RegisterCategory::StackPointer],
        vec![
            RegisterCategory::StackPointer,
            RegisterCategory::GeneralPurpose64,
        ],
        FlowControlType::Sequential,
        MemoryAccessPattern::StackAccess,
        false,
    )
}

/// Create a NOP instruction
pub fn make_nop(address: u64) -> DecodedInstruction {
    make_instruction_full(
        address,
        1,
        OpcodeCategory::Nop,
        "nop",
        vec![],
        OperandPattern::NoOperands,
        vec![],
        vec![],
        FlowControlType::Sequential,
        MemoryAccessPattern::NoMemory,
        false,
    )
}

/// Create a SYSCALL instruction
pub fn make_syscall(address: u64) -> DecodedInstruction {
    make_instruction_full(
        address,
        2,
        OpcodeCategory::SystemCall,
        "syscall",
        vec![],
        OperandPattern::NoOperands,
        vec![],
        vec![],
        FlowControlType::Interrupt,
        MemoryAccessPattern::NoMemory,
        false,
    )
}

/// Create a memory load instruction (MOV reg, [mem])
pub fn make_mem_load(address: u64) -> DecodedInstruction {
    make_instruction_full(
        address,
        3,
        OpcodeCategory::DataTransfer,
        "mov",
        vec![OperandType::Register, OperandType::Memory],
        OperandPattern::RegMem,
        vec![RegisterCategory::GeneralPurpose64],
        vec![RegisterCategory::GeneralPurpose64],
        FlowControlType::Sequential,
        MemoryAccessPattern::IndirectMemory,
        false,
    )
}

/// Create a memory store instruction (MOV [mem], reg)
pub fn make_mem_store(address: u64) -> DecodedInstruction {
    make_instruction_full(
        address,
        3,
        OpcodeCategory::DataTransfer,
        "mov",
        vec![OperandType::Memory, OperandType::Register],
        OperandPattern::MemReg,
        vec![
            RegisterCategory::GeneralPurpose64,
            RegisterCategory::GeneralPurpose64,
        ],
        vec![],
        FlowControlType::Sequential,
        MemoryAccessPattern::IndirectMemory,
        false,
    )
}

// ============================================================================
// HTM Result Helpers
// ============================================================================

/// Create a ProcessResult with configurable fields
pub fn make_process_result(
    anomaly_score: f32,
    active_cells: Vec<u32>,
    predictive_cells: Vec<u32>,
    bursting_columns: usize,
) -> ProcessResult {
    ProcessResult {
        anomaly_score,
        active_cells,
        predictive_cells,
        bursting_columns,
    }
}

/// Create a low-anomaly ProcessResult (normal/expected)
pub fn make_normal_result(cells: Vec<u32>) -> ProcessResult {
    make_process_result(0.1, cells.clone(), cells, 2)
}

/// Create a high-anomaly ProcessResult (anomalous)
pub fn make_anomalous_result(cells: Vec<u32>) -> ProcessResult {
    make_process_result(0.9, cells, vec![], 20)
}

// ============================================================================
// Cluster Helpers
// ============================================================================

/// Create an InstructionResult combining instruction and HTM result
pub fn make_instruction_result(
    instruction: DecodedInstruction,
    result: ProcessResult,
) -> InstructionResult {
    InstructionResult {
        instruction,
        result,
    }
}

/// Create an InstructionResult with simple parameters
pub fn make_simple_instruction_result(
    address: u64,
    opcode: OpcodeCategory,
    anomaly: f32,
    cells: Vec<u32>,
) -> InstructionResult {
    InstructionResult {
        instruction: make_test_instruction(address, opcode, "test"),
        result: ProcessResult {
            anomaly_score: anomaly,
            active_cells: cells.clone(),
            predictive_cells: cells,
            bursting_columns: 0,
        },
    }
}

/// Create a Fingerprint from cell indices
pub fn make_test_fingerprint(cells: Vec<u32>) -> Fingerprint {
    Fingerprint::new(cells)
}

// ============================================================================
// Binary Test Fixtures
// ============================================================================

/// Create a CodeSection with raw instruction bytes
pub fn make_code_section(name: &str, virtual_address: u64, data: Vec<u8>) -> CodeSection {
    CodeSection {
        name: name.to_string(),
        virtual_address,
        data,
        executable: true,
    }
}

/// Create a .text section with some test instructions
pub fn make_text_section(instructions: &[&[u8]]) -> CodeSection {
    let mut data = Vec::new();
    for instr in instructions {
        data.extend_from_slice(instr);
    }
    make_code_section(".text", 0x401000, data)
}

/// Create a minimal valid x86-64 ELF binary
///
/// This creates a statically-linked ELF64 executable that will make the
/// exit(0) syscall. It's the smallest valid ELF that can be executed.
pub fn make_minimal_elf64() -> Vec<u8> {
    // ELF64 header (64 bytes)
    let mut elf = vec![
        // e_ident (16 bytes)
        0x7F, b'E', b'L', b'F', // Magic
        0x02, // 64-bit
        0x01, // Little-endian
        0x01, // ELF version 1
        0x00, // System V ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
        // e_type (2 bytes)
        0x02, 0x00, // ET_EXEC - Executable
        // e_machine (2 bytes)
        0x3E, 0x00, // x86-64
        // e_version (4 bytes)
        0x01, 0x00, 0x00, 0x00, // ELF version 1
        // e_entry (8 bytes) - entry point
        0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x400078
        // e_phoff (8 bytes) - program header offset
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 64 bytes
        // e_shoff (8 bytes) - section header offset (0 = none)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // e_flags (4 bytes)
        0x00, 0x00, 0x00, 0x00,
        // e_ehsize (2 bytes) - ELF header size
        0x40, 0x00, // 64 bytes
        // e_phentsize (2 bytes) - program header entry size
        0x38, 0x00, // 56 bytes
        // e_phnum (2 bytes) - number of program headers
        0x01, 0x00, // 1 entry
        // e_shentsize (2 bytes) - section header entry size
        0x40, 0x00, // 64 bytes
        // e_shnum (2 bytes) - number of section headers
        0x00, 0x00, // 0 entries
        // e_shstrndx (2 bytes) - section name string table index
        0x00, 0x00,
    ];

    // Program header (56 bytes) at offset 64
    let ph = vec![
        // p_type (4 bytes)
        0x01, 0x00, 0x00, 0x00, // PT_LOAD
        // p_flags (4 bytes)
        0x05, 0x00, 0x00, 0x00, // PF_R | PF_X
        // p_offset (8 bytes) - offset in file
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // p_vaddr (8 bytes) - virtual address
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x400000
        // p_paddr (8 bytes) - physical address
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        // p_filesz (8 bytes) - size in file
        0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 136 bytes total
        // p_memsz (8 bytes) - size in memory
        0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // p_align (8 bytes) - alignment
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 4096
    ];
    elf.extend_from_slice(&ph);

    // Code at offset 120 (0x78)
    // This is the entry point (0x400078)
    let code = vec![
        0x48, 0x31, 0xC0, // xor rax, rax
        0xB0, 0x3C, // mov al, 60 (exit syscall)
        0x48, 0x31, 0xFF, // xor rdi, rdi (exit code 0)
        0x0F, 0x05, // syscall
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // nops for padding
    ];
    elf.extend_from_slice(&code);

    elf
}

/// Create a minimal valid x86-64 PE (Portable Executable) binary
///
/// This creates a minimal PE32+ executable.
pub fn make_minimal_pe64() -> Vec<u8> {
    let mut pe = Vec::new();

    // DOS Header (64 bytes)
    let dos_header = vec![
        // DOS Magic
        0x4D, 0x5A, // "MZ"
        // Padding to e_lfanew at offset 60
        0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // e_lfanew - PE header offset (offset 60)
        0x80, 0x00, 0x00, 0x00, // 128
    ];
    pe.extend_from_slice(&dos_header);

    // DOS Stub - padding to offset 128
    pe.resize(128, 0);

    // PE Signature
    pe.extend_from_slice(&[0x50, 0x45, 0x00, 0x00]); // "PE\0\0"

    // COFF File Header (20 bytes)
    pe.extend_from_slice(&[
        0x64, 0x86, // Machine: AMD64
        0x01, 0x00, // NumberOfSections: 1
        0x00, 0x00, 0x00, 0x00, // TimeDateStamp
        0x00, 0x00, 0x00, 0x00, // PointerToSymbolTable
        0x00, 0x00, 0x00, 0x00, // NumberOfSymbols
        0xF0, 0x00, // SizeOfOptionalHeader: 240
        0x22, 0x00, // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    ]);

    // Optional Header (PE32+) - 240 bytes
    let mut opt_header = vec![
        0x0B, 0x02, // Magic: PE32+
        0x0E, 0x00, // LinkerVersion
        0x00, 0x02, 0x00, 0x00, // SizeOfCode: 512
        0x00, 0x00, 0x00, 0x00, // SizeOfInitializedData
        0x00, 0x00, 0x00, 0x00, // SizeOfUninitializedData
        0x00, 0x10, 0x00, 0x00, // AddressOfEntryPoint: 0x1000
        0x00, 0x10, 0x00, 0x00, // BaseOfCode: 0x1000
        // PE32+ specific
        0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, // ImageBase: 0x140000000
        0x00, 0x10, 0x00, 0x00, // SectionAlignment: 4096
        0x00, 0x02, 0x00, 0x00, // FileAlignment: 512
        0x06, 0x00, // MajorOperatingSystemVersion: 6
        0x00, 0x00, // MinorOperatingSystemVersion: 0
        0x00, 0x00, // MajorImageVersion
        0x00, 0x00, // MinorImageVersion
        0x06, 0x00, // MajorSubsystemVersion: 6
        0x00, 0x00, // MinorSubsystemVersion: 0
        0x00, 0x00, 0x00, 0x00, // Win32VersionValue
        0x00, 0x30, 0x00, 0x00, // SizeOfImage: 0x3000
        0x00, 0x02, 0x00, 0x00, // SizeOfHeaders: 512
        0x00, 0x00, 0x00, 0x00, // CheckSum
        0x03, 0x00, // Subsystem: CONSOLE
        0x60, 0x81, // DllCharacteristics: DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, // SizeOfStackReserve: 1MB
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SizeOfStackCommit: 4KB
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, // SizeOfHeapReserve: 1MB
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SizeOfHeapCommit: 4KB
        0x00, 0x00, 0x00, 0x00, // LoaderFlags
        0x10, 0x00, 0x00, 0x00, // NumberOfRvaAndSizes: 16
    ];

    // Data directories (16 entries * 8 bytes = 128 bytes)
    for _ in 0..16 {
        opt_header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    pe.extend_from_slice(&opt_header);

    // Section Header for .text (40 bytes)
    let section_header = vec![
        0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, // Name: ".text"
        0x00, 0x02, 0x00, 0x00, // VirtualSize: 512
        0x00, 0x10, 0x00, 0x00, // VirtualAddress: 0x1000
        0x00, 0x02, 0x00, 0x00, // SizeOfRawData: 512
        0x00, 0x02, 0x00, 0x00, // PointerToRawData: 512
        0x00, 0x00, 0x00, 0x00, // PointerToRelocations
        0x00, 0x00, 0x00, 0x00, // PointerToLinenumbers
        0x00, 0x00, // NumberOfRelocations
        0x00, 0x00, // NumberOfLinenumbers
        0x20, 0x00, 0x00, 0x60, // Characteristics: CNT_CODE | MEM_EXECUTE | MEM_READ
    ];
    pe.extend_from_slice(&section_header);

    // Pad to 512 bytes (file alignment)
    pe.resize(512, 0);

    // .text section content (512 bytes)
    let mut code = vec![
        // Entry point code - simple ret
        0x48, 0x31, 0xC0, // xor rax, rax
        0xC3, // ret
        // Some additional instructions for testing
        0x48, 0x89, 0xD8, // mov rax, rbx
        0x48, 0x01, 0xD8, // add rax, rbx
        0x48, 0x29, 0xD8, // sub rax, rbx
        0x48, 0x31, 0xC0, // xor rax, rax
        0x85, 0xC0, // test eax, eax
        0x74, 0x02, // je +2
        0xEB, 0x00, // jmp +0
        0xC3, // ret
    ];
    code.resize(512, 0x90); // Pad with NOPs
    pe.extend_from_slice(&code);

    pe
}

/// Create a sequence of instructions that forms a typical loop pattern
pub fn make_loop_sequence() -> Vec<DecodedInstruction> {
    vec![
        make_mov_reg_reg(0x1000),
        make_add_reg_imm(0x1003),
        make_cmp(0x1006),
        make_je(0x1008),
    ]
}

/// Create a function-like instruction sequence
pub fn make_function_sequence() -> Vec<DecodedInstruction> {
    vec![
        make_push(0x1000),           // push rbp
        make_mov_reg_reg(0x1001),    // mov rbp, rsp
        make_mov_reg_reg(0x1004),    // some work
        make_add_reg_imm(0x1007),    // more work
        make_cmp(0x100A),            // compare
        make_je(0x100C),             // conditional
        make_pop(0x100E),            // pop rbp
        make_ret(0x100F),            // ret
    ]
}

// ============================================================================
// Test Result Helpers
// ============================================================================

/// Assert that an anomaly score is within valid bounds [0, 1]
pub fn assert_valid_anomaly(score: f32) {
    assert!(
        (0.0..=1.0).contains(&score),
        "Anomaly score {} is not in range [0, 1]",
        score
    );
}

/// Assert that a similarity score is within valid bounds [0, 1]
pub fn assert_valid_similarity(score: f64) {
    assert!(
        (0.0..=1.0).contains(&score),
        "Similarity score {} is not in range [0, 1]",
        score
    );
}

/// Assert that two f64 values are approximately equal
pub fn assert_approx_eq(a: f64, b: f64, epsilon: f64) {
    assert!(
        (a - b).abs() < epsilon,
        "Values {} and {} differ by more than {}",
        a,
        b,
        epsilon
    );
}

/// Assert that two f32 values are approximately equal
pub fn assert_approx_eq_f32(a: f32, b: f32, epsilon: f32) {
    assert!(
        (a - b).abs() < epsilon,
        "Values {} and {} differ by more than {}",
        a,
        b,
        epsilon
    );
}
