//! x86/x86-64 instruction decoder using iced-x86

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

use crate::binary::loader::{Architecture, CodeSection};

use super::features::{
    DecodedInstruction, FlowControlType, FunctionBoundaryHint, MemoryAccessPattern, OpcodeCategory,
    OperandPattern, OperandType, RegisterCategory,
};

/// x86/x86-64 instruction decoder
pub struct X86Decoder {
    bitness: u32,
}

impl X86Decoder {
    /// Create a new decoder for the given architecture
    pub fn new(arch: Architecture) -> Self {
        let bitness = match arch {
            Architecture::X86 => 32,
            Architecture::X86_64 => 64,
        };
        Self { bitness }
    }

    /// Decode all instructions in a code section
    pub fn decode_section(&self, section: &CodeSection) -> Vec<DecodedInstruction> {
        let mut decoder = Decoder::with_ip(
            self.bitness,
            &section.data,
            section.virtual_address,
            DecoderOptions::NONE,
        );

        let mut instructions = Vec::new();
        let mut iced_instr = Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut iced_instr);
            if !iced_instr.is_invalid() {
                instructions.push(self.extract_features(&iced_instr));
            }
        }

        instructions
    }

    /// Extract features from a decoded instruction
    fn extract_features(&self, instr: &Instruction) -> DecodedInstruction {
        let operand_types = self.extract_operand_types(instr);
        let registers_read = self.extract_registers_read(instr);
        let registers_written = self.extract_registers_written(instr);

        DecodedInstruction {
            address: instr.ip(),
            length: instr.len(),
            opcode_category: self.categorize_opcode(instr),
            mnemonic: format!("{:?}", instr.mnemonic()).to_lowercase(),
            operand_pattern: self.classify_operand_pattern(&operand_types),
            operand_types,
            registers_read: registers_read.clone(),
            registers_written: registers_written.clone(),
            flow_control: self.convert_flow_control(instr),
            memory_access: self.classify_memory_access(instr),
            has_immediate: self.has_immediate(instr),
            boundary_hint: self.detect_boundary_hint(instr, &registers_read, &registers_written),
        }
    }

    /// Categorize the opcode into a semantic category
    fn categorize_opcode(&self, instr: &Instruction) -> OpcodeCategory {
        use Mnemonic::*;

        match instr.mnemonic() {
            // Data transfer
            Mov | Movzx | Movsx | Movsxd | Xchg | Lea | Bswap | Movbe => {
                OpcodeCategory::DataTransfer
            }
            Cmova | Cmovae | Cmovb | Cmovbe | Cmove | Cmovg | Cmovge | Cmovl | Cmovle | Cmovne
            | Cmovno | Cmovnp | Cmovns | Cmovo | Cmovp | Cmovs => OpcodeCategory::DataTransfer,

            // Arithmetic
            Add | Adc | Sub | Sbb | Mul | Imul | Div | Idiv | Inc | Dec | Neg | Cwd | Cdq | Cqo
            | Cbw | Cwde | Cdqe => OpcodeCategory::Arithmetic,

            // Logic
            And | Or | Xor | Not | Shl | Shr | Sar | Sal | Rol | Ror | Rcl | Rcr | Shld | Shrd
            | Bt | Bts | Btr | Btc | Bsf | Bsr | Popcnt | Lzcnt | Tzcnt => OpcodeCategory::Logic,

            // Compare
            Cmp | Test => OpcodeCategory::Compare,

            // Control flow
            Jmp | Call | Ret | Retf | Loop | Loope | Loopne | Jcxz | Jecxz | Jrcxz => {
                OpcodeCategory::ControlFlow
            }
            // Conditional jumps
            Ja | Jae | Jb | Jbe | Je | Jg | Jge | Jl | Jle | Jne | Jno | Jnp | Jns | Jo | Jp
            | Js => OpcodeCategory::ControlFlow,

            // String operations
            Movsb | Movsw | Movsd | Movsq | Cmpsb | Cmpsw | Cmpsd | Cmpsq | Scasb | Scasw
            | Scasd | Scasq | Lodsb | Lodsw | Lodsd | Lodsq | Stosb | Stosw | Stosd | Stosq => {
                OpcodeCategory::String
            }

            // Stack operations
            Push | Pop | Pushf | Pushfq | Popf | Popfq | Pusha | Pushad | Popa | Popad | Enter
            | Leave => OpcodeCategory::Stack,

            // System calls
            Syscall | Sysenter | Sysexit | Sysret | Int | Int1 | Int3 | Into | Iret | Iretd
            | Iretq => OpcodeCategory::SystemCall,

            // NOP
            Nop => OpcodeCategory::Nop,

            // Catch-all for other mnemonics - use string-based categorization
            other => {
                let name = format!("{:?}", other);
                if name.starts_with('F') {
                    OpcodeCategory::FloatingPoint
                } else if name.starts_with('V')
                    || name.starts_with('P')
                    || name.contains("ps")
                    || name.contains("pd")
                {
                    OpcodeCategory::Simd
                } else {
                    OpcodeCategory::Other
                }
            }
        }
    }

    /// Extract operand types from the instruction
    fn extract_operand_types(&self, instr: &Instruction) -> Vec<OperandType> {
        (0..instr.op_count())
            .map(|i| match instr.op_kind(i) {
                OpKind::Register => OperandType::Register,
                OpKind::Memory => OperandType::Memory,
                OpKind::Immediate8 | OpKind::Immediate8_2nd => OperandType::Immediate8,
                OpKind::Immediate16 | OpKind::Immediate8to16 => OperandType::Immediate16,
                OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate8to32 => {
                    OperandType::Immediate32
                }
                OpKind::Immediate64 | OpKind::Immediate8to64 => OperandType::Immediate64,
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    OperandType::NearBranch
                }
                OpKind::FarBranch16 | OpKind::FarBranch32 => OperandType::FarBranch,
                // Memory segment operands (string instructions)
                OpKind::MemorySegSI
                | OpKind::MemorySegESI
                | OpKind::MemorySegRSI
                | OpKind::MemorySegDI
                | OpKind::MemorySegEDI
                | OpKind::MemorySegRDI
                | OpKind::MemoryESDI
                | OpKind::MemoryESEDI
                | OpKind::MemoryESRDI => OperandType::Memory,
            })
            .collect()
    }

    /// Classify the operand pattern
    fn classify_operand_pattern(&self, operands: &[OperandType]) -> OperandPattern {
        use OperandType::*;

        match operands {
            [] => OperandPattern::NoOperands,
            [Register] => OperandPattern::RegOnly,
            [Memory] => OperandPattern::MemOnly,
            [Immediate8 | Immediate16 | Immediate32 | Immediate64] => OperandPattern::ImmOnly,
            [NearBranch | FarBranch] => OperandPattern::ImmOnly,
            [Register, Register] => OperandPattern::RegReg,
            [Register, Memory] => OperandPattern::RegMem,
            [Memory, Register] => OperandPattern::MemReg,
            [Register, Immediate8 | Immediate16 | Immediate32 | Immediate64] => {
                OperandPattern::RegImm
            }
            [Memory, Immediate8 | Immediate16 | Immediate32 | Immediate64] => {
                OperandPattern::MemImm
            }
            [Register, Register, Immediate8 | Immediate16 | Immediate32 | Immediate64] => {
                OperandPattern::RegRegImm
            }
            _ if operands.len() > 2 => OperandPattern::Complex,
            _ => OperandPattern::Other,
        }
    }

    /// Extract registers read by the instruction
    fn extract_registers_read(&self, instr: &Instruction) -> Vec<RegisterCategory> {
        let mut categories = Vec::new();

        // Check operands for register reads
        for i in 0..instr.op_count() {
            if instr.op_kind(i) == OpKind::Register {
                // For most instructions, operand 1+ are reads
                // Operand 0 can be both read and written
                if i > 0 || self.is_read_write_op(instr) {
                    let reg = instr.op_register(i);
                    let cat = self.categorize_register(reg);
                    if cat != RegisterCategory::None && !categories.contains(&cat) {
                        categories.push(cat);
                    }
                }
            }
            // Memory operands may have base/index registers
            if instr.op_kind(i) == OpKind::Memory {
                let base = instr.memory_base();
                let index = instr.memory_index();
                if base != Register::None {
                    let cat = self.categorize_register(base);
                    if cat != RegisterCategory::None && !categories.contains(&cat) {
                        categories.push(cat);
                    }
                }
                if index != Register::None {
                    let cat = self.categorize_register(index);
                    if cat != RegisterCategory::None && !categories.contains(&cat) {
                        categories.push(cat);
                    }
                }
            }
        }

        categories
    }

    /// Extract registers written by the instruction
    fn extract_registers_written(&self, instr: &Instruction) -> Vec<RegisterCategory> {
        let mut categories = Vec::new();

        // First operand is typically the destination
        if instr.op_count() > 0 && instr.op_kind(0) == OpKind::Register {
            let reg = instr.op_register(0);
            let cat = self.categorize_register(reg);
            if cat != RegisterCategory::None && !categories.contains(&cat) {
                categories.push(cat);
            }
        }

        // Some instructions implicitly modify registers
        match instr.mnemonic() {
            Mnemonic::Push | Mnemonic::Pop | Mnemonic::Call | Mnemonic::Ret => {
                if !categories.contains(&RegisterCategory::StackPointer) {
                    categories.push(RegisterCategory::StackPointer);
                }
            }
            Mnemonic::Mul | Mnemonic::Imul | Mnemonic::Div | Mnemonic::Idiv => {
                // These modify EAX/EDX
                if self.bitness == 64 {
                    if !categories.contains(&RegisterCategory::GeneralPurpose64) {
                        categories.push(RegisterCategory::GeneralPurpose64);
                    }
                } else {
                    if !categories.contains(&RegisterCategory::GeneralPurpose32) {
                        categories.push(RegisterCategory::GeneralPurpose32);
                    }
                }
            }
            _ => {}
        }

        // Check if flags are modified
        if instr.rflags_modified() != 0 {
            if !categories.contains(&RegisterCategory::Flags) {
                categories.push(RegisterCategory::Flags);
            }
        }

        categories
    }

    /// Check if the instruction reads and writes its first operand
    fn is_read_write_op(&self, instr: &Instruction) -> bool {
        matches!(
            instr.mnemonic(),
            Mnemonic::Add
                | Mnemonic::Sub
                | Mnemonic::And
                | Mnemonic::Or
                | Mnemonic::Xor
                | Mnemonic::Inc
                | Mnemonic::Dec
                | Mnemonic::Neg
                | Mnemonic::Not
                | Mnemonic::Shl
                | Mnemonic::Shr
                | Mnemonic::Sar
                | Mnemonic::Rol
                | Mnemonic::Ror
                | Mnemonic::Adc
                | Mnemonic::Sbb
        )
    }

    /// Categorize a register into a semantic category
    fn categorize_register(&self, reg: Register) -> RegisterCategory {
        match reg {
            Register::None => RegisterCategory::None,

            // 8-bit
            Register::AL
            | Register::BL
            | Register::CL
            | Register::DL
            | Register::AH
            | Register::BH
            | Register::CH
            | Register::DH
            | Register::SIL
            | Register::DIL
            | Register::BPL
            | Register::SPL
            | Register::R8L
            | Register::R9L
            | Register::R10L
            | Register::R11L
            | Register::R12L
            | Register::R13L
            | Register::R14L
            | Register::R15L => RegisterCategory::GeneralPurpose8,

            // 16-bit
            Register::AX
            | Register::BX
            | Register::CX
            | Register::DX
            | Register::SI
            | Register::DI
            | Register::R8W
            | Register::R9W
            | Register::R10W
            | Register::R11W
            | Register::R12W
            | Register::R13W
            | Register::R14W
            | Register::R15W => RegisterCategory::GeneralPurpose16,

            // 32-bit
            Register::EAX
            | Register::EBX
            | Register::ECX
            | Register::EDX
            | Register::ESI
            | Register::EDI
            | Register::R8D
            | Register::R9D
            | Register::R10D
            | Register::R11D
            | Register::R12D
            | Register::R13D
            | Register::R14D
            | Register::R15D => RegisterCategory::GeneralPurpose32,

            // 64-bit
            Register::RAX
            | Register::RBX
            | Register::RCX
            | Register::RDX
            | Register::RSI
            | Register::RDI
            | Register::R8
            | Register::R9
            | Register::R10
            | Register::R11
            | Register::R12
            | Register::R13
            | Register::R14
            | Register::R15 => RegisterCategory::GeneralPurpose64,

            // Stack pointer
            Register::SP | Register::ESP | Register::RSP => RegisterCategory::StackPointer,

            // Base pointer
            Register::BP | Register::EBP | Register::RBP => RegisterCategory::BasePointer,

            // Instruction pointer
            Register::EIP | Register::RIP => RegisterCategory::InstructionPointer,

            // Segment registers
            Register::CS
            | Register::DS
            | Register::ES
            | Register::FS
            | Register::GS
            | Register::SS => RegisterCategory::Segment,

            // XMM registers
            Register::XMM0
            | Register::XMM1
            | Register::XMM2
            | Register::XMM3
            | Register::XMM4
            | Register::XMM5
            | Register::XMM6
            | Register::XMM7
            | Register::XMM8
            | Register::XMM9
            | Register::XMM10
            | Register::XMM11
            | Register::XMM12
            | Register::XMM13
            | Register::XMM14
            | Register::XMM15 => RegisterCategory::Xmm,

            // YMM registers
            Register::YMM0
            | Register::YMM1
            | Register::YMM2
            | Register::YMM3
            | Register::YMM4
            | Register::YMM5
            | Register::YMM6
            | Register::YMM7
            | Register::YMM8
            | Register::YMM9
            | Register::YMM10
            | Register::YMM11
            | Register::YMM12
            | Register::YMM13
            | Register::YMM14
            | Register::YMM15 => RegisterCategory::Ymm,

            // FPU registers
            Register::ST0
            | Register::ST1
            | Register::ST2
            | Register::ST3
            | Register::ST4
            | Register::ST5
            | Register::ST6
            | Register::ST7 => RegisterCategory::Fpu,

            // Default to None for unrecognized
            _ => RegisterCategory::None,
        }
    }

    /// Convert iced-x86 flow control to our type
    fn convert_flow_control(&self, instr: &Instruction) -> FlowControlType {
        match instr.flow_control() {
            FlowControl::Next => FlowControlType::Sequential,
            FlowControl::UnconditionalBranch => {
                if instr.op_count() > 0 && instr.op_kind(0) == OpKind::Memory {
                    FlowControlType::IndirectJump
                } else if instr.op_count() > 0 && instr.op_kind(0) == OpKind::Register {
                    FlowControlType::IndirectJump
                } else {
                    FlowControlType::UnconditionalJump
                }
            }
            FlowControl::ConditionalBranch => FlowControlType::ConditionalJump,
            FlowControl::Call => {
                if instr.op_count() > 0
                    && (instr.op_kind(0) == OpKind::Memory || instr.op_kind(0) == OpKind::Register)
                {
                    FlowControlType::IndirectCall
                } else {
                    FlowControlType::Call
                }
            }
            FlowControl::Return => FlowControlType::Return,
            FlowControl::IndirectBranch => FlowControlType::IndirectJump,
            FlowControl::IndirectCall => FlowControlType::IndirectCall,
            FlowControl::Interrupt => FlowControlType::Interrupt,
            FlowControl::XbeginXabortXend => FlowControlType::Sequential,
            FlowControl::Exception => FlowControlType::Sequential,
        }
    }

    /// Classify the memory access pattern
    fn classify_memory_access(&self, instr: &Instruction) -> MemoryAccessPattern {
        for i in 0..instr.op_count() {
            if instr.op_kind(i) == OpKind::Memory {
                let base = instr.memory_base();

                // Check for stack access
                if matches!(
                    base,
                    Register::ESP | Register::RSP | Register::EBP | Register::RBP
                ) {
                    return MemoryAccessPattern::StackAccess;
                }

                // Check for RIP-relative
                if matches!(base, Register::RIP | Register::EIP) {
                    return MemoryAccessPattern::RipRelative;
                }

                // Check for direct memory (no base register)
                if base == Register::None && instr.memory_index() == Register::None {
                    return MemoryAccessPattern::DirectMemory;
                }

                return MemoryAccessPattern::IndirectMemory;
            }
        }

        MemoryAccessPattern::NoMemory
    }

    /// Check if the instruction has an immediate operand
    fn has_immediate(&self, instr: &Instruction) -> bool {
        (0..instr.op_count()).any(|i| {
            matches!(
                instr.op_kind(i),
                OpKind::Immediate8
                    | OpKind::Immediate8_2nd
                    | OpKind::Immediate16
                    | OpKind::Immediate32
                    | OpKind::Immediate32to64
                    | OpKind::Immediate64
            )
        })
    }

    /// Detect function boundary hints from instruction patterns
    fn detect_boundary_hint(
        &self,
        instr: &Instruction,
        registers_read: &[RegisterCategory],
        registers_written: &[RegisterCategory],
    ) -> FunctionBoundaryHint {
        use Mnemonic::*;

        match instr.mnemonic() {
            // PROLOGUE PATTERNS

            // endbr64/endbr32 - Intel CET (Control-flow Enforcement Technology)
            Endbr64 | Endbr32 => FunctionBoundaryHint::PrologueCet,

            // push rbp/ebp - save frame pointer (classic prologue start)
            Push => {
                if instr.op_count() > 0 && instr.op_kind(0) == OpKind::Register {
                    let reg = instr.op_register(0);
                    if matches!(reg, Register::RBP | Register::EBP | Register::BP) {
                        return FunctionBoundaryHint::PrologueSaveFrame;
                    }
                    // push of callee-saved registers (rbx, r12-r15 on x64)
                    if self.is_callee_saved_register(reg) {
                        return FunctionBoundaryHint::PrologueSaveReg;
                    }
                }
                FunctionBoundaryHint::None
            }

            // mov rbp, rsp - set up frame pointer
            Mov => {
                if instr.op_count() >= 2
                    && instr.op_kind(0) == OpKind::Register
                    && instr.op_kind(1) == OpKind::Register
                {
                    let dst = instr.op_register(0);
                    let src = instr.op_register(1);
                    // mov rbp, rsp / mov ebp, esp
                    if matches!(dst, Register::RBP | Register::EBP)
                        && matches!(src, Register::RSP | Register::ESP)
                    {
                        return FunctionBoundaryHint::PrologueSetFrame;
                    }
                    // mov rsp, rbp (epilogue - restore stack)
                    if matches!(dst, Register::RSP | Register::ESP)
                        && matches!(src, Register::RBP | Register::EBP)
                    {
                        return FunctionBoundaryHint::EpilogueDeallocStack;
                    }
                }
                FunctionBoundaryHint::None
            }

            // sub rsp, N - allocate stack space
            Sub => {
                if instr.op_count() >= 2 && instr.op_kind(0) == OpKind::Register {
                    let reg = instr.op_register(0);
                    if matches!(reg, Register::RSP | Register::ESP | Register::SP) {
                        return FunctionBoundaryHint::PrologueAllocStack;
                    }
                }
                FunctionBoundaryHint::None
            }

            // EPILOGUE PATTERNS

            // add rsp, N - deallocate stack space
            Add => {
                if instr.op_count() >= 2 && instr.op_kind(0) == OpKind::Register {
                    let reg = instr.op_register(0);
                    if matches!(reg, Register::RSP | Register::ESP | Register::SP) {
                        return FunctionBoundaryHint::EpilogueDeallocStack;
                    }
                }
                FunctionBoundaryHint::None
            }

            // pop rbp/ebp - restore frame pointer
            Pop => {
                if instr.op_count() > 0 && instr.op_kind(0) == OpKind::Register {
                    let reg = instr.op_register(0);
                    if matches!(reg, Register::RBP | Register::EBP | Register::BP) {
                        return FunctionBoundaryHint::EpilogueRestoreFrame;
                    }
                    // pop of callee-saved registers
                    if self.is_callee_saved_register(reg) {
                        return FunctionBoundaryHint::EpilogueRestoreReg;
                    }
                }
                FunctionBoundaryHint::None
            }

            // leave - equivalent to mov rsp, rbp; pop rbp
            Leave => FunctionBoundaryHint::EpilogueLeave,

            // ret/retn - function return
            Ret | Retf => FunctionBoundaryHint::EpilogueReturn,

            // jmp can be a tail call if it jumps to a function
            // (we can't easily detect this without more context, but indirect jumps
            // at the end of functions are often tail calls)
            Jmp => {
                // If it's a far jump or indirect jump after stack cleanup,
                // it might be a tail call - we can't be certain without more context
                if instr.op_count() > 0 {
                    match instr.op_kind(0) {
                        OpKind::Memory | OpKind::Register => {
                            // Indirect jump - might be a tail call via function pointer
                            FunctionBoundaryHint::EpilogueTailCall
                        }
                        _ => FunctionBoundaryHint::None,
                    }
                } else {
                    FunctionBoundaryHint::None
                }
            }

            _ => FunctionBoundaryHint::None,
        }
    }

    /// Check if a register is a callee-saved register (must be preserved across function calls)
    fn is_callee_saved_register(&self, reg: Register) -> bool {
        match self.bitness {
            64 => matches!(
                reg,
                Register::RBX
                    | Register::R12
                    | Register::R13
                    | Register::R14
                    | Register::R15
                    | Register::EBX
                    | Register::R12D
                    | Register::R13D
                    | Register::R14D
                    | Register::R15D
            ),
            32 => matches!(
                reg,
                Register::EBX | Register::ESI | Register::EDI | Register::EBP
            ),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Decoder Creation Tests
    // ========================================================================

    #[test]
    fn test_decoder_x86_bitness() {
        let decoder = X86Decoder::new(Architecture::X86);
        assert_eq!(decoder.bitness, 32);
    }

    #[test]
    fn test_decoder_x86_64_bitness() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        assert_eq!(decoder.bitness, 64);
    }

    // ========================================================================
    // Basic Instruction Decoding Tests
    // ========================================================================

    fn make_section(data: Vec<u8>) -> CodeSection {
        CodeSection {
            name: ".text".to_string(),
            virtual_address: 0x1000,
            data,
            executable: true,
        }
    }

    #[test]
    fn test_decode_nop() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        let section = make_section(vec![0x90]); // NOP
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].address, 0x1000);
        assert_eq!(instructions[0].length, 1);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::Nop);
        assert_eq!(instructions[0].mnemonic, "nop");
        assert_eq!(instructions[0].flow_control, FlowControlType::Sequential);
    }

    #[test]
    fn test_decode_ret() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        let section = make_section(vec![0xC3]); // RET
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::ControlFlow);
        assert_eq!(instructions[0].mnemonic, "ret");
        assert_eq!(instructions[0].flow_control, FlowControlType::Return);
    }

    #[test]
    fn test_decode_mov_reg_reg_64() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // MOV RAX, RBX (48 89 D8)
        let section = make_section(vec![0x48, 0x89, 0xD8]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::DataTransfer);
        assert_eq!(instructions[0].mnemonic, "mov");
        assert_eq!(instructions[0].operand_pattern, OperandPattern::RegReg);
        assert!(!instructions[0].has_immediate);
    }

    #[test]
    fn test_decode_mov_reg_imm() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // MOV EAX, 0x12345678 (B8 78 56 34 12)
        let section = make_section(vec![0xB8, 0x78, 0x56, 0x34, 0x12]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::DataTransfer);
        assert_eq!(instructions[0].operand_pattern, OperandPattern::RegImm);
        assert!(instructions[0].has_immediate);
    }

    #[test]
    fn test_decode_add_reg_reg() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // ADD RAX, RBX (48 01 D8)
        let section = make_section(vec![0x48, 0x01, 0xD8]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::Arithmetic);
        assert_eq!(instructions[0].mnemonic, "add");
    }

    #[test]
    fn test_decode_sub_reg_reg() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // SUB RAX, RBX (48 29 D8)
        let section = make_section(vec![0x48, 0x29, 0xD8]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::Arithmetic);
        assert_eq!(instructions[0].mnemonic, "sub");
    }

    #[test]
    fn test_decode_xor_reg_reg() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // XOR EAX, EAX (31 C0)
        let section = make_section(vec![0x31, 0xC0]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::Logic);
        assert_eq!(instructions[0].mnemonic, "xor");
    }

    #[test]
    fn test_decode_cmp() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // CMP EAX, EBX (39 D8)
        let section = make_section(vec![0x39, 0xD8]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::Compare);
        assert_eq!(instructions[0].mnemonic, "cmp");
    }

    #[test]
    fn test_decode_test() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // TEST EAX, EAX (85 C0)
        let section = make_section(vec![0x85, 0xC0]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::Compare);
        assert_eq!(instructions[0].mnemonic, "test");
    }

    // ========================================================================
    // Control Flow Tests
    // ========================================================================

    #[test]
    fn test_decode_jmp_rel8() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // JMP rel8 (EB 05)
        let section = make_section(vec![0xEB, 0x05]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::ControlFlow);
        assert_eq!(instructions[0].flow_control, FlowControlType::UnconditionalJump);
    }

    #[test]
    fn test_decode_je_rel8() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // JE rel8 (74 05)
        let section = make_section(vec![0x74, 0x05]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::ControlFlow);
        assert_eq!(instructions[0].flow_control, FlowControlType::ConditionalJump);
    }

    #[test]
    fn test_decode_jne_rel8() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // JNE rel8 (75 05)
        let section = make_section(vec![0x75, 0x05]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].flow_control, FlowControlType::ConditionalJump);
    }

    #[test]
    fn test_decode_call_rel32() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // CALL rel32 (E8 00 00 00 00)
        let section = make_section(vec![0xE8, 0x00, 0x00, 0x00, 0x00]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::ControlFlow);
        assert_eq!(instructions[0].flow_control, FlowControlType::Call);
    }

    #[test]
    fn test_decode_syscall() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // SYSCALL (0F 05)
        let section = make_section(vec![0x0F, 0x05]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::SystemCall);
        // iced-x86 reports SYSCALL as Call (it transfers control and returns)
        assert_eq!(instructions[0].flow_control, FlowControlType::Call);
    }

    #[test]
    fn test_decode_int3() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // INT3 (CC)
        let section = make_section(vec![0xCC]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::SystemCall);
        assert_eq!(instructions[0].flow_control, FlowControlType::Interrupt);
    }

    // ========================================================================
    // Stack Operation Tests
    // ========================================================================

    #[test]
    fn test_decode_push_rbp() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // PUSH RBP (55)
        let section = make_section(vec![0x55]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::Stack);
        assert_eq!(instructions[0].mnemonic, "push");
        assert!(instructions[0].registers_written.contains(&RegisterCategory::StackPointer));
    }

    #[test]
    fn test_decode_pop_rbp() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // POP RBP (5D)
        let section = make_section(vec![0x5D]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::Stack);
        assert_eq!(instructions[0].mnemonic, "pop");
    }

    #[test]
    fn test_decode_leave() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // LEAVE (C9)
        let section = make_section(vec![0xC9]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::Stack);
        assert_eq!(instructions[0].mnemonic, "leave");
    }

    // ========================================================================
    // Memory Access Pattern Tests
    // ========================================================================

    #[test]
    fn test_decode_mov_mem_stack_access() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // MOV [RSP+8], RAX (48 89 44 24 08)
        let section = make_section(vec![0x48, 0x89, 0x44, 0x24, 0x08]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].memory_access, MemoryAccessPattern::StackAccess);
    }

    #[test]
    fn test_decode_mov_mem_rbp_access() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // MOV [RBP-8], RAX (48 89 45 F8)
        let section = make_section(vec![0x48, 0x89, 0x45, 0xF8]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].memory_access, MemoryAccessPattern::StackAccess);
    }

    #[test]
    fn test_decode_no_memory_access() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // MOV RAX, RBX (48 89 D8)
        let section = make_section(vec![0x48, 0x89, 0xD8]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].memory_access, MemoryAccessPattern::NoMemory);
    }

    // ========================================================================
    // Register Category Tests
    // ========================================================================

    #[test]
    fn test_categorize_register_8bit() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        assert_eq!(decoder.categorize_register(Register::AL), RegisterCategory::GeneralPurpose8);
        assert_eq!(decoder.categorize_register(Register::BL), RegisterCategory::GeneralPurpose8);
        assert_eq!(decoder.categorize_register(Register::R8L), RegisterCategory::GeneralPurpose8);
    }

    #[test]
    fn test_categorize_register_16bit() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        assert_eq!(decoder.categorize_register(Register::AX), RegisterCategory::GeneralPurpose16);
        assert_eq!(decoder.categorize_register(Register::BX), RegisterCategory::GeneralPurpose16);
        assert_eq!(decoder.categorize_register(Register::R8W), RegisterCategory::GeneralPurpose16);
    }

    #[test]
    fn test_categorize_register_32bit() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        assert_eq!(decoder.categorize_register(Register::EAX), RegisterCategory::GeneralPurpose32);
        assert_eq!(decoder.categorize_register(Register::EBX), RegisterCategory::GeneralPurpose32);
        assert_eq!(decoder.categorize_register(Register::R8D), RegisterCategory::GeneralPurpose32);
    }

    #[test]
    fn test_categorize_register_64bit() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        assert_eq!(decoder.categorize_register(Register::RAX), RegisterCategory::GeneralPurpose64);
        assert_eq!(decoder.categorize_register(Register::RBX), RegisterCategory::GeneralPurpose64);
        assert_eq!(decoder.categorize_register(Register::R8), RegisterCategory::GeneralPurpose64);
    }

    #[test]
    fn test_categorize_register_special() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        assert_eq!(decoder.categorize_register(Register::RSP), RegisterCategory::StackPointer);
        assert_eq!(decoder.categorize_register(Register::RBP), RegisterCategory::BasePointer);
        assert_eq!(decoder.categorize_register(Register::RIP), RegisterCategory::InstructionPointer);
    }

    #[test]
    fn test_categorize_register_segment() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        assert_eq!(decoder.categorize_register(Register::CS), RegisterCategory::Segment);
        assert_eq!(decoder.categorize_register(Register::DS), RegisterCategory::Segment);
        assert_eq!(decoder.categorize_register(Register::FS), RegisterCategory::Segment);
    }

    #[test]
    fn test_categorize_register_xmm() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        assert_eq!(decoder.categorize_register(Register::XMM0), RegisterCategory::Xmm);
        assert_eq!(decoder.categorize_register(Register::XMM15), RegisterCategory::Xmm);
    }

    #[test]
    fn test_categorize_register_ymm() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        assert_eq!(decoder.categorize_register(Register::YMM0), RegisterCategory::Ymm);
        assert_eq!(decoder.categorize_register(Register::YMM15), RegisterCategory::Ymm);
    }

    #[test]
    fn test_categorize_register_fpu() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        assert_eq!(decoder.categorize_register(Register::ST0), RegisterCategory::Fpu);
        assert_eq!(decoder.categorize_register(Register::ST7), RegisterCategory::Fpu);
    }

    // ========================================================================
    // Operand Pattern Tests
    // ========================================================================

    #[test]
    fn test_operand_pattern_no_operands() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        let pattern = decoder.classify_operand_pattern(&[]);
        assert_eq!(pattern, OperandPattern::NoOperands);
    }

    #[test]
    fn test_operand_pattern_reg_only() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        let pattern = decoder.classify_operand_pattern(&[OperandType::Register]);
        assert_eq!(pattern, OperandPattern::RegOnly);
    }

    #[test]
    fn test_operand_pattern_mem_only() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        let pattern = decoder.classify_operand_pattern(&[OperandType::Memory]);
        assert_eq!(pattern, OperandPattern::MemOnly);
    }

    #[test]
    fn test_operand_pattern_imm_only() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        let pattern = decoder.classify_operand_pattern(&[OperandType::Immediate32]);
        assert_eq!(pattern, OperandPattern::ImmOnly);
    }

    #[test]
    fn test_operand_pattern_reg_reg() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        let pattern = decoder.classify_operand_pattern(&[OperandType::Register, OperandType::Register]);
        assert_eq!(pattern, OperandPattern::RegReg);
    }

    #[test]
    fn test_operand_pattern_reg_mem() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        let pattern = decoder.classify_operand_pattern(&[OperandType::Register, OperandType::Memory]);
        assert_eq!(pattern, OperandPattern::RegMem);
    }

    #[test]
    fn test_operand_pattern_mem_reg() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        let pattern = decoder.classify_operand_pattern(&[OperandType::Memory, OperandType::Register]);
        assert_eq!(pattern, OperandPattern::MemReg);
    }

    #[test]
    fn test_operand_pattern_reg_imm() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        let pattern = decoder.classify_operand_pattern(&[OperandType::Register, OperandType::Immediate32]);
        assert_eq!(pattern, OperandPattern::RegImm);
    }

    #[test]
    fn test_operand_pattern_mem_imm() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        let pattern = decoder.classify_operand_pattern(&[OperandType::Memory, OperandType::Immediate8]);
        assert_eq!(pattern, OperandPattern::MemImm);
    }

    #[test]
    fn test_operand_pattern_reg_reg_imm() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        let pattern = decoder.classify_operand_pattern(&[
            OperandType::Register,
            OperandType::Register,
            OperandType::Immediate8,
        ]);
        assert_eq!(pattern, OperandPattern::RegRegImm);
    }

    // ========================================================================
    // Multiple Instruction Sequence Tests
    // ========================================================================

    #[test]
    fn test_decode_function_prologue() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // push rbp; mov rbp, rsp
        let section = make_section(vec![
            0x55,             // push rbp
            0x48, 0x89, 0xE5, // mov rbp, rsp
        ]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 2);
        assert_eq!(instructions[0].mnemonic, "push");
        assert_eq!(instructions[1].mnemonic, "mov");
    }

    #[test]
    fn test_decode_function_epilogue() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // leave; ret
        let section = make_section(vec![
            0xC9, // leave
            0xC3, // ret
        ]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 2);
        assert_eq!(instructions[0].mnemonic, "leave");
        assert_eq!(instructions[1].mnemonic, "ret");
    }

    #[test]
    fn test_decode_multiple_nops() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        let section = make_section(vec![0x90, 0x90, 0x90, 0x90, 0x90]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 5);
        for instr in &instructions {
            assert_eq!(instr.mnemonic, "nop");
            assert_eq!(instr.opcode_category, OpcodeCategory::Nop);
        }
    }

    #[test]
    fn test_decode_address_progression() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        let section = make_section(vec![
            0x90,             // nop (1 byte)
            0x48, 0x89, 0xD8, // mov rax, rbx (3 bytes)
            0xC3,             // ret (1 byte)
        ]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 3);
        assert_eq!(instructions[0].address, 0x1000);
        assert_eq!(instructions[1].address, 0x1001);
        assert_eq!(instructions[2].address, 0x1004);
    }

    // ========================================================================
    // x86 (32-bit) Mode Tests
    // ========================================================================

    #[test]
    fn test_decode_x86_mov() {
        let decoder = X86Decoder::new(Architecture::X86);
        // MOV EAX, EBX (89 D8)
        let section = make_section(vec![0x89, 0xD8]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::DataTransfer);
        assert!(instructions[0].registers_written.contains(&RegisterCategory::GeneralPurpose32));
    }

    #[test]
    fn test_decode_x86_push_pop() {
        let decoder = X86Decoder::new(Architecture::X86);
        // PUSH EBP (55); POP EBP (5D)
        let section = make_section(vec![0x55, 0x5D]);
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 2);
        assert_eq!(instructions[0].opcode_category, OpcodeCategory::Stack);
        assert_eq!(instructions[1].opcode_category, OpcodeCategory::Stack);
    }

    // ========================================================================
    // Edge Cases and Invalid Instructions
    // ========================================================================

    #[test]
    fn test_decode_empty_section() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        let section = make_section(vec![]);
        let instructions = decoder.decode_section(&section);

        assert!(instructions.is_empty());
    }

    #[test]
    fn test_read_write_op_detection() {
        let decoder = X86Decoder::new(Architecture::X86_64);

        // ADD is a read-write operation
        let section = make_section(vec![0x48, 0x01, 0xD8]); // add rax, rbx
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        // RAX should be both read and written
        assert!(instructions[0].registers_read.contains(&RegisterCategory::GeneralPurpose64));
        assert!(instructions[0].registers_written.contains(&RegisterCategory::GeneralPurpose64));
    }

    #[test]
    fn test_flags_modified() {
        let decoder = X86Decoder::new(Architecture::X86_64);
        // CMP sets flags
        let section = make_section(vec![0x39, 0xD8]); // cmp eax, ebx
        let instructions = decoder.decode_section(&section);

        assert_eq!(instructions.len(), 1);
        assert!(instructions[0].registers_written.contains(&RegisterCategory::Flags));
    }
}
