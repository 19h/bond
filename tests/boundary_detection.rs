// Test function boundary detection

use bond::binary::loader::load_binary;
use bond::disasm::decoder::X86Decoder;
use bond::disasm::features::{DecodedInstruction, FunctionBoundaryHint};
use std::path::Path;

const CORPUS_DIR: &str = "tests/corpus/bin";

fn corpus_available() -> bool {
    Path::new(CORPUS_DIR).join("train_loops").exists()
}

fn disassemble_binary(path: &str) -> Vec<DecodedInstruction> {
    let binary = load_binary(Path::new(path)).unwrap();
    let decoder = X86Decoder::new(binary.architecture());
    let mut instructions = Vec::new();
    for section in binary.code_sections() {
        instructions.extend(decoder.decode_section(&section));
    }
    instructions
}

#[test]
fn test_boundary_detection_in_real_binary() {
    if !corpus_available() {
        return;
    }

    println!("\n=== FUNCTION BOUNDARY DETECTION ===\n");

    let path = format!("{}/train_functions", CORPUS_DIR);
    let instructions = disassemble_binary(&path);

    println!("Total instructions: {}", instructions.len());

    // Count boundary hints
    let mut prologue_count = 0;
    let mut epilogue_count = 0;
    let mut prologue_types: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut epilogue_types: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for instr in &instructions {
        if instr.boundary_hint.is_prologue() {
            prologue_count += 1;
            *prologue_types.entry(format!("{:?}", instr.boundary_hint)).or_insert(0) += 1;
        }
        if instr.boundary_hint.is_epilogue() {
            epilogue_count += 1;
            *epilogue_types.entry(format!("{:?}", instr.boundary_hint)).or_insert(0) += 1;
        }
    }

    println!("Prologue hints: {}", prologue_count);
    for (hint_type, count) in &prologue_types {
        println!("  {}: {}", hint_type, count);
    }

    println!("\nEpilogue hints: {}", epilogue_count);
    for (hint_type, count) in &epilogue_types {
        println!("  {}: {}", hint_type, count);
    }

    // Show some example sequences
    println!("\n=== Example Prologue Sequences ===");
    let mut shown_prologues = 0;
    for (i, instr) in instructions.iter().enumerate() {
        if instr.boundary_hint == FunctionBoundaryHint::PrologueSaveFrame && shown_prologues < 3 {
            println!("\nPrologue at 0x{:x}:", instr.address);
            for j in i..std::cmp::min(i + 5, instructions.len()) {
                println!(
                    "  0x{:x}: {} [{:?}]",
                    instructions[j].address,
                    instructions[j].mnemonic,
                    instructions[j].boundary_hint
                );
            }
            shown_prologues += 1;
        }
    }

    println!("\n=== Example Epilogue Sequences ===");
    let mut shown_epilogues = 0;
    for (i, instr) in instructions.iter().enumerate() {
        if instr.boundary_hint == FunctionBoundaryHint::EpilogueReturn && shown_epilogues < 3 {
            // Show 5 instructions before ret
            let start = if i >= 4 { i - 4 } else { 0 };
            println!("\nEpilogue ending at 0x{:x}:", instr.address);
            for j in start..=i {
                println!(
                    "  0x{:x}: {} [{:?}]",
                    instructions[j].address,
                    instructions[j].mnemonic,
                    instructions[j].boundary_hint
                );
            }
            shown_epilogues += 1;
        }
    }

    // Basic validation
    assert!(prologue_count > 0, "Should detect at least some prologues");
    assert!(epilogue_count > 0, "Should detect at least some epilogues");
}

#[test]
fn test_boundary_distribution_across_binaries() {
    if !corpus_available() {
        return;
    }

    println!("\n=== BOUNDARY DISTRIBUTION ACROSS BINARIES ===\n");

    let binaries = vec![
        "train_loops",
        "train_functions",
        "test_mixed",
        "test_novel",
    ];

    for name in binaries {
        let path = format!("{}/{}", CORPUS_DIR, name);
        let instructions = disassemble_binary(&path);

        let prologues = instructions.iter().filter(|i| i.boundary_hint.is_prologue()).count();
        let epilogues = instructions.iter().filter(|i| i.boundary_hint.is_epilogue()).count();
        let total = instructions.len();

        println!(
            "{}: {} inst, {} prologues ({:.1}%), {} epilogues ({:.1}%)",
            name,
            total,
            prologues,
            100.0 * prologues as f64 / total as f64,
            epilogues,
            100.0 * epilogues as f64 / total as f64
        );
    }
}

#[test]
fn test_boundary_encoding_in_sdr() {
    use bond::encoding::instruction_encoder::InstructionEncoder;
    use bond::disasm::features::{
        FlowControlType, MemoryAccessPattern, OpcodeCategory, OperandPattern, RegisterCategory,
    };

    let encoder = InstructionEncoder::new();

    // Create instructions with different boundary hints
    let make_instr = |hint: FunctionBoundaryHint| -> DecodedInstruction {
        DecodedInstruction {
            address: 0x1000,
            length: 3,
            opcode_category: OpcodeCategory::Stack,
            mnemonic: "push".to_string(),
            operand_types: vec![],
            operand_pattern: OperandPattern::RegOnly,
            registers_read: vec![RegisterCategory::BasePointer],
            registers_written: vec![RegisterCategory::StackPointer],
            flow_control: FlowControlType::Sequential,
            memory_access: MemoryAccessPattern::StackAccess,
            has_immediate: false,
            boundary_hint: hint,
        }
    };

    let no_hint = make_instr(FunctionBoundaryHint::None);
    let prologue = make_instr(FunctionBoundaryHint::PrologueSaveFrame);
    let epilogue = make_instr(FunctionBoundaryHint::EpilogueRestoreFrame);

    let sdr_none = encoder.encode(&no_hint);
    let sdr_prologue = encoder.encode(&prologue);
    let sdr_epilogue = encoder.encode(&epilogue);

    let sparse_none = sdr_none.get_sparse();
    let sparse_prologue = sdr_prologue.get_sparse();
    let sparse_epilogue = sdr_epilogue.get_sparse();

    println!("\n=== BOUNDARY ENCODING TEST ===\n");
    println!("No hint:   {} active bits", sparse_none.len());
    println!("Prologue:  {} active bits", sparse_prologue.len());
    println!("Epilogue:  {} active bits", sparse_epilogue.len());

    // Prologue and epilogue should have more active bits than no hint
    assert!(
        sparse_prologue.len() > sparse_none.len(),
        "Prologue should have more active bits"
    );
    assert!(
        sparse_epilogue.len() > sparse_none.len(),
        "Epilogue should have more active bits"
    );

    // Prologue and epilogue SDRs should be different from each other
    assert_ne!(
        sparse_prologue, sparse_epilogue,
        "Prologue and epilogue should have different encodings"
    );

    println!("\nPrologue unique bits: {:?}", &sparse_prologue[sparse_prologue.len()-8..]);
    println!("Epilogue unique bits: {:?}", &sparse_epilogue[sparse_epilogue.len()-8..]);
}
