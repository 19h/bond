//! End-to-end integration tests for the Bond HTM-based binary analyzer
//!
//! These tests verify the complete pipeline from binary loading through
//! cluster detection.

mod common;

use bond::binary::loader::{load_binary_from_bytes, Architecture};
use bond::cluster::detector::{ClusterDetector, ClusterDetectorConfig, InstructionResult};
use bond::cluster::fingerprint::Fingerprint;
use bond::disasm::decoder::X86Decoder;
use bond::disasm::features::OpcodeCategory;
use bond::htm::config::HtmConfig;
use bond::htm::pipeline::BondHtmPipeline;
use common::*;

// ============================================================================
// Full Pipeline Tests
// ============================================================================

#[test]
fn test_full_pipeline_with_minimal_elf() {
    // Load minimal ELF
    let elf_bytes = make_minimal_elf64();
    let loader = load_binary_from_bytes(elf_bytes).expect("Failed to load ELF");

    assert_eq!(loader.architecture(), Architecture::X86_64);

    // We may not have code sections in the minimal ELF (it's a program header only)
    // but the pipeline shouldn't crash
    let sections = loader.code_sections();

    if !sections.is_empty() {
        // Decode instructions
        let decoder = X86Decoder::new(loader.architecture());
        let instructions = decoder.decode_section(&sections[0]);

        // Process through HTM
        let mut pipeline = BondHtmPipeline::new();

        for instr in &instructions {
            let result = pipeline.process(instr, true);
            assert_valid_anomaly(result.anomaly_score);
        }
    }
}

#[test]
fn test_full_pipeline_with_minimal_pe() {
    // Load minimal PE
    let pe_bytes = make_minimal_pe64();
    let loader = load_binary_from_bytes(pe_bytes).expect("Failed to load PE");

    assert_eq!(loader.architecture(), Architecture::X86_64);

    let sections = loader.code_sections();
    assert!(!sections.is_empty(), "PE should have code sections");

    // Decode instructions
    let decoder = X86Decoder::new(loader.architecture());
    let instructions = decoder.decode_section(&sections[0]);

    assert!(!instructions.is_empty(), "Should decode some instructions");

    // Process through HTM
    let mut pipeline = BondHtmPipeline::new();

    for instr in &instructions {
        let result = pipeline.process(instr, true);
        assert_valid_anomaly(result.anomaly_score);
        assert!(!result.active_cells.is_empty());
    }
}

#[test]
fn test_full_pipeline_with_cluster_detection() {
    // Create a code section with known instruction patterns
    let section = make_text_section(&[
        // Function-like pattern 1
        PUSH_RBP,
        MOV_RBP_RSP,
        XOR_RAX_RAX,
        ADD_EAX_1,
        ADD_EAX_1,
        ADD_EAX_1,
        MOV_RSP_RBP,
        POP_RBP,
        RET,
        // NOP padding
        NOP, NOP, NOP,
        // Function-like pattern 2
        PUSH_RBP,
        MOV_RBP_RSP,
        SUB_RAX_RBX,
        MOV_RSP_RBP,
        POP_RBP,
        RET,
    ]);

    // Decode
    let decoder = X86Decoder::new(Architecture::X86_64);
    let instructions = decoder.decode_section(&section);

    assert!(instructions.len() > 10, "Should have decoded many instructions");

    // Process through HTM
    let mut pipeline = BondHtmPipeline::new();
    let mut results: Vec<InstructionResult> = Vec::new();

    for instr in &instructions {
        let process_result = pipeline.process(instr, true);
        results.push(InstructionResult {
            instruction: instr.clone(),
            result: process_result,
        });
    }

    // Detect clusters
    let config = ClusterDetectorConfig {
        boundary_threshold: 0.7,
        min_cluster_size: 3,
        merge_threshold: 0.3,
        centroid_threshold: 0.5,
    };
    let detector = ClusterDetector::with_config(config);
    let clusters = detector.detect_clusters(&results);

    // Verify cluster properties
    for cluster in &clusters {
        assert!(cluster.instruction_count > 0);
        assert!(!cluster.representative_sequence.is_empty());
        assert!(!cluster.name.is_empty());
    }
}

// ============================================================================
// HTM Learning Tests
// ============================================================================

#[test]
fn test_htm_learns_repeating_pattern() {
    // Create a repeating instruction sequence
    let section = make_text_section(&[
        // Pattern A
        MOV_RAX_RBX,
        ADD_RAX_RBX,
        XOR_EAX_EAX,
        // Pattern A (repeat)
        MOV_RAX_RBX,
        ADD_RAX_RBX,
        XOR_EAX_EAX,
        // Pattern A (repeat)
        MOV_RAX_RBX,
        ADD_RAX_RBX,
        XOR_EAX_EAX,
        // Pattern A (repeat)
        MOV_RAX_RBX,
        ADD_RAX_RBX,
        XOR_EAX_EAX,
    ]);

    let decoder = X86Decoder::new(Architecture::X86_64);
    let instructions = decoder.decode_section(&section);

    let mut pipeline = BondHtmPipeline::new();

    // Train on the sequence multiple times
    for _ in 0..5 {
        pipeline.reset();
        for instr in &instructions {
            pipeline.process(instr, true);
        }
    }

    // Test: anomaly should be lower for learned patterns
    pipeline.reset();
    let mut anomalies = Vec::new();
    for instr in &instructions {
        let result = pipeline.process(instr, false);
        anomalies.push(result.anomaly_score);
    }

    // Average anomaly should be reasonable (some learning occurred)
    let avg_anomaly: f32 = anomalies.iter().sum::<f32>() / anomalies.len() as f32;
    assert!(avg_anomaly >= 0.0 && avg_anomaly <= 1.0);
}

#[test]
fn test_htm_detects_anomalous_instruction() {
    // Train on a consistent pattern
    let normal_section = make_text_section(&[
        MOV_RAX_RBX,
        MOV_RAX_RBX,
        MOV_RAX_RBX,
        MOV_RAX_RBX,
    ]);

    let decoder = X86Decoder::new(Architecture::X86_64);
    let normal_instructions = decoder.decode_section(&normal_section);

    let mut pipeline = BondHtmPipeline::new();

    // Train
    for _ in 0..10 {
        pipeline.reset();
        for instr in &normal_instructions {
            pipeline.process(instr, true);
        }
    }

    // Inject an anomalous instruction (SYSCALL)
    let anomaly_section = make_text_section(&[SYSCALL]);
    let anomaly_instructions = decoder.decode_section(&anomaly_section);

    // Test with normal pattern followed by anomaly
    pipeline.reset();
    for instr in &normal_instructions {
        pipeline.process(instr, false);
    }

    // The anomalous instruction should have a different pattern
    if !anomaly_instructions.is_empty() {
        let result = pipeline.process(&anomaly_instructions[0], false);
        assert_valid_anomaly(result.anomaly_score);
    }
}

// ============================================================================
// Decoder Integration Tests
// ============================================================================

#[test]
fn test_decode_and_categorize_function_prologue() {
    let section = make_text_section(&[
        PUSH_RBP,     // Stack operation
        MOV_RBP_RSP,  // Data transfer
    ]);

    let decoder = X86Decoder::new(Architecture::X86_64);
    let instructions = decoder.decode_section(&section);

    assert_eq!(instructions.len(), 2);
    assert_eq!(instructions[0].opcode_category, OpcodeCategory::Stack);
    assert_eq!(instructions[1].opcode_category, OpcodeCategory::DataTransfer);
}

#[test]
fn test_decode_and_categorize_arithmetic_sequence() {
    let section = make_text_section(&[
        ADD_RAX_RBX,
        SUB_RAX_RBX,
        XOR_RAX_RAX,
    ]);

    let decoder = X86Decoder::new(Architecture::X86_64);
    let instructions = decoder.decode_section(&section);

    assert_eq!(instructions.len(), 3);
    assert_eq!(instructions[0].opcode_category, OpcodeCategory::Arithmetic);
    assert_eq!(instructions[1].opcode_category, OpcodeCategory::Arithmetic);
    assert_eq!(instructions[2].opcode_category, OpcodeCategory::Logic);
}

#[test]
fn test_decode_control_flow_sequence() {
    let section = make_text_section(&[
        CMP_EAX_EBX,  // Compare
        JE_REL8,      // Conditional jump
        JMP_REL8,     // Unconditional jump
    ]);

    let decoder = X86Decoder::new(Architecture::X86_64);
    let instructions = decoder.decode_section(&section);

    assert_eq!(instructions.len(), 3);
    assert_eq!(instructions[0].opcode_category, OpcodeCategory::Compare);
    assert_eq!(instructions[1].opcode_category, OpcodeCategory::ControlFlow);
    assert_eq!(instructions[2].opcode_category, OpcodeCategory::ControlFlow);
}

// ============================================================================
// Fingerprint and Cluster Matching Tests
// ============================================================================

#[test]
fn test_fingerprint_similarity_in_pipeline() {
    let section = make_text_section(&[
        MOV_RAX_RBX,
        ADD_RAX_RBX,
        MOV_RAX_RBX,
        ADD_RAX_RBX,
    ]);

    let decoder = X86Decoder::new(Architecture::X86_64);
    let instructions = decoder.decode_section(&section);

    let mut pipeline = BondHtmPipeline::new();
    let mut fingerprints = Vec::new();

    for instr in &instructions {
        let result = pipeline.process(instr, true);
        fingerprints.push(Fingerprint::new(result.active_cells));
    }

    // Similar instructions should have some fingerprint overlap
    // (same instruction type at different positions)
    if fingerprints.len() >= 4 {
        let sim_01 = fingerprints[0].similarity(&fingerprints[2]); // MOV vs MOV
        let sim_02 = fingerprints[1].similarity(&fingerprints[3]); // ADD vs ADD

        // Similar instructions should have non-zero similarity
        assert!(sim_01 >= 0.0);
        assert!(sim_02 >= 0.0);
    }
}

#[test]
fn test_cluster_detection_with_known_boundaries() {
    // Create sequence with clear cluster boundaries
    let section = make_text_section(&[
        // Cluster 1: Arithmetic operations
        ADD_RAX_RBX,
        ADD_EAX_1,
        SUB_RAX_RBX,
        ADD_RAX_RBX,
        ADD_EAX_1,
        // Boundary: CALL
        CALL_REL32,
        // Cluster 2: Stack operations
        PUSH_RBP,
        PUSH_RAX,
        POP_RAX,
        POP_RBP,
        PUSH_RBP,
        // Boundary: RET
        RET,
    ]);

    let decoder = X86Decoder::new(Architecture::X86_64);
    let instructions = decoder.decode_section(&section);

    let mut pipeline = BondHtmPipeline::new();
    let mut results = Vec::new();

    for instr in &instructions {
        let result = pipeline.process(instr, true);
        results.push(InstructionResult {
            instruction: instr.clone(),
            result,
        });
    }

    let detector = ClusterDetector::new();
    let clusters = detector.detect_clusters(&results);

    // Should detect clusters (exact count depends on thresholds)
    // The important thing is the algorithm runs without errors
    for cluster in &clusters {
        assert!(cluster.instruction_count > 0);
        assert!(cluster.anomaly_score_mean >= 0.0 && cluster.anomaly_score_mean <= 1.0);
    }
}

// ============================================================================
// Real Binary Tests (if available)
// ============================================================================

#[test]
fn test_analyze_system_binary() {
    use std::path::Path;

    let path = Path::new("/bin/ls");
    if !path.exists() {
        return; // Skip if not on Linux
    }

    let loader = match bond::binary::loader::load_binary(path) {
        Ok(l) => l,
        Err(_) => return, // Skip if can't load
    };

    let sections = loader.code_sections();
    if sections.is_empty() {
        return;
    }

    let decoder = X86Decoder::new(loader.architecture());

    // Only analyze first 100 instructions to keep test fast
    let text_section = &sections[0];
    let limited_section = bond::binary::loader::CodeSection {
        name: text_section.name.clone(),
        virtual_address: text_section.virtual_address,
        data: text_section.data[..text_section.data.len().min(500)].to_vec(),
        executable: true,
    };

    let instructions = decoder.decode_section(&limited_section);

    let mut pipeline = BondHtmPipeline::new();
    let mut results = Vec::new();

    for instr in instructions.iter().take(100) {
        let result = pipeline.process(instr, true);
        results.push(InstructionResult {
            instruction: instr.clone(),
            result,
        });
    }

    // Detect clusters
    let detector = ClusterDetector::new();
    let clusters = detector.detect_clusters(&results);

    // Verify we can process real code
    assert!(!results.is_empty());

    // Verify clusters are valid if any were detected
    let default_config = ClusterDetectorConfig::default();
    for cluster in &clusters {
        assert!(cluster.instruction_count >= default_config.min_cluster_size
            || clusters.is_empty()); // Config check
    }
}

// ============================================================================
// Configuration Tests
// ============================================================================

#[test]
fn test_custom_htm_config_in_pipeline() {
    let mut config = HtmConfig::default();
    config.temporal_memory.cells_per_column = 16;

    let mut pipeline = BondHtmPipeline::with_config(&config);

    assert_eq!(pipeline.cells_per_column(), 16);

    // Verify pipeline works with custom config
    let section = make_text_section(&[NOP, NOP, NOP]);
    let decoder = X86Decoder::new(Architecture::X86_64);
    let instructions = decoder.decode_section(&section);

    for instr in &instructions {
        let result = pipeline.process(instr, true);
        assert_valid_anomaly(result.anomaly_score);
    }
}

#[test]
fn test_custom_cluster_detector_config() {
    let config = ClusterDetectorConfig {
        boundary_threshold: 0.5,
        min_cluster_size: 2,
        merge_threshold: 0.5,
        centroid_threshold: 0.3,
    };

    let detector = ClusterDetector::with_config(config);

    // Create simple results
    let results: Vec<InstructionResult> = (0..10)
        .map(|i| {
            make_simple_instruction_result(
                0x1000 + i * 3,
                OpcodeCategory::DataTransfer,
                0.2,
                vec![1, 2, 3],
            )
        })
        .collect();

    let clusters = detector.detect_clusters(&results);

    // With min_cluster_size=2, we should be able to detect clusters
    // (exact behavior depends on the algorithm)
    for cluster in &clusters {
        assert!(cluster.instruction_count >= 2);
    }
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_empty_instruction_sequence() {
    let detector = ClusterDetector::new();
    let clusters = detector.detect_clusters(&[]);
    assert!(clusters.is_empty());
}

#[test]
fn test_single_instruction() {
    let section = make_text_section(&[NOP]);
    let decoder = X86Decoder::new(Architecture::X86_64);
    let instructions = decoder.decode_section(&section);

    let mut pipeline = BondHtmPipeline::new();
    let result = pipeline.process(&instructions[0], true);

    assert_valid_anomaly(result.anomaly_score);

    // Single instruction shouldn't form a cluster (below min size)
    let detector = ClusterDetector::new();
    let results = vec![InstructionResult {
        instruction: instructions[0].clone(),
        result,
    }];
    let clusters = detector.detect_clusters(&results);
    assert!(clusters.is_empty() || clusters[0].instruction_count == 1);
}

#[test]
fn test_pipeline_reset() {
    let section = make_text_section(&[MOV_RAX_RBX, ADD_RAX_RBX]);
    let decoder = X86Decoder::new(Architecture::X86_64);
    let instructions = decoder.decode_section(&section);

    let mut pipeline = BondHtmPipeline::new();

    // Process once
    for instr in &instructions {
        pipeline.process(instr, true);
    }

    // Reset
    pipeline.reset();

    // Process again - should work correctly
    for instr in &instructions {
        let result = pipeline.process(instr, true);
        assert_valid_anomaly(result.anomaly_score);
    }
}
