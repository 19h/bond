// Debug cluster detection

use bond::binary::loader::load_binary;
use bond::cluster::detector::{ClusterDetector, InstructionResult};
use bond::disasm::decoder::X86Decoder;
use bond::disasm::features::{DecodedInstruction, FlowControlType};
use bond::htm::pipeline::BondHtmPipeline;
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
fn debug_boundary_detection() {
    if !corpus_available() {
        return;
    }

    println!("\n=== BOUNDARY DETECTION DEBUG ===\n");

    let mut pipeline = BondHtmPipeline::new();

    // Process just train_loops
    let path = format!("{}/train_loops", CORPUS_DIR);
    let instructions = disassemble_binary(&path);

    println!("train_loops: {} instructions", instructions.len());

    // Count potential boundaries
    let mut call_count = 0;
    let mut ret_count = 0;
    let mut jmp_count = 0;

    let mut results: Vec<InstructionResult> = Vec::new();
    let mut prev_anomaly = 0.0f32;
    let mut anomaly_spikes = 0;

    for inst in &instructions {
        match inst.flow_control {
            FlowControlType::Call => call_count += 1,
            FlowControlType::Return => ret_count += 1,
            FlowControlType::UnconditionalJump => jmp_count += 1,
            _ => {}
        }

        let htm_result = pipeline.process(inst, true);

        // Check for anomaly spike
        if htm_result.anomaly_score > 0.01 && htm_result.anomaly_score > prev_anomaly * 5.0 {
            anomaly_spikes += 1;
        }

        prev_anomaly = htm_result.anomaly_score;

        results.push(InstructionResult {
            instruction: inst.clone(),
            result: htm_result,
        });
    }

    println!("  CALL instructions: {}", call_count);
    println!("  RET instructions: {}", ret_count);
    println!("  JMP instructions: {}", jmp_count);
    println!("  Anomaly spikes: {}", anomaly_spikes);
    println!("  Expected boundaries: ~{}", call_count + ret_count + jmp_count + anomaly_spikes);

    // Now run cluster detection
    let detector = ClusterDetector::new();
    let clusters = detector.detect_clusters(&results);

    println!("\n  Clusters detected: {}", clusters.len());
    for cluster in clusters.iter().take(10) {
        println!(
            "    Cluster {}: {} instructions at 0x{:x}, {:?}",
            cluster.id,
            cluster.instruction_count,
            cluster.start_addresses[0],
            cluster.dominant_category
        );
    }
}

#[test]
fn debug_fingerprint_similarity() {
    if !corpus_available() {
        return;
    }

    println!("\n=== FINGERPRINT SIMILARITY DEBUG ===\n");

    let mut pipeline = BondHtmPipeline::new();

    let path = format!("{}/train_loops", CORPUS_DIR);
    let instructions = disassemble_binary(&path);

    // Collect fingerprints at each instruction
    let mut similarities_to_prev = Vec::new();
    let mut prev_cells: Option<Vec<u32>> = None;

    for inst in instructions.iter().take(50) {
        let result = pipeline.process(inst, true);

        if let Some(ref prev) = prev_cells {
            let prev_fp = bond::cluster::fingerprint::Fingerprint::new(prev.clone());
            let curr_fp = bond::cluster::fingerprint::Fingerprint::new(result.active_cells.clone());
            let sim = prev_fp.similarity(&curr_fp);
            similarities_to_prev.push(sim);
        }

        prev_cells = Some(result.active_cells.clone());
    }

    println!("Fingerprint similarity to previous instruction (first 50):");
    let below_03 = similarities_to_prev.iter().filter(|&&s| s < 0.3).count();
    let below_05 = similarities_to_prev.iter().filter(|&&s| s < 0.5).count();
    let below_07 = similarities_to_prev.iter().filter(|&&s| s < 0.7).count();
    let avg: f64 = similarities_to_prev.iter().sum::<f64>() / similarities_to_prev.len() as f64;

    println!("  Average: {:.4}", avg);
    println!("  Below 0.3: {} ({:.1}%)", below_03, 100.0 * below_03 as f64 / similarities_to_prev.len() as f64);
    println!("  Below 0.5: {} ({:.1}%)", below_05, 100.0 * below_05 as f64 / similarities_to_prev.len() as f64);
    println!("  Below 0.7: {} ({:.1}%)", below_07, 100.0 * below_07 as f64 / similarities_to_prev.len() as f64);

    // Show first few
    println!("\n  First 10 similarities:");
    for (i, sim) in similarities_to_prev.iter().take(10).enumerate() {
        println!("    [{}]: {:.4}", i+1, sim);
    }
}
