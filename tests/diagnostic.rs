// Diagnostic test to understand why HTM isn't discriminating patterns

use bond::binary::loader::load_binary;
use bond::cluster::fingerprint::Fingerprint;
use bond::disasm::decoder::X86Decoder;
use bond::disasm::features::DecodedInstruction;
use bond::encoding::instruction_encoder::InstructionEncoder;
use bond::htm::pipeline::BondHtmPipeline;
use std::collections::HashMap;
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
fn diagnose_encoding_diversity() {
    if !corpus_available() {
        return;
    }

    let encoder = InstructionEncoder::new();

    println!("\n=== ENCODING DIVERSITY DIAGNOSTIC ===\n");

    // Check how many unique SDRs we get per binary
    for name in &["train_loops", "train_math", "test_mixed", "test_novel"] {
        let path = format!("{}/{}", CORPUS_DIR, name);
        let instructions = disassemble_binary(&path);

        let mut unique_sdrs: HashMap<Vec<u32>, usize> = HashMap::new();
        let mut total_active_bits = 0usize;

        for inst in &instructions {
            let sdr = encoder.encode(inst);
            let sparse = sdr.get_sparse().to_vec();
            total_active_bits += sparse.len();
            *unique_sdrs.entry(sparse).or_insert(0) += 1;
        }

        let avg_active = total_active_bits as f64 / instructions.len() as f64;
        let most_common = unique_sdrs.values().max().unwrap_or(&0);

        println!(
            "{}: {} instructions -> {} unique SDRs ({:.1}% unique)",
            name,
            instructions.len(),
            unique_sdrs.len(),
            100.0 * unique_sdrs.len() as f64 / instructions.len() as f64
        );
        println!(
            "  Average active bits: {:.1}, Most repeated encoding: {} times",
            avg_active, most_common
        );
    }
}

#[test]
fn diagnose_anomaly_distribution() {
    if !corpus_available() {
        return;
    }

    println!("\n=== ANOMALY DISTRIBUTION DIAGNOSTIC ===\n");

    let mut pipeline = BondHtmPipeline::new();

    // Train on just ONE binary
    let train_path = format!("{}/train_loops", CORPUS_DIR);
    let train_instructions = disassemble_binary(&train_path);

    println!("Training on train_loops ({} instructions)...", train_instructions.len());

    let mut train_anomalies = Vec::new();
    for inst in &train_instructions {
        let result = pipeline.process(inst, true);
        train_anomalies.push(result.anomaly_score);
    }

    // Analyze training anomalies
    let train_avg: f32 = train_anomalies.iter().sum::<f32>() / train_anomalies.len() as f32;
    let train_high = train_anomalies.iter().filter(|&&a| a > 0.5).count();
    let train_zero = train_anomalies.iter().filter(|&&a| a < 0.01).count();

    println!("\nTraining anomalies:");
    println!("  Average: {:.4}", train_avg);
    println!("  High (>0.5): {} ({:.1}%)", train_high, 100.0 * train_high as f64 / train_anomalies.len() as f64);
    println!("  Zero (<0.01): {} ({:.1}%)", train_zero, 100.0 * train_zero as f64 / train_anomalies.len() as f64);

    // Now test on different binaries WITHOUT resetting
    for name in &["train_loops", "train_math", "test_mixed", "test_novel"] {
        let path = format!("{}/{}", CORPUS_DIR, name);
        let instructions = disassemble_binary(&path);

        pipeline.reset(); // Reset temporal context but keep learned patterns

        let mut anomalies = Vec::new();
        for inst in &instructions {
            let result = pipeline.process(inst, false); // No learning
            anomalies.push(result.anomaly_score);
        }

        let avg: f32 = anomalies.iter().sum::<f32>() / anomalies.len() as f32;
        let high = anomalies.iter().filter(|&&a| a > 0.5).count();
        let zero = anomalies.iter().filter(|&&a| a < 0.01).count();

        println!("\n{} (after training):", name);
        println!("  Average anomaly: {:.4}", avg);
        println!("  High (>0.5): {} ({:.1}%)", high, 100.0 * high as f64 / anomalies.len() as f64);
        println!("  Zero (<0.01): {} ({:.1}%)", zero, 100.0 * zero as f64 / anomalies.len() as f64);
    }
}

#[test]
fn diagnose_fingerprint_diversity() {
    if !corpus_available() {
        return;
    }

    println!("\n=== FINGERPRINT DIVERSITY DIAGNOSTIC ===\n");

    let mut pipeline = BondHtmPipeline::new();

    // Process one binary and look at fingerprints
    let path = format!("{}/train_loops", CORPUS_DIR);
    let instructions = disassemble_binary(&path);

    let mut fingerprints: Vec<Fingerprint> = Vec::new();

    for inst in instructions.iter().take(100) {
        let result = pipeline.process(inst, true);
        fingerprints.push(Fingerprint::new(result.active_cells.clone()));
    }

    // Check fingerprint sizes
    let sizes: Vec<usize> = fingerprints.iter().map(|f| f.size()).collect();
    let avg_size: f64 = sizes.iter().sum::<usize>() as f64 / sizes.len() as f64;
    let min_size = *sizes.iter().min().unwrap_or(&0);
    let max_size = *sizes.iter().max().unwrap_or(&0);

    println!("Fingerprint sizes (first 100 instructions):");
    println!("  Average: {:.1}", avg_size);
    println!("  Min: {}, Max: {}", min_size, max_size);

    // Check pairwise similarities
    let mut similarities = Vec::new();
    for i in 0..fingerprints.len() {
        for j in i + 1..fingerprints.len() {
            similarities.push(fingerprints[i].similarity(&fingerprints[j]));
        }
    }

    let avg_sim: f64 = similarities.iter().sum::<f64>() / similarities.len() as f64;
    let min_sim = similarities.iter().cloned().fold(1.0, f64::min);
    let max_sim = similarities.iter().cloned().fold(0.0, f64::max);
    let high_sim = similarities.iter().filter(|&&s| s > 0.5).count();

    println!("\nPairwise fingerprint similarities:");
    println!("  Average: {:.4}", avg_sim);
    println!("  Min: {:.4}, Max: {:.4}", min_sim, max_sim);
    println!(
        "  High (>0.5): {} ({:.1}%)",
        high_sim,
        100.0 * high_sim as f64 / similarities.len() as f64
    );
}

#[test]
fn diagnose_what_htm_sees() {
    if !corpus_available() {
        return;
    }

    println!("\n=== WHAT HTM ACTUALLY SEES ===\n");

    let encoder = InstructionEncoder::new();

    // Compare specific instruction types across binaries
    let train_path = format!("{}/train_loops", CORPUS_DIR);
    let novel_path = format!("{}/test_novel", CORPUS_DIR);

    let train_instructions = disassemble_binary(&train_path);
    let novel_instructions = disassemble_binary(&novel_path);

    // Find some specific instruction types
    let train_movs: Vec<_> = train_instructions.iter().filter(|i| i.mnemonic.starts_with("mov")).take(5).collect();
    let novel_movs: Vec<_> = novel_instructions.iter().filter(|i| i.mnemonic.starts_with("mov")).take(5).collect();

    println!("Comparing MOV instructions:");
    println!("(showing mnemonic, operand_types, registers_read, registers_written)\n");

    for (i, inst) in train_movs.iter().enumerate() {
        let sdr = encoder.encode(inst);
        println!(
            "  train MOV {}: {} bits, mnem='{}', ops={:?}, read={:?}, write={:?}",
            i,
            sdr.get_sparse().len(),
            inst.mnemonic,
            inst.operand_types,
            inst.registers_read,
            inst.registers_written
        );
    }
    println!();
    for (i, inst) in novel_movs.iter().enumerate() {
        let sdr = encoder.encode(inst);
        println!(
            "  novel MOV {}: {} bits, mnem='{}', ops={:?}, read={:?}, write={:?}",
            i,
            sdr.get_sparse().len(),
            inst.mnemonic,
            inst.operand_types,
            inst.registers_read,
            inst.registers_written
        );
    }

    // Check if similar instructions get similar encodings
    if !train_movs.is_empty() && !novel_movs.is_empty() {
        let train_sdr = encoder.encode(train_movs[0]);
        let novel_sdr = encoder.encode(novel_movs[0]);

        let train_sparse = train_sdr.get_sparse().to_vec();
        let novel_sparse = novel_sdr.get_sparse().to_vec();

        let train_set: std::collections::HashSet<_> = train_sparse.iter().collect();
        let novel_set: std::collections::HashSet<_> = novel_sparse.iter().collect();

        let intersection = train_set.intersection(&novel_set).count();
        let union = train_set.union(&novel_set).count();
        let jaccard = intersection as f64 / union as f64;

        println!("\nFirst MOV encoding similarity (Jaccard): {:.4}", jaccard);
    }
}

#[test]
fn diagnose_mnemonic_distribution() {
    if !corpus_available() {
        return;
    }

    println!("\n=== MNEMONIC DISTRIBUTION ===\n");

    for name in &["train_loops", "test_novel"] {
        let path = format!("{}/{}", CORPUS_DIR, name);
        let instructions = disassemble_binary(&path);

        let mut mnemonic_counts: HashMap<String, usize> = HashMap::new();
        for inst in &instructions {
            // Get base mnemonic (without size suffix)
            let base = inst.mnemonic.split_whitespace().next().unwrap_or(&inst.mnemonic);
            *mnemonic_counts.entry(base.to_string()).or_insert(0) += 1;
        }

        let mut sorted: Vec<_> = mnemonic_counts.into_iter().collect();
        sorted.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

        println!("{} top mnemonics:", name);
        for (mnem, count) in sorted.iter().take(10) {
            println!("  {}: {} ({:.1}%)", mnem, count, 100.0 * *count as f64 / instructions.len() as f64);
        }
        println!();
    }
}
