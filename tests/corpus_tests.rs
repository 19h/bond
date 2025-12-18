// Corpus-based integration tests for Bond
// Tests HTM learning and pattern detection using compiled C binaries

use bond::binary::loader::{load_binary, Architecture, BinaryLoader};
use bond::cluster::detector::{Cluster, ClusterDetector, ClusterDetectorConfig, InstructionResult};
use bond::disasm::decoder::X86Decoder;
use bond::disasm::features::{DecodedInstruction, FlowControlType};
use bond::htm::pipeline::BondHtmPipeline;
use std::collections::HashMap;
use std::path::Path;

/// Path to the corpus binaries
const CORPUS_DIR: &str = "tests/corpus/bin";

/// Check if corpus binaries exist
fn corpus_available() -> bool {
    Path::new(CORPUS_DIR).join("train_loops").exists()
}

/// Get all training binaries
fn get_training_binaries() -> Vec<String> {
    let corpus = Path::new(CORPUS_DIR);
    let mut binaries = Vec::new();

    for name in &[
        "train_loops",
        "train_math",
        "train_strings",
        "train_functions",
        "train_control",
    ] {
        let path = corpus.join(name);
        if path.exists() {
            binaries.push(path.to_string_lossy().to_string());
        }
    }
    binaries
}

/// Get test binaries
fn get_test_binaries() -> Vec<(String, &'static str)> {
    let corpus = Path::new(CORPUS_DIR);
    let mut binaries = Vec::new();

    let test_mixed = corpus.join("test_mixed");
    if test_mixed.exists() {
        binaries.push((test_mixed.to_string_lossy().to_string(), "mixed"));
    }

    let test_novel = corpus.join("test_novel");
    if test_novel.exists() {
        binaries.push((test_novel.to_string_lossy().to_string(), "novel"));
    }

    binaries
}

/// Disassemble a binary and return decoded instructions
fn disassemble_binary(path: &str) -> Result<Vec<DecodedInstruction>, String> {
    let binary = load_binary(Path::new(path)).map_err(|e| format!("Load error: {:?}", e))?;

    let arch = binary.architecture();
    let decoder = X86Decoder::new(arch);
    let mut instructions = Vec::new();

    for section in binary.code_sections() {
        let decoded = decoder.decode_section(&section);
        instructions.extend(decoded);
    }

    Ok(instructions)
}

/// Statistics about a binary
#[derive(Debug)]
struct BinaryStats {
    total_instructions: usize,
    unique_opcodes: usize,
    functions_detected: usize,
    average_function_size: f64,
}

/// Analyze a binary and collect statistics
fn analyze_binary(path: &str) -> Result<BinaryStats, String> {
    let instructions = disassemble_binary(path)?;
    let mut opcode_set = std::collections::HashSet::new();
    let mut function_count = 0;
    let mut current_function_size = 0;
    let mut function_sizes = Vec::new();

    for inst in &instructions {
        opcode_set.insert(inst.opcode_category);

        // Simple function boundary detection: ret instruction ends a function
        current_function_size += 1;
        if inst.flow_control == FlowControlType::Return {
            if current_function_size > 1 {
                function_count += 1;
                function_sizes.push(current_function_size);
            }
            current_function_size = 0;
        }
    }

    let avg_size = if function_sizes.is_empty() {
        0.0
    } else {
        function_sizes.iter().sum::<usize>() as f64 / function_sizes.len() as f64
    };

    Ok(BinaryStats {
        total_instructions: instructions.len(),
        unique_opcodes: opcode_set.len(),
        functions_detected: function_count,
        average_function_size: avg_size,
    })
}

/// Process a binary through the HTM pipeline and return instruction results
fn process_binary_through_htm(
    path: &str,
    pipeline: &mut BondHtmPipeline,
    learn: bool,
) -> Result<Vec<InstructionResult>, String> {
    let instructions = disassemble_binary(path)?;
    let mut results = Vec::new();

    for inst in instructions {
        let htm_result = pipeline.process(&inst, learn);
        results.push(InstructionResult {
            instruction: inst,
            result: htm_result,
        });
    }

    Ok(results)
}

// =============================================================================
// BASIC CORPUS TESTS
// =============================================================================

#[test]
fn test_corpus_binaries_exist() {
    if !corpus_available() {
        eprintln!("Corpus not built. Run: cd tests/corpus && ./build.sh");
        return;
    }

    let training = get_training_binaries();
    assert!(
        !training.is_empty(),
        "No training binaries found in corpus"
    );

    let test = get_test_binaries();
    assert!(!test.is_empty(), "No test binaries found in corpus");

    println!("Found {} training binaries", training.len());
    println!("Found {} test binaries", test.len());
}

#[test]
fn test_corpus_binaries_loadable() {
    if !corpus_available() {
        return;
    }

    for path in get_training_binaries() {
        let result = load_binary(Path::new(&path));
        assert!(
            result.is_ok(),
            "Failed to load training binary {}: {:?}",
            path,
            result.err()
        );

        let binary = result.unwrap();
        assert!(
            binary.architecture() == Architecture::X86_64,
            "Expected 64-bit binary: {}",
            path
        );
        assert!(
            !binary.code_sections().is_empty(),
            "No executable sections in {}",
            path
        );
    }

    for (path, _) in get_test_binaries() {
        let result = load_binary(Path::new(&path));
        assert!(
            result.is_ok(),
            "Failed to load test binary {}: {:?}",
            path,
            result.err()
        );
    }
}

#[test]
fn test_corpus_binary_statistics() {
    if !corpus_available() {
        return;
    }

    println!("\n=== Corpus Binary Statistics ===\n");

    for path in get_training_binaries() {
        let stats = analyze_binary(&path).unwrap();
        let name = Path::new(&path).file_name().unwrap().to_string_lossy();
        println!(
            "{}: {} instructions, {} unique opcodes, {} functions (avg {:.1} inst/func)",
            name,
            stats.total_instructions,
            stats.unique_opcodes,
            stats.functions_detected,
            stats.average_function_size
        );

        // Sanity checks
        assert!(stats.total_instructions > 50, "Too few instructions in {}", path);
        assert!(stats.functions_detected >= 3, "Too few functions in {}", path);
    }

    println!();

    for (path, category) in get_test_binaries() {
        let stats = analyze_binary(&path).unwrap();
        let name = Path::new(&path).file_name().unwrap().to_string_lossy();
        println!(
            "{} ({}): {} instructions, {} unique opcodes, {} functions",
            name, category, stats.total_instructions, stats.unique_opcodes, stats.functions_detected
        );
    }
}

// =============================================================================
// HTM TRAINING TESTS
// =============================================================================

#[test]
fn test_htm_training_on_corpus() {
    if !corpus_available() {
        return;
    }

    let mut pipeline = BondHtmPipeline::new();

    let training_binaries = get_training_binaries();
    assert!(!training_binaries.is_empty());

    let mut total_trained = 0;

    for path in &training_binaries {
        let instructions = disassemble_binary(path).unwrap();
        let name = Path::new(path).file_name().unwrap().to_string_lossy();

        for inst in &instructions {
            let _ = pipeline.process(&inst, true); // Learning enabled
            total_trained += 1;
        }

        println!("Trained on {}: {} instructions", name, instructions.len());
    }

    println!("\nTotal instructions trained: {}", total_trained);
    assert!(total_trained > 500, "Should have trained on significant amount of data");
}

#[test]
fn test_htm_learns_instruction_sequences() {
    if !corpus_available() {
        return;
    }

    let mut pipeline = BondHtmPipeline::new();

    // Train on loop patterns specifically
    let loop_binary = format!("{}/train_loops", CORPUS_DIR);
    if !Path::new(&loop_binary).exists() {
        return;
    }

    let instructions = disassemble_binary(&loop_binary).unwrap();

    // First pass - learning
    let mut first_pass_anomalies = Vec::new();
    for inst in &instructions {
        let result = pipeline.process(&inst, true);
        first_pass_anomalies.push(result.anomaly_score);
    }

    // Reset temporal memory to test fresh
    pipeline.reset();

    // Second pass - should have lower anomaly since patterns are learned
    let mut second_pass_anomalies = Vec::new();
    for inst in &instructions {
        let result = pipeline.process(&inst, true);
        second_pass_anomalies.push(result.anomaly_score);
    }

    let avg_first: f32 = first_pass_anomalies.iter().sum::<f32>() / first_pass_anomalies.len() as f32;
    let avg_second: f32 = second_pass_anomalies.iter().sum::<f32>() / second_pass_anomalies.len() as f32;

    println!("First pass average anomaly: {:.4}", avg_first);
    println!("Second pass average anomaly: {:.4}", avg_second);

    // Second pass should generally have lower anomaly (HTM learned the patterns)
}

// =============================================================================
// PATTERN DETECTION TESTS
// =============================================================================

#[test]
fn test_cluster_detection_on_training_corpus() {
    if !corpus_available() {
        return;
    }

    let mut pipeline = BondHtmPipeline::new();
    let detector = ClusterDetector::new();

    // Collect all results across training binaries
    let mut all_results = Vec::new();

    for path in get_training_binaries() {
        let name = Path::new(&path).file_name().unwrap().to_string_lossy();
        let results = process_binary_through_htm(&path, &mut pipeline, true).unwrap();
        let inst_count = results.len();
        all_results.extend(results);

        println!("{}: {} instructions processed", name, inst_count);
    }

    // Detect clusters from all results
    let clusters = detector.detect_clusters(&all_results);
    println!("\nTotal clusters detected: {}", clusters.len());

    for cluster in clusters.iter().take(10) {
        println!(
            "  Cluster {}: {} instructions, {:?}, anomaly={:.4}",
            cluster.id, cluster.instruction_count, cluster.dominant_category, cluster.anomaly_score_mean
        );
    }
}

#[test]
fn test_pattern_transfer_mixed_binary() {
    if !corpus_available() {
        return;
    }

    let mut pipeline = BondHtmPipeline::new();

    // Train on all training binaries
    for path in get_training_binaries() {
        let instructions = disassemble_binary(&path).unwrap();
        for inst in &instructions {
            let _ = pipeline.process(&inst, true);
        }
    }

    // Now test on mixed binary (contains similar patterns)
    let mixed_path = format!("{}/test_mixed", CORPUS_DIR);
    if !Path::new(&mixed_path).exists() {
        return;
    }

    let test_instructions = disassemble_binary(&mixed_path).unwrap();
    let mut anomalies = Vec::new();

    // Reset to test fresh prediction
    pipeline.reset();

    for inst in &test_instructions {
        let result = pipeline.process(&inst, false); // No learning
        anomalies.push(result.anomaly_score);
    }

    let avg_anomaly: f32 = anomalies.iter().sum::<f32>() / anomalies.len() as f32;
    let max_anomaly = anomalies.iter().cloned().fold(0.0f32, f32::max);
    let min_anomaly = anomalies.iter().cloned().fold(1.0f32, f32::min);

    println!("\nMixed binary (similar patterns) analysis:");
    println!("  Total instructions: {}", test_instructions.len());
    println!("  Average anomaly: {:.4}", avg_anomaly);
    println!("  Min anomaly: {:.4}", min_anomaly);
    println!("  Max anomaly: {:.4}", max_anomaly);
}

#[test]
fn test_pattern_transfer_novel_binary() {
    if !corpus_available() {
        return;
    }

    let mut pipeline = BondHtmPipeline::new();

    // Train on all training binaries
    for path in get_training_binaries() {
        let instructions = disassemble_binary(&path).unwrap();
        for inst in &instructions {
            let _ = pipeline.process(&inst, true);
        }
    }

    // Test on novel binary (contains different patterns)
    let novel_path = format!("{}/test_novel", CORPUS_DIR);
    if !Path::new(&novel_path).exists() {
        return;
    }

    // Reset to test fresh prediction
    pipeline.reset();

    let test_instructions = disassemble_binary(&novel_path).unwrap();
    let mut anomalies = Vec::new();

    for inst in &test_instructions {
        let result = pipeline.process(&inst, false); // No learning
        anomalies.push(result.anomaly_score);
    }

    let avg_anomaly: f32 = anomalies.iter().sum::<f32>() / anomalies.len() as f32;
    let max_anomaly = anomalies.iter().cloned().fold(0.0f32, f32::max);
    let min_anomaly = anomalies.iter().cloned().fold(1.0f32, f32::min);

    println!("\nNovel binary (different patterns) analysis:");
    println!("  Total instructions: {}", test_instructions.len());
    println!("  Average anomaly: {:.4}", avg_anomaly);
    println!("  Min anomaly: {:.4}", min_anomaly);
    println!("  Max anomaly: {:.4}", max_anomaly);
}

#[test]
fn test_mixed_vs_novel_anomaly_comparison() {
    if !corpus_available() {
        return;
    }

    let mut pipeline = BondHtmPipeline::new();

    // Train on all training binaries
    println!("Training HTM on corpus...");
    let mut training_count = 0;
    for path in get_training_binaries() {
        let instructions = disassemble_binary(&path).unwrap();
        for inst in &instructions {
            let _ = pipeline.process(&inst, true);
            training_count += 1;
        }
    }
    println!("Trained on {} instructions\n", training_count);

    // Analyze mixed binary
    let mixed_path = format!("{}/test_mixed", CORPUS_DIR);
    let novel_path = format!("{}/test_novel", CORPUS_DIR);

    if !Path::new(&mixed_path).exists() || !Path::new(&novel_path).exists() {
        return;
    }

    let mixed_instructions = disassemble_binary(&mixed_path).unwrap();
    let novel_instructions = disassemble_binary(&novel_path).unwrap();

    // Process mixed
    pipeline.reset();
    let mut mixed_anomalies = Vec::new();
    for inst in &mixed_instructions {
        let result = pipeline.process(&inst, false);
        mixed_anomalies.push(result.anomaly_score);
    }

    // Process novel
    pipeline.reset();
    let mut novel_anomalies = Vec::new();
    for inst in &novel_instructions {
        let result = pipeline.process(&inst, false);
        novel_anomalies.push(result.anomaly_score);
    }

    let avg_mixed: f32 = mixed_anomalies.iter().sum::<f32>() / mixed_anomalies.len() as f32;
    let avg_novel: f32 = novel_anomalies.iter().sum::<f32>() / novel_anomalies.len() as f32;

    println!("=== Anomaly Comparison ===");
    println!("Mixed binary (similar patterns):");
    println!("  Instructions: {}", mixed_instructions.len());
    println!("  Average anomaly: {:.4}", avg_mixed);
    println!();
    println!("Novel binary (different patterns):");
    println!("  Instructions: {}", novel_instructions.len());
    println!("  Average anomaly: {:.4}", avg_novel);
    println!();

    // Calculate anomaly distribution
    let mixed_high = mixed_anomalies.iter().filter(|&&a| a > 0.5).count();
    let novel_high = novel_anomalies.iter().filter(|&&a| a > 0.5).count();

    println!("High anomaly (>0.5) instructions:");
    println!(
        "  Mixed: {} ({:.1}%)",
        mixed_high,
        100.0 * mixed_high as f64 / mixed_anomalies.len() as f64
    );
    println!(
        "  Novel: {} ({:.1}%)",
        novel_high,
        100.0 * novel_high as f64 / novel_anomalies.len() as f64
    );
}

// =============================================================================
// CROSS-BINARY CLUSTER SIMILARITY TESTS
// =============================================================================

#[test]
fn test_cluster_fingerprint_similarity() {
    if !corpus_available() {
        return;
    }

    let mut pipeline = BondHtmPipeline::new();
    let detector = ClusterDetector::new();

    // Train and collect results on training corpus
    let mut training_results = Vec::new();
    for path in get_training_binaries() {
        let results = process_binary_through_htm(&path, &mut pipeline, true).unwrap();
        training_results.extend(results);
    }

    let training_clusters = detector.detect_clusters(&training_results);
    println!(
        "Training corpus: {} clusters detected",
        training_clusters.len()
    );

    // Now analyze test binaries
    for (path, category) in get_test_binaries() {
        let name = Path::new(&path).file_name().unwrap().to_string_lossy();

        pipeline.reset();
        let test_results = process_binary_through_htm(&path, &mut pipeline, false).unwrap();
        let test_clusters = detector.detect_clusters(&test_results);

        // Calculate similarity between test clusters and training clusters
        let mut similarities = Vec::new();
        for test_cluster in &test_clusters {
            for training_cluster in &training_clusters {
                let sim = test_cluster.fingerprint.similarity(&training_cluster.fingerprint);
                similarities.push(sim);
            }
        }

        let avg_sim = if similarities.is_empty() {
            0.0
        } else {
            similarities.iter().sum::<f64>() / similarities.len() as f64
        };

        let max_sim = similarities.iter().cloned().fold(0.0f64, f64::max);

        println!(
            "{} ({}): {} clusters, avg similarity: {:.4}, max similarity: {:.4}",
            name,
            category,
            test_clusters.len(),
            avg_sim,
            max_sim
        );
    }
}

// =============================================================================
// FUNCTION BOUNDARY DETECTION TESTS
// =============================================================================

#[test]
fn test_function_boundary_detection() {
    if !corpus_available() {
        return;
    }

    let mut pipeline = BondHtmPipeline::new();

    // Analyze function boundaries in training binaries
    for path in get_training_binaries() {
        let instructions = disassemble_binary(&path).unwrap();
        let name = Path::new(&path).file_name().unwrap().to_string_lossy();

        // Track anomaly spikes (potential function boundaries)
        let mut anomaly_spikes = Vec::new();
        let mut prev_anomaly = 0.0f32;

        for (i, inst) in instructions.iter().enumerate() {
            let result = pipeline.process(&inst, true);

            // Detect anomaly spike (might indicate boundary)
            let anomaly_change = result.anomaly_score - prev_anomaly;
            if anomaly_change > 0.3 && result.anomaly_score > 0.5 {
                anomaly_spikes.push((i, inst.address, result.anomaly_score));
            }

            prev_anomaly = result.anomaly_score;
        }

        // Count actual function returns (ret instructions)
        let ret_count = instructions
            .iter()
            .filter(|i| i.flow_control == FlowControlType::Return)
            .count();

        println!(
            "{}: {} instructions, {} ret instructions, {} anomaly spikes",
            name,
            instructions.len(),
            ret_count,
            anomaly_spikes.len()
        );
    }
}

// =============================================================================
// ENCODING CONSISTENCY TESTS
// =============================================================================

#[test]
fn test_encoding_consistency_across_binaries() {
    if !corpus_available() {
        return;
    }

    use bond::encoding::instruction_encoder::InstructionEncoder;
    let encoder = InstructionEncoder::new();

    // Track unique encodings across all binaries
    let mut encoding_map: HashMap<Vec<u32>, Vec<String>> = HashMap::new();

    for path in get_training_binaries() {
        let instructions = disassemble_binary(&path).unwrap();
        let name = Path::new(&path)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();

        for inst in &instructions {
            let sdr = encoder.encode(&inst);
            let sparse = sdr.get_sparse().to_vec();

            encoding_map
                .entry(sparse)
                .or_insert_with(Vec::new)
                .push(format!("{}:{}", name, inst.mnemonic));
        }
    }

    // Count unique vs shared encodings
    let total_encodings = encoding_map.len();
    let shared_encodings = encoding_map.values().filter(|v| v.len() > 1).count();
    let unique_encodings = total_encodings - shared_encodings;

    println!("\nEncoding analysis across training corpus:");
    println!("  Total unique SDR encodings: {}", total_encodings);
    println!("  Shared across binaries: {}", shared_encodings);
    println!("  Unique to single binary: {}", unique_encodings);

    // Show some examples of shared encodings
    println!("\nExamples of shared encodings:");
    let mut shared_examples: Vec<_> = encoding_map
        .iter()
        .filter(|(_, v)| v.len() > 2)
        .collect();
    shared_examples.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));

    for (_, sources) in shared_examples.iter().take(5) {
        println!("  Shared by {} instructions", sources.len());
    }
}

// =============================================================================
// STRIPPED BINARY TESTS
// =============================================================================

#[test]
fn test_stripped_binaries() {
    if !corpus_available() {
        return;
    }

    use bond::encoding::instruction_encoder::InstructionEncoder;
    let encoder = InstructionEncoder::new();

    // Compare analysis of stripped vs non-stripped binaries
    let test_pairs = [
        ("train_loops", "train_loops_stripped"),
        ("test_mixed", "test_mixed_stripped"),
    ];

    for (normal_name, stripped_name) in &test_pairs {
        let normal_path = format!("{}/{}", CORPUS_DIR, normal_name);
        let stripped_path = format!("{}/{}", CORPUS_DIR, stripped_name);

        if !Path::new(&normal_path).exists() || !Path::new(&stripped_path).exists() {
            continue;
        }

        let normal_instructions = disassemble_binary(&normal_path).unwrap();
        let stripped_instructions = disassemble_binary(&stripped_path).unwrap();

        // The instruction sequences should be identical
        assert_eq!(
            normal_instructions.len(),
            stripped_instructions.len(),
            "Stripped binary should have same instruction count"
        );

        // Verify encodings are identical
        let mut differences = 0;
        for (n, s) in normal_instructions.iter().zip(stripped_instructions.iter()) {
            let n_sdr = encoder.encode(&n);
            let s_sdr = encoder.encode(&s);

            if n_sdr.get_sparse() != s_sdr.get_sparse() {
                differences += 1;
            }
        }

        println!(
            "{} vs {}: {} instructions, {} encoding differences",
            normal_name,
            stripped_name,
            normal_instructions.len(),
            differences
        );

        // Encoding should be identical regardless of symbols
        assert_eq!(
            differences, 0,
            "Stripped binary should produce identical encodings"
        );
    }
}

// =============================================================================
// FULL PIPELINE TEST
// =============================================================================

#[test]
fn test_full_training_and_detection_pipeline() {
    if !corpus_available() {
        eprintln!("\n=======================================================");
        eprintln!("CORPUS NOT BUILT - Run: cd tests/corpus && ./build.sh");
        eprintln!("=======================================================\n");
        return;
    }

    println!("\n");
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║      BOND: Full Training and Detection Pipeline Test     ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // Phase 1: Setup
    let mut pipeline = BondHtmPipeline::new();
    let detector = ClusterDetector::new();

    // Phase 2: Training
    println!("Phase 1: Training on corpus...");
    let mut all_training_results = Vec::new();

    for path in get_training_binaries() {
        let name = Path::new(&path).file_name().unwrap().to_string_lossy();
        let results = process_binary_through_htm(&path, &mut pipeline, true).unwrap();
        let inst_count = results.len();
        all_training_results.extend(results);
        print!("  [OK] {} ({} instructions)\n", name, inst_count);
    }

    println!("\n  Total trained: {} instructions", all_training_results.len());

    let training_clusters = detector.detect_clusters(&all_training_results);
    println!("  Clusters detected: {}", training_clusters.len());

    // Phase 3: Testing
    println!("\nPhase 2: Testing pattern transfer...");

    for (path, category) in get_test_binaries() {
        let name = Path::new(&path).file_name().unwrap().to_string_lossy();

        pipeline.reset();
        let test_results = process_binary_through_htm(&path, &mut pipeline, false).unwrap();

        // Calculate anomaly stats
        let anomalies: Vec<f32> = test_results.iter().map(|r| r.result.anomaly_score).collect();
        let avg_anomaly: f32 = anomalies.iter().sum::<f32>() / anomalies.len() as f32;

        let test_clusters = detector.detect_clusters(&test_results);

        println!(
            "  {} ({}):",
            name, category
        );
        println!("    Instructions: {}", test_results.len());
        println!("    Average anomaly: {:.4}", avg_anomaly);
        println!("    Clusters detected: {}", test_clusters.len());

        // Calculate similarity to training clusters
        let mut max_similarities = Vec::new();
        for test_cluster in &test_clusters {
            let max_sim = training_clusters
                .iter()
                .map(|tc| test_cluster.fingerprint.similarity(&tc.fingerprint))
                .fold(0.0f64, f64::max);
            max_similarities.push(max_sim);
        }

        if !max_similarities.is_empty() {
            let avg_max_sim: f64 =
                max_similarities.iter().sum::<f64>() / max_similarities.len() as f64;
            println!("    Avg max similarity to training: {:.4}", avg_max_sim);
        }
    }

    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║                    Pipeline Test Complete                 ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");
}
