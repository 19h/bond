// Actionable analysis tests - demonstrate what the system can actually detect

use bond::binary::loader::load_binary;
use bond::cluster::detector::{ClusterDetector, InstructionResult};
use bond::disasm::decoder::X86Decoder;
use bond::disasm::features::{DecodedInstruction, OpcodeCategory};
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

fn process_binary(path: &str, pipeline: &mut BondHtmPipeline, learn: bool) -> Vec<InstructionResult> {
    let instructions = disassemble_binary(path);
    let mut results = Vec::new();
    for inst in instructions {
        let htm_result = pipeline.process(&inst, learn);
        results.push(InstructionResult {
            instruction: inst,
            result: htm_result,
        });
    }
    results
}

/// Cluster signature for matching
#[derive(Debug, Clone)]
struct ClusterSignature {
    size: usize,
    dominant_category: OpcodeCategory,
    start_mnemonic: String,
    has_loop: bool,       // Contains backward jumps
    has_call: bool,       // Contains function calls
    category_distribution: HashMap<OpcodeCategory, usize>,
}

fn compute_cluster_signature(results: &[InstructionResult]) -> ClusterSignature {
    let mut category_dist: HashMap<OpcodeCategory, usize> = HashMap::new();
    let mut has_loop = false;
    let mut has_call = false;

    for result in results {
        *category_dist.entry(result.instruction.opcode_category).or_insert(0) += 1;

        if result.instruction.mnemonic.starts_with("call") {
            has_call = true;
        }
        // Simple loop detection: backward jump
        if result.instruction.mnemonic.starts_with("j") {
            // This is a simplification - real loop detection would check the offset
            has_loop = true;
        }
    }

    let dominant = category_dist.iter()
        .max_by_key(|(_, count)| *count)
        .map(|(cat, _)| *cat)
        .unwrap_or(OpcodeCategory::Other);

    ClusterSignature {
        size: results.len(),
        dominant_category: dominant,
        start_mnemonic: results.first()
            .map(|r| r.instruction.mnemonic.clone())
            .unwrap_or_default(),
        has_loop,
        has_call,
        category_distribution: category_dist,
    }
}

fn signature_similarity(a: &ClusterSignature, b: &ClusterSignature) -> f64 {
    let mut score = 0.0;

    // Same dominant category
    if a.dominant_category == b.dominant_category {
        score += 0.3;
    }

    // Similar size (within 30%)
    let size_ratio = a.size.min(b.size) as f64 / a.size.max(b.size).max(1) as f64;
    score += size_ratio * 0.2;

    // Same structural features
    if a.has_loop == b.has_loop {
        score += 0.15;
    }
    if a.has_call == b.has_call {
        score += 0.15;
    }

    // Category distribution similarity (Jaccard on categories present)
    let a_cats: std::collections::HashSet<_> = a.category_distribution.keys().collect();
    let b_cats: std::collections::HashSet<_> = b.category_distribution.keys().collect();
    let intersection = a_cats.intersection(&b_cats).count();
    let union = a_cats.union(&b_cats).count();
    if union > 0 {
        score += 0.2 * (intersection as f64 / union as f64);
    }

    score
}

#[test]
fn test_find_similar_functions_across_binaries() {
    if !corpus_available() {
        return;
    }

    println!("\n=== CROSS-BINARY FUNCTION MATCHING ===\n");

    let mut pipeline = BondHtmPipeline::new();
    let detector = ClusterDetector::new();

    // Process train_loops
    let loops_path = format!("{}/train_loops", CORPUS_DIR);
    let loops_results = process_binary(&loops_path, &mut pipeline, true);
    let loops_clusters = detector.detect_clusters(&loops_results);

    // Process test_mixed (should have similar functions)
    pipeline.reset();
    let mixed_path = format!("{}/test_mixed", CORPUS_DIR);
    let mixed_results = process_binary(&mixed_path, &mut pipeline, false);
    let mixed_clusters = detector.detect_clusters(&mixed_results);

    println!("train_loops: {} clusters", loops_clusters.len());
    println!("test_mixed: {} clusters", mixed_clusters.len());

    // Compute signatures for all clusters
    let mut loops_sigs: Vec<(usize, ClusterSignature)> = Vec::new();
    let mut mixed_sigs: Vec<(usize, ClusterSignature)> = Vec::new();

    // For train_loops clusters
    let mut start_idx = 0;
    for (i, cluster) in loops_clusters.iter().enumerate() {
        let end_idx = start_idx + cluster.instruction_count;
        if end_idx <= loops_results.len() {
            let sig = compute_cluster_signature(&loops_results[start_idx..end_idx]);
            loops_sigs.push((i, sig));
        }
        start_idx = end_idx;
    }

    // For test_mixed clusters
    start_idx = 0;
    for (i, cluster) in mixed_clusters.iter().enumerate() {
        let end_idx = start_idx + cluster.instruction_count;
        if end_idx <= mixed_results.len() {
            let sig = compute_cluster_signature(&mixed_results[start_idx..end_idx]);
            mixed_sigs.push((i, sig));
        }
        start_idx = end_idx;
    }

    // Find matches
    println!("\n=== Best Matches (similarity > 0.6) ===\n");
    let mut match_count = 0;

    for (loops_idx, loops_sig) in &loops_sigs {
        let mut best_match: Option<(usize, f64)> = None;

        for (mixed_idx, mixed_sig) in &mixed_sigs {
            let sim = signature_similarity(loops_sig, mixed_sig);
            if sim > 0.6 {
                if best_match.map(|(_, s)| sim > s).unwrap_or(true) {
                    best_match = Some((*mixed_idx, sim));
                }
            }
        }

        if let Some((mixed_idx, sim)) = best_match {
            if match_count < 10 {
                println!(
                    "train_loops[{}] ({:?}, {} inst) <-> test_mixed[{}] (sim={:.2})",
                    loops_idx,
                    loops_sig.dominant_category,
                    loops_sig.size,
                    mixed_idx,
                    sim
                );
            }
            match_count += 1;
        }
    }

    println!("\nTotal matches found: {}", match_count);
    assert!(match_count > 0, "Should find at least some matching functions");
}

#[test]
fn test_detect_unique_patterns_in_novel_binary() {
    if !corpus_available() {
        return;
    }

    println!("\n=== DETECTING UNIQUE PATTERNS IN NOVEL BINARY ===\n");

    let mut pipeline = BondHtmPipeline::new();
    let detector = ClusterDetector::new();

    // Train on all training binaries
    for name in &["train_loops", "train_math", "train_strings", "train_functions", "train_control"] {
        let path = format!("{}/{}", CORPUS_DIR, name);
        let _ = process_binary(&path, &mut pipeline, true);
    }

    // Process test_novel
    pipeline.reset();
    let novel_path = format!("{}/test_novel", CORPUS_DIR);
    let novel_results = process_binary(&novel_path, &mut pipeline, false);
    let novel_clusters = detector.detect_clusters(&novel_results);

    println!("test_novel: {} clusters detected", novel_clusters.len());

    // Look at the distribution of opcode categories
    let mut category_counts: HashMap<OpcodeCategory, usize> = HashMap::new();
    for cluster in &novel_clusters {
        *category_counts.entry(cluster.dominant_category).or_insert(0) += 1;
    }

    println!("\nCluster distribution by dominant category:");
    let mut sorted: Vec<_> = category_counts.into_iter().collect();
    sorted.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

    for (cat, count) in &sorted {
        println!("  {:?}: {} clusters", cat, count);
    }

    // Find SIMD-heavy clusters (unique to novel binary)
    println!("\nSIMD clusters (likely unique algorithms):");
    let simd_clusters: Vec<_> = novel_clusters.iter()
        .filter(|c| c.dominant_category == OpcodeCategory::Simd)
        .take(5)
        .collect();

    for cluster in simd_clusters {
        println!(
            "  Cluster at 0x{:x}: {} instructions, first ops: {:?}",
            cluster.start_addresses[0],
            cluster.instruction_count,
            &cluster.representative_sequence[..cluster.representative_sequence.len().min(5)]
        );
    }

    // The novel binary should have some unique patterns
    println!("\nLargest clusters (complex functions):");
    let mut by_size: Vec<_> = novel_clusters.iter().collect();
    by_size.sort_by_key(|c| std::cmp::Reverse(c.instruction_count));

    for cluster in by_size.iter().take(5) {
        println!(
            "  {} instructions at 0x{:x}: {:?} ({})",
            cluster.instruction_count,
            cluster.start_addresses[0],
            cluster.dominant_category,
            cluster.name
        );
    }
}

#[test]
fn test_summary_statistics() {
    if !corpus_available() {
        return;
    }

    println!("\n=== BINARY ANALYSIS SUMMARY ===\n");

    let mut pipeline = BondHtmPipeline::new();
    let detector = ClusterDetector::new();

    let binaries = vec![
        ("train_loops", true),
        ("train_math", true),
        ("test_mixed", false),
        ("test_novel", false),
    ];

    for (name, learn) in binaries {
        let path = format!("{}/{}", CORPUS_DIR, name);
        if !learn {
            pipeline.reset();
        }
        let results = process_binary(&path, &mut pipeline, learn);
        let clusters = detector.detect_clusters(&results);

        // Compute statistics
        let total_inst = results.len();
        let num_clusters = clusters.len();
        let avg_cluster_size = if num_clusters > 0 {
            total_inst as f64 / num_clusters as f64
        } else {
            0.0
        };

        let simd_clusters = clusters.iter()
            .filter(|c| c.dominant_category == OpcodeCategory::Simd)
            .count();

        let control_flow_clusters = clusters.iter()
            .filter(|c| c.dominant_category == OpcodeCategory::ControlFlow)
            .count();

        println!("{}:", name);
        println!("  Instructions: {}", total_inst);
        println!("  Clusters: {} (avg {:.1} inst/cluster)", num_clusters, avg_cluster_size);
        println!("  Control flow clusters: {}", control_flow_clusters);
        println!("  SIMD clusters: {}", simd_clusters);
        println!();
    }
}
