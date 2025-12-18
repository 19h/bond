//! Cluster detection based on HTM cell activations and anomaly scores

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::disasm::features::{DecodedInstruction, FlowControlType, OpcodeCategory};
use crate::htm::pipeline::ProcessResult;

use super::fingerprint::{compute_centroid, Fingerprint};

/// A detected code sequence cluster
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cluster {
    /// Unique cluster ID
    pub id: u32,
    /// Centroid fingerprint (representative cell pattern)
    pub fingerprint: Fingerprint,
    /// Number of instructions in this cluster
    pub instruction_count: usize,
    /// Start addresses where this cluster appears
    pub start_addresses: Vec<u64>,
    /// Representative instruction sequence (first few mnemonics)
    pub representative_sequence: Vec<String>,
    /// Mean anomaly score within the cluster
    pub anomaly_score_mean: f64,
    /// Dominant opcode category
    pub dominant_category: OpcodeCategory,
    /// Cluster name (auto-generated)
    pub name: String,
}

/// Result from processing an instruction (instruction + HTM result)
#[derive(Clone, Debug)]
pub struct InstructionResult {
    /// The decoded instruction
    pub instruction: DecodedInstruction,
    /// HTM processing result
    pub result: ProcessResult,
}

/// Configuration for cluster detection
#[derive(Clone, Debug)]
pub struct ClusterDetectorConfig {
    /// Anomaly score threshold for cluster boundaries
    pub boundary_threshold: f32,
    /// Minimum number of instructions in a cluster
    pub min_cluster_size: usize,
    /// Fingerprint similarity threshold for merging clusters
    pub merge_threshold: f64,
    /// Threshold for centroid computation (fraction of fingerprints cell must appear in)
    pub centroid_threshold: f64,
}

impl Default for ClusterDetectorConfig {
    fn default() -> Self {
        Self {
            boundary_threshold: 0.1,   // Much lower - detect even small anomaly spikes
            min_cluster_size: 3,        // Smaller clusters for more granularity
            merge_threshold: 1.1,       // > 1.0 means never merge (similarity max is 1.0)
            centroid_threshold: 0.3,    // Lower threshold for centroid inclusion
        }
    }
}

/// Cluster detector using HTM results
pub struct ClusterDetector {
    config: ClusterDetectorConfig,
}

impl ClusterDetector {
    /// Create a new cluster detector with default configuration
    pub fn new() -> Self {
        Self::with_config(ClusterDetectorConfig::default())
    }

    /// Create a new cluster detector with custom configuration
    pub fn with_config(config: ClusterDetectorConfig) -> Self {
        Self { config }
    }

    /// Detect clusters from a sequence of instruction results
    pub fn detect_clusters(&self, results: &[InstructionResult]) -> Vec<Cluster> {
        if results.is_empty() {
            return Vec::new();
        }

        // Find cluster boundaries
        let boundaries = self.find_boundaries(results);

        // Create clusters from segments between boundaries
        let mut clusters = self.create_clusters_from_segments(results, &boundaries);

        // Merge similar clusters
        self.merge_similar_clusters(&mut clusters);

        // Assign names to clusters
        for cluster in &mut clusters {
            cluster.name = self.generate_cluster_name(cluster);
        }

        clusters
    }

    /// Find cluster boundary indices
    fn find_boundaries(&self, results: &[InstructionResult]) -> Vec<usize> {
        let mut boundaries = vec![0]; // Always start with index 0

        for (i, result) in results.iter().enumerate().skip(1) {
            if self.is_boundary(result, i, results) {
                boundaries.push(i);
            }
        }

        boundaries.push(results.len()); // End boundary
        boundaries
    }

    /// Check if a position should be a cluster boundary
    fn is_boundary(&self, result: &InstructionResult, idx: usize, all: &[InstructionResult]) -> bool {
        // Control flow changes are strong boundaries
        match result.instruction.flow_control {
            FlowControlType::Call | FlowControlType::Return => return true,
            FlowControlType::UnconditionalJump => return true,
            _ => {}
        }

        // High anomaly score indicates a boundary
        if result.result.anomaly_score > self.config.boundary_threshold {
            return true;
        }

        // Anomaly spike (relative to previous) indicates boundary
        if idx > 0 {
            let prev_anomaly = all[idx - 1].result.anomaly_score;
            let curr_anomaly = result.result.anomaly_score;
            // A 5x increase in anomaly is significant
            if curr_anomaly > 0.01 && curr_anomaly > prev_anomaly * 5.0 {
                return true;
            }
        }

        // Large fingerprint discontinuity indicates boundary
        if idx > 0 {
            let prev_fp = Fingerprint::new(all[idx - 1].result.active_cells.clone());
            let curr_fp = Fingerprint::new(result.result.active_cells.clone());

            // Less strict threshold
            if prev_fp.similarity(&curr_fp) < 0.3 {
                return true;
            }
        }

        false
    }

    /// Create clusters from segments between boundaries
    fn create_clusters_from_segments(
        &self,
        results: &[InstructionResult],
        boundaries: &[usize],
    ) -> Vec<Cluster> {
        let mut clusters = Vec::new();

        for i in 0..boundaries.len() - 1 {
            let start = boundaries[i];
            let end = boundaries[i + 1];
            let segment = &results[start..end];

            if segment.len() >= self.config.min_cluster_size {
                if let Some(cluster) = self.create_cluster(segment, clusters.len() as u32) {
                    clusters.push(cluster);
                }
            }
        }

        clusters
    }

    /// Create a cluster from a segment of results
    fn create_cluster(&self, segment: &[InstructionResult], id: u32) -> Option<Cluster> {
        if segment.is_empty() {
            return None;
        }

        // Collect fingerprints
        let fingerprints: Vec<Fingerprint> = segment
            .iter()
            .map(|r| Fingerprint::new(r.result.active_cells.clone()))
            .collect();

        // Compute centroid
        let centroid = compute_centroid(&fingerprints, self.config.centroid_threshold);

        // Compute mean anomaly
        let anomaly_mean = segment.iter().map(|r| r.result.anomaly_score as f64).sum::<f64>()
            / segment.len() as f64;

        // Get representative sequence
        let rep_sequence: Vec<String> = segment
            .iter()
            .take(10)
            .map(|r| r.instruction.mnemonic.clone())
            .collect();

        // Find dominant opcode category
        let dominant_category = self.find_dominant_category(segment);

        Some(Cluster {
            id,
            fingerprint: centroid,
            instruction_count: segment.len(),
            start_addresses: vec![segment[0].instruction.address],
            representative_sequence: rep_sequence,
            anomaly_score_mean: anomaly_mean,
            dominant_category,
            name: String::new(), // Will be set later
        })
    }

    /// Find the most common opcode category in a segment
    fn find_dominant_category(&self, segment: &[InstructionResult]) -> OpcodeCategory {
        let mut counts: HashMap<OpcodeCategory, usize> = HashMap::new();

        for result in segment {
            *counts.entry(result.instruction.opcode_category).or_insert(0) += 1;
        }

        counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(cat, _)| cat)
            .unwrap_or(OpcodeCategory::Other)
    }

    /// Merge clusters with similar fingerprints
    fn merge_similar_clusters(&self, clusters: &mut Vec<Cluster>) {
        let mut i = 0;
        while i < clusters.len() {
            let mut j = i + 1;
            while j < clusters.len() {
                let similarity = clusters[i].fingerprint.similarity(&clusters[j].fingerprint);

                if similarity > self.config.merge_threshold {
                    // Merge cluster j into cluster i
                    let cluster_j = clusters.remove(j);
                    clusters[i].instruction_count += cluster_j.instruction_count;
                    clusters[i]
                        .start_addresses
                        .extend(cluster_j.start_addresses);
                    clusters[i].fingerprint.merge(&cluster_j.fingerprint);

                    // Recalculate mean anomaly
                    let total_instructions =
                        clusters[i].instruction_count as f64;
                    clusters[i].anomaly_score_mean =
                        (clusters[i].anomaly_score_mean * (total_instructions - cluster_j.instruction_count as f64)
                            + cluster_j.anomaly_score_mean * cluster_j.instruction_count as f64)
                            / total_instructions;
                } else {
                    j += 1;
                }
            }
            i += 1;
        }
    }

    /// Generate a descriptive name for a cluster
    fn generate_cluster_name(&self, cluster: &Cluster) -> String {
        let category_name = match cluster.dominant_category {
            OpcodeCategory::DataTransfer => "data_transfer",
            OpcodeCategory::Arithmetic => "arithmetic",
            OpcodeCategory::Logic => "logic",
            OpcodeCategory::Compare => "compare",
            OpcodeCategory::ControlFlow => "control_flow",
            OpcodeCategory::String => "string_op",
            OpcodeCategory::Stack => "stack_op",
            OpcodeCategory::SystemCall => "syscall",
            OpcodeCategory::FloatingPoint => "fpu",
            OpcodeCategory::Simd => "simd",
            OpcodeCategory::Nop => "nop_block",
            OpcodeCategory::Other => "misc",
        };

        format!("{}_{}", category_name, cluster.id)
    }

    /// Match a fingerprint against known clusters
    pub fn match_cluster<'a>(
        &self,
        fingerprint: &Fingerprint,
        clusters: &'a [Cluster],
    ) -> Option<&'a Cluster> {
        clusters
            .iter()
            .filter(|c| fingerprint.similarity(&c.fingerprint) > self.config.merge_threshold)
            .max_by(|a, b| {
                let sim_a = fingerprint.similarity(&a.fingerprint);
                let sim_b = fingerprint.similarity(&b.fingerprint);
                sim_a.partial_cmp(&sim_b).unwrap_or(std::cmp::Ordering::Equal)
            })
    }
}

impl Default for ClusterDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::features::{FunctionBoundaryHint, MemoryAccessPattern, OperandPattern, RegisterCategory};

    fn make_result(
        address: u64,
        opcode: OpcodeCategory,
        anomaly: f32,
        cells: Vec<u32>,
    ) -> InstructionResult {
        InstructionResult {
            instruction: DecodedInstruction {
                address,
                length: 3,
                opcode_category: opcode,
                mnemonic: "test".to_string(),
                operand_types: vec![],
                operand_pattern: OperandPattern::RegReg,
                registers_read: vec![RegisterCategory::GeneralPurpose64],
                registers_written: vec![RegisterCategory::GeneralPurpose64],
                flow_control: FlowControlType::Sequential,
                memory_access: MemoryAccessPattern::NoMemory,
                has_immediate: false,
                boundary_hint: FunctionBoundaryHint::None,
            },
            result: ProcessResult {
                anomaly_score: anomaly,
                active_cells: cells,
                predictive_cells: vec![],
                bursting_columns: 0,
            },
        }
    }

    #[test]
    fn test_detect_single_cluster() {
        let detector = ClusterDetector::new();

        // Create a sequence of similar instructions with low anomaly
        let results: Vec<InstructionResult> = (0..10)
            .map(|i| {
                make_result(
                    0x1000 + i * 3,
                    OpcodeCategory::DataTransfer,
                    0.05, // Low anomaly (below boundary_threshold of 0.1)
                    vec![1, 2, 3, 4, 5], // Same fingerprint
                )
            })
            .collect();

        let clusters = detector.detect_clusters(&results);

        // Should detect at least one cluster
        assert!(!clusters.is_empty());
    }

    #[test]
    fn test_boundary_detection() {
        let detector = ClusterDetector::new();

        let mut results = Vec::new();

        // First cluster: low anomaly (below 0.1 threshold)
        for i in 0..5 {
            results.push(make_result(
                0x1000 + i * 3,
                OpcodeCategory::DataTransfer,
                0.05,
                vec![1, 2, 3],
            ));
        }

        // High anomaly boundary
        results.push(make_result(
            0x2000,
            OpcodeCategory::ControlFlow,
            0.9,
            vec![100, 101, 102],
        ));

        // Second cluster: low anomaly, different fingerprint
        for i in 0..5 {
            results.push(make_result(
                0x2003 + i * 3,
                OpcodeCategory::Arithmetic,
                0.05,
                vec![10, 11, 12],
            ));
        }

        let clusters = detector.detect_clusters(&results);

        // Should detect at least 2 distinct clusters (boundary at high anomaly point)
        assert!(clusters.len() >= 2);
    }
}
