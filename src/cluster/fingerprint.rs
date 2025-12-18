//! Cell activation fingerprinting for cluster identification

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// A fingerprint representing a cell activation pattern
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fingerprint {
    /// Active cell indices
    cells: Vec<u32>,
}

impl Fingerprint {
    /// Create a new fingerprint from active cells
    pub fn new(cells: Vec<u32>) -> Self {
        let mut cells = cells;
        cells.sort_unstable();
        cells.dedup();
        Self { cells }
    }

    /// Get the active cells
    pub fn cells(&self) -> &[u32] {
        &self.cells
    }

    /// Calculate Jaccard similarity with another fingerprint
    pub fn similarity(&self, other: &Fingerprint) -> f64 {
        if self.cells.is_empty() && other.cells.is_empty() {
            return 1.0;
        }

        let set_a: HashSet<u32> = self.cells.iter().copied().collect();
        let set_b: HashSet<u32> = other.cells.iter().copied().collect();

        let intersection = set_a.intersection(&set_b).count();
        let union = set_a.union(&set_b).count();

        if union == 0 {
            0.0
        } else {
            intersection as f64 / union as f64
        }
    }

    /// Calculate overlap count with another fingerprint
    pub fn overlap(&self, other: &Fingerprint) -> usize {
        let set_a: HashSet<u32> = self.cells.iter().copied().collect();
        let set_b: HashSet<u32> = other.cells.iter().copied().collect();

        set_a.intersection(&set_b).count()
    }

    /// Number of active cells
    pub fn size(&self) -> usize {
        self.cells.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    /// Merge with another fingerprint (union)
    pub fn merge(&mut self, other: &Fingerprint) {
        let mut combined: HashSet<u32> = self.cells.iter().copied().collect();
        combined.extend(other.cells.iter().copied());

        self.cells = combined.into_iter().collect();
        self.cells.sort_unstable();
    }
}

/// Compute a centroid fingerprint from multiple fingerprints
///
/// Returns cells that appear in at least `threshold` fraction of fingerprints
pub fn compute_centroid(fingerprints: &[Fingerprint], threshold: f64) -> Fingerprint {
    if fingerprints.is_empty() {
        return Fingerprint::new(Vec::new());
    }

    // Count occurrences of each cell
    let mut cell_counts: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();

    for fp in fingerprints {
        for &cell in fp.cells() {
            *cell_counts.entry(cell).or_insert(0) += 1;
        }
    }

    // Keep cells that appear in at least threshold fraction
    let min_count = (fingerprints.len() as f64 * threshold).ceil() as usize;
    let centroid_cells: Vec<u32> = cell_counts
        .into_iter()
        .filter(|(_, count)| *count >= min_count)
        .map(|(cell, _)| cell)
        .collect();

    Fingerprint::new(centroid_cells)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_similarity() {
        let fp1 = Fingerprint::new(vec![1, 2, 3, 4, 5]);
        let fp2 = Fingerprint::new(vec![3, 4, 5, 6, 7]);

        // Intersection: {3, 4, 5} = 3 elements
        // Union: {1, 2, 3, 4, 5, 6, 7} = 7 elements
        // Jaccard: 3/7 ≈ 0.4286
        let sim = fp1.similarity(&fp2);
        assert!((sim - 0.4286).abs() < 0.01);
    }

    #[test]
    fn test_identical_fingerprints() {
        let fp1 = Fingerprint::new(vec![1, 2, 3]);
        let fp2 = Fingerprint::new(vec![1, 2, 3]);

        assert!((fp1.similarity(&fp2) - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_disjoint_fingerprints() {
        let fp1 = Fingerprint::new(vec![1, 2, 3]);
        let fp2 = Fingerprint::new(vec![4, 5, 6]);

        assert!((fp1.similarity(&fp2) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_centroid_computation() {
        let fps = vec![
            Fingerprint::new(vec![1, 2, 3]),
            Fingerprint::new(vec![1, 2, 4]),
            Fingerprint::new(vec![1, 3, 5]),
        ];

        // Cell 1 appears in all 3
        // Cell 2 appears in 2/3
        // Cell 3 appears in 2/3
        // Cells 4, 5 appear in 1/3

        // With threshold 0.5, should keep cells appearing in >= 50%
        let centroid = compute_centroid(&fps, 0.5);
        assert!(centroid.cells().contains(&1)); // 100%
        assert!(centroid.cells().contains(&2)); // 66%
        assert!(centroid.cells().contains(&3)); // 66%
    }
}
