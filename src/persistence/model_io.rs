//! Model persistence for saving and loading trained HTM models

use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::cluster::detector::Cluster;
use crate::htm::config::HtmConfig;

/// Metadata about model training
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrainingMetadata {
    /// Number of binaries processed during training
    pub binaries_processed: usize,
    /// Number of instructions processed
    pub instructions_processed: usize,
    /// Training timestamp
    pub timestamp: DateTime<Utc>,
    /// Number of training passes
    pub passes: usize,
    /// List of binary names used for training
    pub binary_names: Vec<String>,
}

/// A trained model that can be saved and loaded
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrainedModel {
    /// Model version for compatibility checking
    pub version: String,
    /// HTM configuration used
    pub config: HtmConfig,
    /// Discovered clusters
    pub clusters: Vec<Cluster>,
    /// Training metadata
    pub metadata: TrainingMetadata,
}

impl TrainedModel {
    /// Create a new trained model
    pub fn new(
        config: HtmConfig,
        clusters: Vec<Cluster>,
        metadata: TrainingMetadata,
    ) -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            config,
            clusters,
            metadata,
        }
    }

    /// Save the model to a file
    pub fn save(&self, path: &Path) -> Result<()> {
        let file = std::fs::File::create(path)?;
        let writer = std::io::BufWriter::new(file);
        bincode::serialize_into(writer, self)?;
        Ok(())
    }

    /// Load a model from a file
    pub fn load(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let model = bincode::deserialize_from(reader)?;
        Ok(model)
    }

    /// Save the model as JSON (human-readable)
    pub fn save_json(&self, path: &Path) -> Result<()> {
        let file = std::fs::File::create(path)?;
        let writer = std::io::BufWriter::new(file);
        serde_json::to_writer_pretty(writer, self)?;
        Ok(())
    }

    /// Load a model from JSON
    pub fn load_json(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let model = serde_json::from_reader(reader)?;
        Ok(model)
    }

    /// Get the number of clusters
    pub fn num_clusters(&self) -> usize {
        self.clusters.len()
    }

    /// Get total instruction count across all clusters
    pub fn total_instructions(&self) -> usize {
        self.clusters.iter().map(|c| c.instruction_count).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_save_load_roundtrip() {
        let model = TrainedModel {
            version: "0.1.0".to_string(),
            config: HtmConfig::default(),
            clusters: vec![],
            metadata: TrainingMetadata {
                binaries_processed: 5,
                instructions_processed: 10000,
                timestamp: Utc::now(),
                passes: 3,
                binary_names: vec!["test".to_string()],
            },
        };

        let dir = tempdir().unwrap();
        let path = dir.path().join("test_model.bin");

        model.save(&path).unwrap();
        let loaded = TrainedModel::load(&path).unwrap();

        assert_eq!(model.version, loaded.version);
        assert_eq!(model.metadata.binaries_processed, loaded.metadata.binaries_processed);
    }

    #[test]
    fn test_json_roundtrip() {
        let model = TrainedModel {
            version: "0.1.0".to_string(),
            config: HtmConfig::default(),
            clusters: vec![],
            metadata: TrainingMetadata {
                binaries_processed: 5,
                instructions_processed: 10000,
                timestamp: Utc::now(),
                passes: 3,
                binary_names: vec!["test".to_string()],
            },
        };

        let dir = tempdir().unwrap();
        let path = dir.path().join("test_model.json");

        model.save_json(&path).unwrap();
        let loaded = TrainedModel::load_json(&path).unwrap();

        assert_eq!(model.version, loaded.version);
    }
}
