//! HTM pipeline configuration

use mokosh::algorithms::{AnomalyMode, SpatialPoolerParams, TemporalMemoryParams};
use serde::{Deserialize, Serialize};

/// Configuration for the HTM pipeline
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HtmConfig {
    /// Spatial Pooler parameters
    pub spatial_pooler: SpConfig,
    /// Temporal Memory parameters
    pub temporal_memory: TmConfig,
}

impl Default for HtmConfig {
    fn default() -> Self {
        Self {
            spatial_pooler: SpConfig::default(),
            temporal_memory: TmConfig::default(),
        }
    }
}

/// Spatial Pooler configuration (serializable wrapper)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpConfig {
    /// Input dimensions (should match encoder output)
    pub input_dimensions: Vec<u32>,
    /// Column dimensions
    pub column_dimensions: Vec<u32>,
    /// Potential radius for connections
    pub potential_radius: u32,
    /// Fraction of potential connections to create
    pub potential_pct: f32,
    /// Use global inhibition
    pub global_inhibition: bool,
    /// Target sparsity (fraction of active columns)
    pub local_area_density: f32,
    /// Permanence threshold for connected synapses
    pub syn_perm_connected: f32,
    /// Permanence increment for active synapses
    pub syn_perm_active_inc: f32,
    /// Permanence decrement for inactive synapses
    pub syn_perm_inactive_dec: f32,
    /// Boost strength
    pub boost_strength: f32,
    /// Duty cycle period
    pub duty_cycle_period: u32,
    /// Random seed
    pub seed: i64,
}

impl Default for SpConfig {
    fn default() -> Self {
        Self {
            input_dimensions: vec![2048],
            column_dimensions: vec![2048],
            potential_radius: 2048,
            potential_pct: 0.5,
            global_inhibition: true,
            local_area_density: 0.02,
            syn_perm_connected: 0.5,
            syn_perm_active_inc: 0.1,
            syn_perm_inactive_dec: 0.02,
            boost_strength: 10.0,
            duty_cycle_period: 1000,
            seed: 42,
        }
    }
}

impl SpConfig {
    /// Convert to mokosh SpatialPoolerParams
    pub fn to_params(&self) -> SpatialPoolerParams {
        SpatialPoolerParams {
            input_dimensions: self.input_dimensions.clone(),
            column_dimensions: self.column_dimensions.clone(),
            potential_radius: self.potential_radius,
            potential_pct: self.potential_pct,
            global_inhibition: self.global_inhibition,
            local_area_density: self.local_area_density,
            num_active_columns_per_inh_area: 0,
            stimulus_threshold: 0,
            syn_perm_inactive_dec: self.syn_perm_inactive_dec,
            syn_perm_active_inc: self.syn_perm_active_inc,
            syn_perm_connected: self.syn_perm_connected,
            min_pct_overlap_duty_cycles: 0.001,
            duty_cycle_period: self.duty_cycle_period,
            boost_strength: self.boost_strength,
            seed: self.seed,
            sp_verbosity: 0,
            wrap_around: true,
        }
    }
}

/// Temporal Memory configuration (serializable wrapper)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TmConfig {
    /// Column dimensions (should match SP output)
    pub column_dimensions: Vec<u32>,
    /// Cells per column
    pub cells_per_column: u32,
    /// Activation threshold for segments
    pub activation_threshold: u32,
    /// Minimum threshold for learning
    pub min_threshold: u32,
    /// Initial permanence for new synapses
    pub initial_permanence: f32,
    /// Permanence threshold for connected synapses
    pub connected_permanence: f32,
    /// Permanence increment for active synapses
    pub permanence_increment: f32,
    /// Permanence decrement for inactive synapses
    pub permanence_decrement: f32,
    /// Permanence decrement for predicted but inactive segments
    pub predicted_segment_decrement: f32,
    /// Maximum synapses per segment
    pub max_synapses_per_segment: u32,
    /// Maximum segments per cell
    pub max_segments_per_cell: u32,
    /// Maximum new synapses per learning cycle
    pub max_new_synapse_count: u32,
    /// Anomaly detection mode
    pub anomaly_mode: AnomalyModeConfig,
    /// Random seed
    pub seed: i64,
}

impl Default for TmConfig {
    fn default() -> Self {
        Self {
            column_dimensions: vec![2048],
            cells_per_column: 32,
            activation_threshold: 13,      // Standard threshold
            min_threshold: 10,             // Standard min
            initial_permanence: 0.21,
            connected_permanence: 0.5,
            permanence_increment: 0.05,    // Moderate learning (was 0.1)
            permanence_decrement: 0.03,    // Moderate forgetting (was 0.1)
            predicted_segment_decrement: 0.001, // Small punishment for wrong predictions
            max_synapses_per_segment: 32,
            max_segments_per_cell: 128,
            max_new_synapse_count: 20,
            anomaly_mode: AnomalyModeConfig::Raw,
            seed: 42,
        }
    }
}

impl TmConfig {
    /// Convert to mokosh TemporalMemoryParams
    pub fn to_params(&self) -> TemporalMemoryParams {
        TemporalMemoryParams {
            column_dimensions: self.column_dimensions.clone(),
            cells_per_column: self.cells_per_column,
            activation_threshold: self.activation_threshold,
            initial_permanence: self.initial_permanence,
            connected_permanence: self.connected_permanence,
            min_threshold: self.min_threshold,
            max_synapses_per_segment: self.max_synapses_per_segment,
            max_segments_per_cell: self.max_segments_per_cell,
            max_new_synapse_count: self.max_new_synapse_count,
            permanence_increment: self.permanence_increment,
            permanence_decrement: self.permanence_decrement,
            predicted_segment_decrement: self.predicted_segment_decrement,
            seed: self.seed,
            anomaly_mode: self.anomaly_mode.to_mokosh(),
            external_predictive_inputs: 0,
            check_input_tm: false,
        }
    }
}

/// Serializable anomaly mode configuration
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyModeConfig {
    Disabled,
    Raw,
    Likelihood,
}

impl AnomalyModeConfig {
    /// Convert to mokosh AnomalyMode
    pub fn to_mokosh(self) -> AnomalyMode {
        match self {
            AnomalyModeConfig::Disabled => AnomalyMode::Disabled,
            AnomalyModeConfig::Raw => AnomalyMode::Raw,
            AnomalyModeConfig::Likelihood => AnomalyMode::Likelihood,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // HtmConfig Tests
    // ========================================================================

    #[test]
    fn test_htm_config_default() {
        let config = HtmConfig::default();

        // Should have default SP and TM configs
        assert_eq!(config.spatial_pooler.input_dimensions, vec![2048]);
        assert_eq!(config.temporal_memory.column_dimensions, vec![2048]);
    }

    #[test]
    fn test_htm_config_clone() {
        let config = HtmConfig::default();
        let cloned = config.clone();

        assert_eq!(
            config.spatial_pooler.input_dimensions,
            cloned.spatial_pooler.input_dimensions
        );
        assert_eq!(
            config.temporal_memory.cells_per_column,
            cloned.temporal_memory.cells_per_column
        );
    }

    #[test]
    fn test_htm_config_serialization() {
        let config = HtmConfig::default();
        let json = serde_json::to_string(&config).expect("Failed to serialize");
        let deserialized: HtmConfig =
            serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(
            config.spatial_pooler.seed,
            deserialized.spatial_pooler.seed
        );
        assert_eq!(
            config.temporal_memory.seed,
            deserialized.temporal_memory.seed
        );
    }

    // ========================================================================
    // SpConfig Tests
    // ========================================================================

    #[test]
    fn test_sp_config_default() {
        let config = SpConfig::default();

        assert_eq!(config.input_dimensions, vec![2048]);
        assert_eq!(config.column_dimensions, vec![2048]);
        assert_eq!(config.potential_radius, 2048);
        assert_eq!(config.potential_pct, 0.5);
        assert!(config.global_inhibition);
        assert_eq!(config.local_area_density, 0.02);
        assert_eq!(config.syn_perm_connected, 0.5);
        assert_eq!(config.syn_perm_active_inc, 0.1);
        assert_eq!(config.syn_perm_inactive_dec, 0.02);
        assert_eq!(config.boost_strength, 10.0);
        assert_eq!(config.duty_cycle_period, 1000);
        assert_eq!(config.seed, 42);
    }

    #[test]
    fn test_sp_config_to_params() {
        let config = SpConfig::default();
        let params = config.to_params();

        assert_eq!(params.input_dimensions, config.input_dimensions);
        assert_eq!(params.column_dimensions, config.column_dimensions);
        assert_eq!(params.potential_radius, config.potential_radius);
        assert_eq!(params.potential_pct, config.potential_pct);
        assert_eq!(params.global_inhibition, config.global_inhibition);
        assert_eq!(params.local_area_density, config.local_area_density);
        assert_eq!(params.syn_perm_connected, config.syn_perm_connected);
        assert_eq!(params.syn_perm_active_inc, config.syn_perm_active_inc);
        assert_eq!(params.syn_perm_inactive_dec, config.syn_perm_inactive_dec);
        assert_eq!(params.boost_strength, config.boost_strength);
        assert_eq!(params.duty_cycle_period, config.duty_cycle_period);
        assert_eq!(params.seed, config.seed);
    }

    #[test]
    fn test_sp_config_custom_values() {
        let config = SpConfig {
            input_dimensions: vec![1024],
            column_dimensions: vec![512],
            potential_radius: 256,
            potential_pct: 0.8,
            global_inhibition: false,
            local_area_density: 0.05,
            syn_perm_connected: 0.4,
            syn_perm_active_inc: 0.05,
            syn_perm_inactive_dec: 0.01,
            boost_strength: 5.0,
            duty_cycle_period: 500,
            seed: 123,
        };

        let params = config.to_params();
        assert_eq!(params.input_dimensions, vec![1024]);
        assert_eq!(params.column_dimensions, vec![512]);
        assert!(!params.global_inhibition);
    }

    #[test]
    fn test_sp_config_serialization() {
        let config = SpConfig::default();
        let json = serde_json::to_string(&config).expect("Failed to serialize");
        let deserialized: SpConfig = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(config.input_dimensions, deserialized.input_dimensions);
        assert_eq!(config.potential_pct, deserialized.potential_pct);
        assert_eq!(config.seed, deserialized.seed);
    }

    // ========================================================================
    // TmConfig Tests
    // ========================================================================

    #[test]
    fn test_tm_config_default() {
        let config = TmConfig::default();

        assert_eq!(config.column_dimensions, vec![2048]);
        assert_eq!(config.cells_per_column, 32);
        assert_eq!(config.activation_threshold, 13);
        assert_eq!(config.min_threshold, 10);
        assert_eq!(config.initial_permanence, 0.21);
        assert_eq!(config.connected_permanence, 0.5);
        assert_eq!(config.permanence_increment, 0.05);
        assert_eq!(config.permanence_decrement, 0.03);
        assert_eq!(config.predicted_segment_decrement, 0.001);
        assert_eq!(config.max_synapses_per_segment, 32);
        assert_eq!(config.max_segments_per_cell, 128);
        assert_eq!(config.max_new_synapse_count, 20);
        assert_eq!(config.anomaly_mode, AnomalyModeConfig::Raw);
        assert_eq!(config.seed, 42);
    }

    #[test]
    fn test_tm_config_to_params() {
        let config = TmConfig::default();
        let params = config.to_params();

        assert_eq!(params.column_dimensions, config.column_dimensions);
        assert_eq!(params.cells_per_column, config.cells_per_column);
        assert_eq!(params.activation_threshold, config.activation_threshold);
        assert_eq!(params.min_threshold, config.min_threshold);
        assert_eq!(params.initial_permanence, config.initial_permanence);
        assert_eq!(params.connected_permanence, config.connected_permanence);
        assert_eq!(params.permanence_increment, config.permanence_increment);
        assert_eq!(params.permanence_decrement, config.permanence_decrement);
        assert_eq!(params.seed, config.seed);
    }

    #[test]
    fn test_tm_config_custom_values() {
        let config = TmConfig {
            column_dimensions: vec![1024],
            cells_per_column: 16,
            activation_threshold: 8,
            min_threshold: 5,
            initial_permanence: 0.3,
            connected_permanence: 0.6,
            permanence_increment: 0.05,
            permanence_decrement: 0.05,
            predicted_segment_decrement: 0.01,
            max_synapses_per_segment: 64,
            max_segments_per_cell: 64,
            max_new_synapse_count: 10,
            anomaly_mode: AnomalyModeConfig::Likelihood,
            seed: 999,
        };

        let params = config.to_params();
        assert_eq!(params.column_dimensions, vec![1024]);
        assert_eq!(params.cells_per_column, 16);
    }

    #[test]
    fn test_tm_config_serialization() {
        let config = TmConfig::default();
        let json = serde_json::to_string(&config).expect("Failed to serialize");
        let deserialized: TmConfig = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(config.column_dimensions, deserialized.column_dimensions);
        assert_eq!(config.cells_per_column, deserialized.cells_per_column);
        assert_eq!(config.anomaly_mode, deserialized.anomaly_mode);
    }

    // ========================================================================
    // AnomalyModeConfig Tests
    // ========================================================================

    #[test]
    fn test_anomaly_mode_disabled() {
        let mode = AnomalyModeConfig::Disabled;
        let mokosh_mode = mode.to_mokosh();
        assert!(matches!(mokosh_mode, AnomalyMode::Disabled));
    }

    #[test]
    fn test_anomaly_mode_raw() {
        let mode = AnomalyModeConfig::Raw;
        let mokosh_mode = mode.to_mokosh();
        assert!(matches!(mokosh_mode, AnomalyMode::Raw));
    }

    #[test]
    fn test_anomaly_mode_likelihood() {
        let mode = AnomalyModeConfig::Likelihood;
        let mokosh_mode = mode.to_mokosh();
        assert!(matches!(mokosh_mode, AnomalyMode::Likelihood));
    }

    #[test]
    fn test_anomaly_mode_equality() {
        assert_eq!(AnomalyModeConfig::Disabled, AnomalyModeConfig::Disabled);
        assert_eq!(AnomalyModeConfig::Raw, AnomalyModeConfig::Raw);
        assert_eq!(AnomalyModeConfig::Likelihood, AnomalyModeConfig::Likelihood);
        assert_ne!(AnomalyModeConfig::Disabled, AnomalyModeConfig::Raw);
    }

    #[test]
    fn test_anomaly_mode_serialization() {
        let modes = [
            AnomalyModeConfig::Disabled,
            AnomalyModeConfig::Raw,
            AnomalyModeConfig::Likelihood,
        ];

        for mode in &modes {
            let json = serde_json::to_string(mode).expect("Failed to serialize");
            let deserialized: AnomalyModeConfig =
                serde_json::from_str(&json).expect("Failed to deserialize");
            assert_eq!(*mode, deserialized);
        }
    }

    // ========================================================================
    // Integration Tests
    // ========================================================================

    #[test]
    fn test_matching_dimensions() {
        let config = HtmConfig::default();

        // SP output should match TM input
        assert_eq!(
            config.spatial_pooler.column_dimensions,
            config.temporal_memory.column_dimensions
        );
    }

    #[test]
    fn test_reasonable_default_values() {
        let config = HtmConfig::default();

        // SP values should be reasonable
        assert!(config.spatial_pooler.potential_pct > 0.0 && config.spatial_pooler.potential_pct <= 1.0);
        assert!(config.spatial_pooler.local_area_density > 0.0 && config.spatial_pooler.local_area_density < 1.0);
        assert!(config.spatial_pooler.syn_perm_connected > 0.0 && config.spatial_pooler.syn_perm_connected < 1.0);

        // TM values should be reasonable
        assert!(config.temporal_memory.cells_per_column > 0);
        assert!(config.temporal_memory.activation_threshold > 0);
        assert!(config.temporal_memory.initial_permanence > 0.0 && config.temporal_memory.initial_permanence < 1.0);
        assert!(config.temporal_memory.connected_permanence > 0.0 && config.temporal_memory.connected_permanence < 1.0);
    }

    #[test]
    fn test_full_config_roundtrip() {
        let original = HtmConfig {
            spatial_pooler: SpConfig {
                input_dimensions: vec![1024],
                column_dimensions: vec![512],
                potential_radius: 512,
                potential_pct: 0.6,
                global_inhibition: true,
                local_area_density: 0.03,
                syn_perm_connected: 0.45,
                syn_perm_active_inc: 0.08,
                syn_perm_inactive_dec: 0.015,
                boost_strength: 8.0,
                duty_cycle_period: 800,
                seed: 100,
            },
            temporal_memory: TmConfig {
                column_dimensions: vec![512],
                cells_per_column: 24,
                activation_threshold: 10,
                min_threshold: 7,
                initial_permanence: 0.25,
                connected_permanence: 0.55,
                permanence_increment: 0.08,
                permanence_decrement: 0.08,
                predicted_segment_decrement: 0.005,
                max_synapses_per_segment: 48,
                max_segments_per_cell: 96,
                max_new_synapse_count: 15,
                anomaly_mode: AnomalyModeConfig::Likelihood,
                seed: 200,
            },
        };

        // Serialize and deserialize
        let json = serde_json::to_string_pretty(&original).expect("Failed to serialize");
        let restored: HtmConfig = serde_json::from_str(&json).expect("Failed to deserialize");

        // Verify all values match
        assert_eq!(
            original.spatial_pooler.input_dimensions,
            restored.spatial_pooler.input_dimensions
        );
        assert_eq!(
            original.spatial_pooler.seed,
            restored.spatial_pooler.seed
        );
        assert_eq!(
            original.temporal_memory.cells_per_column,
            restored.temporal_memory.cells_per_column
        );
        assert_eq!(
            original.temporal_memory.anomaly_mode,
            restored.temporal_memory.anomaly_mode
        );
    }
}
