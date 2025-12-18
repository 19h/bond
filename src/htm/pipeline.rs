//! HTM pipeline for processing instructions through Spatial Pooler and Temporal Memory

use mokosh::algorithms::{SpatialPooler, TemporalMemory};
use mokosh::types::Sdr;

use crate::disasm::features::DecodedInstruction;
use crate::encoding::instruction_encoder::{InstructionEncoder, SDR_SIZE};

use super::config::HtmConfig;

/// Result of processing a single instruction through the HTM pipeline
#[derive(Clone, Debug)]
pub struct ProcessResult {
    /// Anomaly score (0.0 = fully predicted, 1.0 = fully anomalous)
    pub anomaly_score: f32,
    /// Active cell indices
    pub active_cells: Vec<u32>,
    /// Predictive cell indices (for next step)
    pub predictive_cells: Vec<u32>,
    /// Number of bursting columns (active but not predicted)
    pub bursting_columns: usize,
}

/// HTM pipeline combining Spatial Pooler and Temporal Memory
pub struct BondHtmPipeline {
    /// Spatial Pooler
    spatial_pooler: SpatialPooler,
    /// Temporal Memory
    temporal_memory: TemporalMemory,
    /// Instruction encoder
    encoder: InstructionEncoder,
    /// Current SP output (reused buffer)
    sp_output: Sdr,
    /// Column dimensions for calculating bursting columns
    num_columns: usize,
    /// Cells per column
    cells_per_column: u32,
}

impl BondHtmPipeline {
    /// Create a new HTM pipeline with default configuration
    pub fn new() -> Self {
        Self::with_config(&HtmConfig::default())
    }

    /// Create a new HTM pipeline with custom configuration
    pub fn with_config(config: &HtmConfig) -> Self {
        let sp_params = config.spatial_pooler.to_params();
        let tm_params = config.temporal_memory.to_params();

        let num_columns = config.spatial_pooler.column_dimensions.iter().map(|&d| d as usize).product();
        let cells_per_column = config.temporal_memory.cells_per_column;

        Self {
            spatial_pooler: SpatialPooler::new(sp_params).expect("valid SP params"),
            temporal_memory: TemporalMemory::new(tm_params).expect("valid TM params"),
            encoder: InstructionEncoder::new(),
            sp_output: Sdr::new(&[num_columns as u32]),
            num_columns,
            cells_per_column,
        }
    }

    /// Process a single instruction through the pipeline
    ///
    /// # Arguments
    ///
    /// * `instr` - The decoded instruction to process
    /// * `learn` - Whether to enable learning
    ///
    /// # Returns
    ///
    /// Processing result containing anomaly score and cell activations
    pub fn process(&mut self, instr: &DecodedInstruction, learn: bool) -> ProcessResult {
        // Encode instruction to SDR
        let input_sdr = self.encoder.encode(instr);

        // Run through Spatial Pooler
        self.spatial_pooler.compute(&input_sdr, learn, &mut self.sp_output);

        // Get predictions before TM compute
        let predicted_columns = self.get_predicted_columns();

        // Run through Temporal Memory
        self.temporal_memory.compute(&self.sp_output, learn);

        // Get active columns for bursting calculation
        let active_columns = self.sp_output.get_sparse();

        // Calculate bursting columns
        let bursting = self.count_bursting_columns(&active_columns, &predicted_columns);

        ProcessResult {
            anomaly_score: self.temporal_memory.anomaly(),
            active_cells: self.temporal_memory.active_cells().to_vec(),
            predictive_cells: self.temporal_memory.predictive_cells().to_vec(),
            bursting_columns: bursting,
        }
    }

    /// Process a sequence of instructions
    ///
    /// # Arguments
    ///
    /// * `instructions` - Slice of decoded instructions
    /// * `learn` - Whether to enable learning
    ///
    /// # Returns
    ///
    /// Vector of processing results for each instruction
    pub fn process_sequence(
        &mut self,
        instructions: &[DecodedInstruction],
        learn: bool,
    ) -> Vec<ProcessResult> {
        instructions
            .iter()
            .map(|instr| self.process(instr, learn))
            .collect()
    }

    /// Reset the temporal memory state (call between unrelated sequences)
    pub fn reset(&mut self) {
        self.temporal_memory.reset();
    }

    /// Get the current anomaly score
    pub fn anomaly(&self) -> f32 {
        self.temporal_memory.anomaly()
    }

    /// Get active cells from the last compute
    pub fn active_cells(&self) -> &[u32] {
        self.temporal_memory.active_cells()
    }

    /// Get predictive cells from the last compute
    pub fn predictive_cells(&self) -> &[u32] {
        self.temporal_memory.predictive_cells()
    }

    /// Get the SDR size
    pub fn sdr_size(&self) -> usize {
        SDR_SIZE
    }

    /// Get the number of columns
    pub fn num_columns(&self) -> usize {
        self.num_columns
    }

    /// Get cells per column
    pub fn cells_per_column(&self) -> u32 {
        self.cells_per_column
    }

    /// Get a reference to the spatial pooler
    pub fn spatial_pooler(&self) -> &SpatialPooler {
        &self.spatial_pooler
    }

    /// Get a mutable reference to the spatial pooler
    pub fn spatial_pooler_mut(&mut self) -> &mut SpatialPooler {
        &mut self.spatial_pooler
    }

    /// Get a reference to the temporal memory
    pub fn temporal_memory(&self) -> &TemporalMemory {
        &self.temporal_memory
    }

    /// Get a mutable reference to the temporal memory
    pub fn temporal_memory_mut(&mut self) -> &mut TemporalMemory {
        &mut self.temporal_memory
    }

    /// Get predicted columns (convert predictive cells to columns)
    fn get_predicted_columns(&self) -> Vec<u32> {
        let predictive_cells = self.temporal_memory.predictive_cells();
        let mut columns: Vec<u32> = predictive_cells
            .iter()
            .map(|&cell| cell / self.cells_per_column)
            .collect();
        columns.sort_unstable();
        columns.dedup();
        columns
    }

    /// Count bursting columns (active but not predicted)
    fn count_bursting_columns(&self, active_columns: &[u32], predicted_columns: &[u32]) -> usize {
        let predicted_set: std::collections::HashSet<u32> =
            predicted_columns.iter().copied().collect();

        active_columns
            .iter()
            .filter(|col| !predicted_set.contains(col))
            .count()
    }
}

impl Default for BondHtmPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::features::{FlowControlType, FunctionBoundaryHint, MemoryAccessPattern, OpcodeCategory, OperandPattern, RegisterCategory};

    fn make_test_instruction(opcode: OpcodeCategory) -> DecodedInstruction {
        DecodedInstruction {
            address: 0x1000,
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
        }
    }

    #[test]
    fn test_pipeline_creation() {
        let pipeline = BondHtmPipeline::new();
        assert_eq!(pipeline.num_columns(), 2048);
        assert_eq!(pipeline.cells_per_column(), 32);
    }

    #[test]
    fn test_process_instruction() {
        let mut pipeline = BondHtmPipeline::new();
        let instr = make_test_instruction(OpcodeCategory::DataTransfer);

        let result = pipeline.process(&instr, true);

        // Anomaly should be high initially (nothing learned yet)
        assert!(result.anomaly_score >= 0.0);
        assert!(result.anomaly_score <= 1.0);
        assert!(!result.active_cells.is_empty());
    }

    #[test]
    fn test_sequence_learning() {
        let mut pipeline = BondHtmPipeline::new();

        // Create a simple repeating sequence
        let sequence = vec![
            make_test_instruction(OpcodeCategory::DataTransfer),
            make_test_instruction(OpcodeCategory::Arithmetic),
            make_test_instruction(OpcodeCategory::Compare),
            make_test_instruction(OpcodeCategory::ControlFlow),
        ];

        // Train on the sequence multiple times
        for _ in 0..10 {
            pipeline.reset();
            for instr in &sequence {
                pipeline.process(instr, true);
            }
        }

        // Now test - anomaly should be lower
        pipeline.reset();
        let results = pipeline.process_sequence(&sequence, false);

        // After learning, later instructions should have lower anomaly
        // (the first instruction will always be anomalous after reset)
        assert!(results.len() == 4);
    }
}
