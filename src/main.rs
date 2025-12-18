//! Bond: HTM-based binary analysis tool for code sequence clustering
//!
//! This tool uses Hierarchical Temporal Memory (HTM) to discover and detect
//! patterns in machine code sequences.

use std::path::PathBuf;

use anyhow::Result;
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};

use bond::binary::loader::load_binary;
use bond::cluster::detector::{ClusterDetector, InstructionResult};
use bond::disasm::decoder::X86Decoder;
use bond::htm::config::HtmConfig;
use bond::htm::pipeline::BondHtmPipeline;
use bond::persistence::model_io::{TrainedModel, TrainingMetadata};

#[derive(Parser)]
#[command(name = "bond")]
#[command(author, version, about = "HTM-based binary analysis tool for code sequence clustering")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Train the HTM model on binary files
    Train {
        /// Binary files to train on
        #[arg(required = true)]
        binaries: Vec<PathBuf>,

        /// Output model file
        #[arg(short, long, default_value = "bond_model.bin")]
        output: PathBuf,

        /// Number of training passes
        #[arg(short, long, default_value = "3")]
        passes: usize,
    },

    /// Analyze a binary using a trained model
    Analyze {
        /// Binary file to analyze
        #[arg(required = true)]
        binary: PathBuf,

        /// Trained model file
        #[arg(short, long, required = true)]
        model: PathBuf,

        /// Output format
        #[arg(short, long, default_value = "text")]
        format: OutputFormat,

        /// Output file (stdout if not specified)
        #[arg(short = 'O', long)]
        output: Option<PathBuf>,
    },

    /// List clusters in a trained model
    ListClusters {
        /// Trained model file
        #[arg(required = true)]
        model: PathBuf,

        /// Show detailed cluster information
        #[arg(short, long)]
        detailed: bool,

        /// Output format
        #[arg(short, long, default_value = "text")]
        format: OutputFormat,
    },

    /// Show model information
    Info {
        /// Trained model file
        #[arg(required = true)]
        model: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Train {
            binaries,
            output,
            passes,
        } => train(&binaries, &output, passes, cli.verbose),

        Commands::Analyze {
            binary,
            model,
            format,
            output,
        } => analyze(&binary, &model, format, output.as_deref(), cli.verbose),

        Commands::ListClusters {
            model,
            detailed,
            format,
        } => list_clusters(&model, detailed, format),

        Commands::Info { model } => show_info(&model),
    }
}

/// Train the HTM model on binaries
fn train(binaries: &[PathBuf], output: &PathBuf, passes: usize, verbose: bool) -> Result<()> {
    println!("Bond - Training HTM model");
    println!("==========================");
    println!("Binaries: {}", binaries.len());
    println!("Passes: {}", passes);
    println!();

    let config = HtmConfig::default();
    let mut pipeline = BondHtmPipeline::with_config(&config);
    let detector = ClusterDetector::new();

    let mut all_results: Vec<InstructionResult> = Vec::new();
    let mut binary_names = Vec::new();
    let mut total_instructions = 0usize;

    // Multi-pass training
    for pass in 0..passes {
        println!("Pass {}/{}...", pass + 1, passes);

        for path in binaries {
            if verbose {
                println!("  Processing: {:?}", path);
            }

            let loader = match load_binary(path) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("  Warning: Failed to load {:?}: {}", path, e);
                    continue;
                }
            };

            let arch = loader.architecture();
            let decoder = X86Decoder::new(arch);

            for section in loader.code_sections() {
                if verbose {
                    println!("    Section: {} ({} bytes)", section.name, section.data.len());
                }

                let instructions = decoder.decode_section(&section);

                pipeline.reset();
                for instr in &instructions {
                    let result = pipeline.process(instr, true);

                    // Only collect results on the final pass
                    if pass == passes - 1 {
                        all_results.push(InstructionResult {
                            instruction: instr.clone(),
                            result,
                        });
                        total_instructions += 1;
                    }
                }
            }

            if pass == passes - 1 {
                binary_names.push(
                    path.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                );
            }
        }
    }

    println!();
    println!("Detecting clusters...");

    // Detect clusters from the final pass results
    let clusters = detector.detect_clusters(&all_results);

    println!("Found {} clusters", clusters.len());

    // Create trained model
    let metadata = TrainingMetadata {
        binaries_processed: binaries.len(),
        instructions_processed: total_instructions,
        timestamp: Utc::now(),
        passes,
        binary_names,
    };

    let model = TrainedModel::new(config, clusters, metadata);

    // Save model
    model.save(output)?;
    println!();
    println!("Model saved to: {:?}", output);

    Ok(())
}

/// Analyze a binary using a trained model
fn analyze(
    binary: &PathBuf,
    model_path: &PathBuf,
    format: OutputFormat,
    output: Option<&std::path::Path>,
    verbose: bool,
) -> Result<()> {
    if verbose {
        println!("Loading model...");
    }

    let model = TrainedModel::load(model_path)?;
    let config = model.config.clone();
    let mut pipeline = BondHtmPipeline::with_config(&config);
    let detector = ClusterDetector::new();

    if verbose {
        println!("Analyzing binary: {:?}", binary);
    }

    let loader = load_binary(binary)?;
    let arch = loader.architecture();
    let decoder = X86Decoder::new(arch);

    let mut results: Vec<InstructionResult> = Vec::new();
    let mut high_anomalies: Vec<(u64, String, f32)> = Vec::new();

    for section in loader.code_sections() {
        let instructions = decoder.decode_section(&section);

        pipeline.reset();
        for instr in &instructions {
            let result = pipeline.process(instr, false);

            // Track high anomaly instructions
            if result.anomaly_score > 0.7 {
                high_anomalies.push((
                    instr.address,
                    instr.mnemonic.clone(),
                    result.anomaly_score,
                ));
            }

            results.push(InstructionResult {
                instruction: instr.clone(),
                result,
            });
        }
    }

    // Detect clusters in the analyzed binary
    let detected_clusters = detector.detect_clusters(&results);

    // Match against known clusters
    let mut known_matches = 0;
    for cluster in &detected_clusters {
        if detector
            .match_cluster(&cluster.fingerprint, &model.clusters)
            .is_some()
        {
            known_matches += 1;
        }
    }

    // Calculate overall anomaly
    let overall_anomaly = if results.is_empty() {
        0.0
    } else {
        results.iter().map(|r| r.result.anomaly_score as f64).sum::<f64>() / results.len() as f64
    };

    // Generate report
    let report = AnalysisReport {
        binary_path: binary.to_string_lossy().to_string(),
        total_instructions: results.len(),
        detected_clusters: detected_clusters.len(),
        known_cluster_matches: known_matches,
        overall_anomaly_score: overall_anomaly,
        high_anomalies: high_anomalies
            .into_iter()
            .take(20)
            .map(|(addr, mnem, score)| AnomalyEntry {
                address: format!("0x{:x}", addr),
                mnemonic: mnem,
                score,
            })
            .collect(),
        clusters: detected_clusters
            .iter()
            .map(|c| ClusterEntry {
                name: c.name.clone(),
                instruction_count: c.instruction_count,
                anomaly_mean: c.anomaly_score_mean,
            })
            .collect(),
    };

    let output_str = match format {
        OutputFormat::Text => format_report_text(&report),
        OutputFormat::Json => serde_json::to_string_pretty(&report)?,
    };

    match output {
        Some(path) => std::fs::write(path, output_str)?,
        None => println!("{}", output_str),
    }

    Ok(())
}

/// List clusters in a model
fn list_clusters(model_path: &PathBuf, detailed: bool, format: OutputFormat) -> Result<()> {
    let model = TrainedModel::load(model_path)?;

    match format {
        OutputFormat::Text => {
            println!("Clusters in model");
            println!("=================");
            println!();

            for cluster in &model.clusters {
                println!(
                    "{}: {} instructions, avg anomaly: {:.3}",
                    cluster.name, cluster.instruction_count, cluster.anomaly_score_mean
                );

                if detailed {
                    println!("  ID: {}", cluster.id);
                    println!("  Addresses: {:?}", cluster.start_addresses.iter().take(5).map(|a| format!("0x{:x}", a)).collect::<Vec<_>>());
                    println!(
                        "  Representative: {}",
                        cluster.representative_sequence.join(" -> ")
                    );
                    println!("  Fingerprint size: {}", cluster.fingerprint.size());
                    println!();
                }
            }

            println!();
            println!("Total: {} clusters", model.clusters.len());
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&model.clusters)?);
        }
    }

    Ok(())
}

/// Show model information
fn show_info(model_path: &PathBuf) -> Result<()> {
    let model = TrainedModel::load(model_path)?;

    println!("Bond Model Information");
    println!("======================");
    println!();
    println!("Version: {}", model.version);
    println!("Clusters: {}", model.num_clusters());
    println!("Total instructions: {}", model.total_instructions());
    println!();
    println!("Training:");
    println!("  Binaries processed: {}", model.metadata.binaries_processed);
    println!(
        "  Instructions processed: {}",
        model.metadata.instructions_processed
    );
    println!("  Passes: {}", model.metadata.passes);
    println!("  Timestamp: {}", model.metadata.timestamp);
    println!();
    println!("Configuration:");
    println!(
        "  SP columns: {:?}",
        model.config.spatial_pooler.column_dimensions
    );
    println!(
        "  TM cells/column: {}",
        model.config.temporal_memory.cells_per_column
    );
    println!(
        "  SP sparsity: {:.1}%",
        model.config.spatial_pooler.local_area_density * 100.0
    );

    Ok(())
}

// Report structures for output

#[derive(serde::Serialize)]
struct AnalysisReport {
    binary_path: String,
    total_instructions: usize,
    detected_clusters: usize,
    known_cluster_matches: usize,
    overall_anomaly_score: f64,
    high_anomalies: Vec<AnomalyEntry>,
    clusters: Vec<ClusterEntry>,
}

#[derive(serde::Serialize)]
struct AnomalyEntry {
    address: String,
    mnemonic: String,
    score: f32,
}

#[derive(serde::Serialize)]
struct ClusterEntry {
    name: String,
    instruction_count: usize,
    anomaly_mean: f64,
}

fn format_report_text(report: &AnalysisReport) -> String {
    let mut out = String::new();

    out.push_str("Bond Analysis Report\n");
    out.push_str("====================\n");
    out.push_str(&format!("Binary: {}\n", report.binary_path));
    out.push_str(&format!("Total Instructions: {}\n", report.total_instructions));
    out.push_str(&format!(
        "Overall Anomaly Score: {:.3}\n",
        report.overall_anomaly_score
    ));
    out.push_str("\n");

    out.push_str(&format!("Detected Clusters: {}\n", report.detected_clusters));
    out.push_str(&format!(
        "Known Cluster Matches: {}\n",
        report.known_cluster_matches
    ));
    out.push_str("\n");

    if !report.high_anomalies.is_empty() {
        out.push_str("High Anomaly Instructions:\n");
        for entry in &report.high_anomalies {
            out.push_str(&format!(
                "  {}: {} (score: {:.2})\n",
                entry.address, entry.mnemonic, entry.score
            ));
        }
        out.push_str("\n");
    }

    if !report.clusters.is_empty() {
        out.push_str("Cluster Summary:\n");
        for cluster in &report.clusters {
            out.push_str(&format!(
                "  {}: {} instructions, avg anomaly: {:.3}\n",
                cluster.name, cluster.instruction_count, cluster.anomaly_mean
            ));
        }
    }

    out
}
