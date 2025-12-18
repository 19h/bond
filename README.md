# Bond

Bond is an experimental binary analysis tool that uses Hierarchical Temporal Memory (HTM) to learn patterns in machine code. Rather than relying on signatures or heuristics, Bond learns the "texture" of code—the temporal relationships between instructions that emerge from how compilers structure programs.

## The Problem

Traditional binary analysis tools treat instructions as isolated units or rely on pattern matching against known signatures. This works until it doesn't: polymorphic code, compiler variations, and novel constructs break these approaches. What if we could learn what "normal" code looks like and detect deviations from that baseline?

## The Approach

HTM is a machine learning algorithm inspired by the neocortex. Unlike neural networks that learn static mappings, HTM learns *sequences*. It builds a model of what typically follows what, making it naturally suited for analyzing instruction streams.

Bond works in three stages:

1. **Encoding**: Each instruction becomes a Sparse Distributed Representation (SDR)—a 2048-bit vector where roughly 2% of bits are active. The encoding captures semantic features: opcode category, register usage, memory access patterns, control flow type, and function boundary hints.

2. **Learning**: The HTM Temporal Memory processes instruction sequences, learning which patterns typically follow others. After training on normal code, it can identify anomalous sequences—instructions that don't fit the learned patterns.

3. **Clustering**: Instructions are grouped into clusters based on control flow boundaries (calls, returns, jumps) and anomaly spikes. These clusters roughly correspond to functions or code blocks and can be compared across binaries.

## Understanding the Encoding

The SDR encoding is the critical bridge between raw instructions and HTM processing. Here's why specific features matter:

**Opcode Category** (128 bits): Groups instructions by semantic function—data transfer, arithmetic, logic, control flow, etc. This lets HTM generalize across specific opcodes.

**Mnemonic Hash** (256 bits): A distributed hash of the specific mnemonic. `MOV` and `LEA` are both data transfer but behave differently; this captures that distinction.

**Register Usage** (512 bits): Which register categories are read/written. The pattern `[read: GeneralPurpose64, write: StackPointer]` is characteristic of certain operations.

**Function Boundary Hints** (128 bits): Prologue patterns (`push rbp`, `mov rbp, rsp`, `sub rsp, N`) and epilogue patterns (`pop rbp`, `ret`) get explicit encoding. This helps HTM recognize function structure.

The encoding uses *semantic overlap*: similar instructions share active bits. A `MOV RAX, RBX` and `MOV RCX, RDX` will have high overlap (same category, same pattern), while `MOV RAX, [RBP-8]` will differ (memory access pattern changes). This property is essential for HTM's pattern matching.

## How Anomaly Detection Works

HTM maintains a model of "what comes next." After seeing `push rbp` thousands of times followed by `mov rbp, rsp`, it learns this transition. When processing new code:

- **Expected sequences** produce low anomaly scores (near 0)
- **Unexpected sequences** produce high anomaly scores (near 1)

In practice, HTM learns common patterns quickly—too quickly. After modest training, most code produces near-zero anomaly because compilers generate predictable instruction sequences. The anomaly score alone isn't enough for useful analysis.

## Cluster-Based Analysis

Bond's practical value comes from cluster analysis rather than raw anomaly scores. Clusters are delimited by:

1. **Control flow boundaries**: CALL, RET, and unconditional JMP instructions
2. **Anomaly spikes**: Points where anomaly score increases 5x from the previous instruction
3. **Fingerprint discontinuities**: Points where the HTM's internal state changes dramatically

Each cluster gets a signature: dominant opcode category, instruction count, presence of loops/calls, average anomaly. These signatures enable cross-binary comparison—finding similar functions across different executables.

## Cross-Binary Matching

Given clusters from two binaries, Bond computes signature similarity:

```
similarity = jaccard(category_distribution_A, category_distribution_B)
           × size_similarity
           × structural_match(has_call, has_loop, ...)
```

A loop-heavy function in binary A will match loop-heavy functions in binary B, even if the specific instructions differ. This is useful for:

- Finding code reuse across binaries
- Identifying common library functions
- Detecting similar malware variants

## Working with Bond

Training on a corpus of "normal" binaries:

```rust
let mut pipeline = BondHtmPipeline::new();

for binary in training_corpus {
    let instructions = disassemble(binary);
    for instr in instructions {
        pipeline.process(&instr, true); // true = learning enabled
    }
}
```

Analyzing a target binary:

```rust
let instructions = disassemble(target);
let results: Vec<InstructionResult> = instructions
    .iter()
    .map(|instr| InstructionResult {
        instruction: instr.clone(),
        result: pipeline.process(instr, false), // false = inference only
    })
    .collect();

let detector = ClusterDetector::new();
let clusters = detector.detect_clusters(&results);
```

Comparing clusters across binaries:

```rust
for cluster_a in &clusters_binary_a {
    for cluster_b in &clusters_binary_b {
        let sim = cluster_a.signature.similarity(&cluster_b.signature);
        if sim > 0.7 {
            println!("Match: {:?} <-> {:?}", cluster_a, cluster_b);
        }
    }
}
```

## Limitations and Gotchas

**HTM learns fast**. After a few hundred instructions, most common patterns are learned. This means anomaly-based detection has diminishing returns—almost everything looks "normal" after training.

**The encoding matters more than the algorithm**. Most of Bond's discriminative power comes from how instructions are encoded, not from HTM magic. A different encoding scheme would produce very different results.

**Cluster boundaries are heuristic**. The boundary detection uses thresholds tuned for typical compiler output. Obfuscated code or hand-written assembly may not cluster cleanly.

**This is experimental**. Bond is a research tool exploring whether HTM is useful for binary analysis. It's not production malware detection software.

## Why HTM?

HTM has properties that make it interesting for this domain:

- **Online learning**: Updates incrementally, no batch training required
- **Sequence modeling**: Naturally captures temporal patterns
- **Sparse representations**: Efficient and noise-tolerant
- **Biological plausibility**: The algorithm mimics how cortical columns process sensory input

Whether these properties translate to practical advantages over simpler approaches (n-gram models, RNNs, transformers) is an open question. Bond exists partly to explore that question.

## Building

```bash
cargo build --release
cargo test
```

The test suite includes a C corpus that gets compiled to test binaries. Make sure you have `gcc` available:

```bash
cd tests/corpus && ./build.sh
```

## The Name

Bond. Binary analysis through Online Neural Detection. Or maybe it's about finding connections between code patterns. Or it just sounded good. Pick your interpretation.
