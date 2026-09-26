# SBPF-EYE

SBPF bytecode analysis tool with a terminal UI for inspecting functions,
basic blocks, and instructions in Solana/SBPF ELF programs.

## Status

This is a work in progress. The current analysis is intentionally lightweight:
it extracts instructions, basic blocks, function entry points, reachability, and
direct call edges from the program text section.

Calls encoded as unresolved relocation placeholders, such as `src = 1,
imm = -1`, are not treated as direct local call edges unless the analyzer has
resolved them. This avoids false self-call edges.

## Usage

Run against the default sample:

```sh
cargo run
```

Run against a specific SBPF shared object:

```sh
cargo run -- samples/hello_solana_pinocchio_program.so
```

## Compiler Diff

Compare the same Rust program across all supported sBPF architectures:

```sh
cargo run -- compiler-diff <PROGRAM_DIR>
```

The default report shows build status, a compact summary, and important deltas
against the lowest successfully built version. Architectures are detected
automatically; use `--versions` only to limit the comparison:

```sh
cargo run -- compiler-diff <PROGRAM_DIR> --versions v0,v2,v3
```

Show opcode changes, function changes, and the detailed ELF size breakdown:

```sh
cargo run -- compiler-diff <PROGRAM_DIR> --verbose
```

Emit the complete analysis and comparison as JSON:

```sh
cargo run -- compiler-diff <PROGRAM_DIR> --json
```

Keep the separately built ELF files after the report:

```sh
cargo run -- compiler-diff <PROGRAM_DIR> --keep-builds
```

`PROGRAM_DIR` must contain the program's `Cargo.toml`. A failed or unsupported
architecture is reported without stopping the remaining builds.

## TUI Controls

| Key | Action |
| --- | --- |
| `Tab` | Move to the next pane |
| `Shift+Tab` | Move to the previous pane |
| `j` / `Down` | Move selection down |
| `k` / `Up` | Move selection up |
| `q` | Quit |
| `Ctrl-C` | Quit |

The TUI has three browser panes:

- Functions
- Blocks for the selected function
- Instructions for the selected block

The bottom detail panel shows the full selected item from the active pane and
wraps long text.

## Library API

The analyzer is exposed as a library so other frontends can reuse it:

```rust
use sbpf_eye::analyze_program;

let analysis = analyze_program("samples/hello_solana_pinocchio_program.so");

println!("{:?}", analysis.binary_info);
println!("functions: {}", analysis.functions.len());
println!("blocks: {}", analysis.blocks.len());
println!("instructions: {}", analysis.instructions.len());
```

Primary exported data:

- `ProgramAnalysis`
- `BinaryInfo`
- `Function`
- `BasicBlock`
- `InstructionMetadata`
- `Terminator`

## Development

Format and check:

```sh
cargo fmt
cargo check
cargo test
```

The included sample programs live in `samples/`.
