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

Compare a Rust program using different architectures or compiler profiles.
`PROGRAM_DIR` must contain a `Cargo.toml`; workspace members are supported.

### Prerequisites

- macOS or Linux, with the selected builders installed and available on PATH.
- **Anza:** `cargo-build-sbf` and the platform-tools version requested by your profile.
- **Blueshift:** `cargo-build-sbpf`, `sbpf-linker >=0.2.3`, and Rust `nightly`
  with LLVM 23 and `rust-src`. Dated nightly selectors are currently unsupported.
  Programs must support `no_std`; local/global Cargo config is currently unsupported
  by this adapter.

Builds run offline, so fetch your program's dependencies and prepare its Cargo.lock
before comparing. sbpf-eye does not install tools or accept setup prompts.

### Compare architectures

Use Anza to compare supported v0–v3 architectures, or select versions explicitly
(v4 is opt-in):

```sh
cargo run -- compiler-diff <PROGRAM_DIR>
cargo run -- compiler-diff <PROGRAM_DIR> --versions v0,v2,v3
```

### Compare compiler profiles

Create a reusable config, then edit the printed file to match your installed tools:

```sh
cargo run -- compiler-diff --init-profiles
```

The starter config includes `anza-v0`, `anza-v3`, `anza-v4`, and `blueshift-v3`.
See [compiler-profiles.toml](examples/compiler-profiles.toml) for the format.
Anza v4 requires platform tools with the `sbpfv4-solana-solana` libraries installed;
a compiler that only lists the target is insufficient.
The saved file lives in `~/Library/Application Support/sbpf-eye/` on macOS,
or `$XDG_CONFIG_HOME/sbpf-eye/` (default `~/.config/sbpf-eye/`) on Linux.
Override its directory with `SBPF_EYE_CONFIG_DIR`.

```sh
# Compare two saved profiles
cargo run -- compiler-diff <PROGRAM_DIR> \
  --select anza-v3,blueshift-v3 --baseline anza-v3

# Compare Anza v3 and v4 (add anza-v4 from the example if using an older config)
cargo run -- compiler-diff <PROGRAM_DIR> \
  --select anza-v3,anza-v4 --baseline anza-v3

# Compare every saved profile
cargo run -- compiler-diff <PROGRAM_DIR> --saved-profiles

# Use a specific config file
cargo run -- compiler-diff <PROGRAM_DIR> \
  --profiles examples/compiler-profiles.toml --baseline anza-v3
```

The baseline defaults to the first selected profile in file order. Profile comparisons
cannot be combined with `--versions` or `--release`; set `release` in the TOML.

### Output and troubleshooting

Append these options to any comparison:

| Option | Purpose |
| --- | --- |
| `--format json` / `--json` | Complete results, metadata, and build logs |
| `--format markdown` | Report for an issue or pull request |
| `--verbose` | Detailed analysis and toolchain information |
| `--show-build-log` | Full stdout/stderr when a build fails |
| `--show-config` | Profile settings and build commands |
| `--show-target-spec` | Compiler target specification, when available |
| `--keep-builds` | Preserve temporary artifacts; combine with `--verbose` to see paths |

Each profile builds in an isolated copy; original project files are not changed.
Check profile statuses: a completed report can contain failed builds, and a failed
baseline produces no deltas. Static instruction counts are not measured compute units.

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


### Planned: Interactive compiler flags

Add visual compiler flag controls to SBPF Eye’s web compiler comparison view.

- Add, remove, and edit flags for each build profile.
- Rebuild and compare assembly, instruction count, binary size, stack usage, and CFG changes.
- Display the effective `rustc` flags and their sources, highlighting flags ignored by Cargo’s precedence rules.
- Support distinct **unset**, **empty**, and **custom** states for `RUSTFLAGS`.
- Show build diagnostics alongside configuration changes when removing a flag breaks compilation.

A motivating example: setting `RUSTFLAGS=""` suppresses target-configured SBPF flags, including `--cfg target_os="solana"`. Without that cfg, `pinocchio-log` selects an implementation requiring `std` and fails on `bpfel-unknown-none`.
