# sbpf-eye Binary Explorer

A local web interface over Blueshift's binary inspection/decoding libraries and
sbpf-eye's static analysis. The existing dark UI, upload/drop/paste workflows, and
standalone browser ELF fallback are preserved.

## Run

Requires Node.js 20+ and Rust with edition 2024 support (Blueshift declares Rust
1.90 minimum). The checked-in lockfile was validated with Rust 1.100 nightly.
No npm runtime dependencies, Solana CLI, or Blueshift CLI installation is needed.
From the repository root:

```sh
cd web
npm run build:bridge
npm run dev
```

Open **http://127.0.0.1:4173**. Cargo downloads the dependencies on the first build.
The bridge calls the local `sbpf-eye` library via `path = "../.."`.

```sh
# Optional binary/port override:
SBPF_EYE_BIN=/absolute/path/to/sbpf-eye-web-bridge PORT=4174 npm run dev

# Standalone JSON report:
./bridge/target/release/sbpf-eye-web-bridge ../samples/hello_solana_asm_program.so
```

`--stream` emits a low-level JSON checkpoint followed by the final JSON report.
The local server uses this mode to retain structure/disassembly if static analysis
crashes or times out. `SBPF_EYE_ARGS_JSON` can override the argument array; its
default is `["{file}","--stream"]`.

## Engine boundaries

Blueshift repository: **https://github.com/blueshift-gg/sbpf**.
Direct dependencies: **`sbpf-disassembler = 0.1.9` and `sbpf-common = 0.1.9`**,
matching sbpf-eye's existing decoder. Published disassembler source identifies
commit `fe93514d96b3bdd56091351aa42a18769303bb15`, directory `crates/disassembler`.

The bridge uses the public Rust APIs, not the CLI or scraped assembly output:

- `ELFHeader::from_elf_file`, `ProgramHeader::from_elf_file`,
  `SectionHeader::from_elf_file`, `Relocation::from_elf_file`.
- `sbpf_common::instruction::Instruction::{from_bytes, from_bytes_sbpf_v2}`
  and `to_asm(AsmFormat::Default)` for raw instruction decoding/formatting.
- `sbpf_eye::analyze_program(path)` and the public analysis accessors for
  functions, blocks, control-flow and call edges, reachability, and local stack estimates.

`Program::to_ixs_raw` is verified in integration tests but deliberately not the
inspection adapter: even its raw mode resolves some syscall names and processes
rodata. The component decoder lets inspection retain the decoded prefix on error
without those transformations. Original bytes remain authoritative.

| Feature | Owner / actual behavior |
|---|---|
| ELF header | Blueshift; structural `object` fallback on rejection |
| Program headers / segments | Blueshift; fallback preserves unknown types/flag bits |
| Section headers and raw data ranges | Blueshift; fallback for unsupported/unsafe inputs, including NOBITS |
| Symbol tables | Bridge structural fallback; Blueshift 0.1.9 exposes no symbol-table API |
| Relocation tables | Blueshift for supported `.rel.dyn` records; fallback retains all REL/RELA records, unknown types, table identity, and signed addends |
| Raw instruction disassembly / assembly text | Blueshift `sbpf-common`, the decoder used by its disassembler |
| Instruction encoding | Exact uploaded bytes and encoded fields; no assembler/editor or re-encoding in the UI |
| Function discovery | sbpf-eye |
| Basic blocks / CFG | sbpf-eye; bridge normalizes IDs and renders existing edges |
| Call graph | sbpf-eye; displayed as navigable function call edges |
| Reachability | sbpf-eye's CFG reachability from `.text+0`, excluding calls |
| Dead-code detection | No definitive dead-code metric exposed; unreachable is not presented as dead |
| Stack usage | sbpf-eye local estimate for fixed frames; dynamic/unknown-frame estimates withheld |
| Compiler comparison | Existing sbpf-eye CLI/library; unchanged, not added to the single-binary web flow |
| Compute-unit profiling | Not available from the inspected API; no fabricated metric |
| Solana loader validation / relocation application | Not implemented; reported separately |

The supplemental structural parser uses the same `object` dependency already
used by Blueshift. The former browser parser is only invoked when the bridge is
unavailable. See [ARCHITECTURE.md](ARCHITECTURE.md) for investigation details,
address rules, stage boundaries, and upstream limitations.

## Navigation

- **Overview:** ELF header, parsed counts, ELF-derived sBPF version, stage errors,
  and warnings. Counts describe available/decoded records, not runtime behavior.
- **ELF Explorer:** sections, segments, symbols, and relocations. Sections expose
  metadata, exact file bytes, and a filter for related symbols.
- **Disassembly:** `.text` byte offsets, virtual addresses, file offsets, raw
  bytes, opcode/operands, symbols, and relocation references. Select an instruction
  for byte highlighting and function/block links.
- **Functions:** select a function to show its instruction set, block links,
  call edges, reachability scope, and stack estimate.
- **Control Flow:** select nodes, follow successors/predecessors, or open a block's
  instructions. Drag the background to pan; scroll to zoom; scope by function.
- **Hex Viewer:** navigate by hexadecimal **file offset**. Section membership and
  instruction/known relocation field byte ranges are highlighted. Unknown
  relocation widths get a target location without an invented byte span.

Tables page in groups of 200; the graph shows up to 120 nodes from the current
page. Off-view edges remain navigable through predecessor/successor lists.

## Tests

From `web/`:

```sh
npm run test:bridge
npm test
cargo clippy --manifest-path bridge/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path ../Cargo.toml --target-dir bridge/target
```

The Rust tests build the debug bridge used by the HTTP tests. All core tests run
without a browser or npm dependencies. Tests use the four tracked ELF fixtures in
`../samples/` plus deliberate mutations of those binaries. No analysis data is
mocked. The subprocess-failure test emits a genuine bridge checkpoint before
injecting a process exit.

Optional browser checks:

```sh
npm install --no-save playwright
npx playwright install chromium
npm run test:browser
```

Alternatively set `BROWSER_EXECUTABLE` to an installed Chromium browser.
`PLAYWRIGHT_MODULE` can point to an existing Playwright module. Browser checks
cover real uploads, cross-navigation, CFG interaction, highlights, malformed
inputs, and mobile overflow; screenshots go to the system temporary directory
(`/tmp/sbpf-eye-cfg.png` and `/tmp/sbpf-eye-mobile.png`).

Validated: 15 Rust integration tests, 6 Node/HTTP tests, 16 existing sbpf-eye
tests, Clippy with warnings denied, and browser navigation/rendering checks.
The four tracked fixtures produced 4 / 537 / 2,786 / 1,100 instructions with no
boundary/count discrepancies between the engines. Details and limitations are
in [ARCHITECTURE.md](ARCHITECTURE.md).

## Operational limits

The service binds to loopback and accepts at most 8 MiB per upload. Analysis has a
30-second subprocess timeout, a 64 MiB JSON-frame output limit, and a 1 MiB stderr
limit. The upstream section-copy path is capped at 64 MiB total payload copies.
The bridge is a developer-local inspector, not a sandbox for executing programs.
It never executes the uploaded bytecode. Existing sbpf-eye analysis complexity
still affects large programs; successful checkpoints survive later failures.

## File inventory

Added:

- `bridge/src/lib.rs`, `blueshift.rs`, `eye.rs`, `elf.rs`, `addresses.rs`,
  `models.rs`, `errors.rs`: orchestration, engine adapters, structural recovery,
  address conversion, wire models, and panic boundary.
- `bridge/tests/integration.rs`, `bridge/tests/checkpoint-exit.mjs`:
  real-fixture integration and process-failure checks.
- `public/api/report.js`, `public/types/report.d.ts`, `public/navigation.js`:
  transport/fallback adapter, wire types, and testable navigation helpers.
- `browser-test.mjs`, `ARCHITECTURE.md`, `.gitignore`.

Updated:

- `bridge/src/main.rs`, `bridge/Cargo.toml`, `bridge/Cargo.lock`.
- `public/app.js`, `public/elf.js`, `public/index.html`, `public/styles.css`.
- `server.mjs`, `test.mjs`, `package.json`, `README.md`.

All implementation changes are contained in `web/`. The pre-existing untracked
web directory and parent working-tree edits were not staged or committed.
