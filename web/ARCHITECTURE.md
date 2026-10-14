# Investigation and integration design

## Findings before integration

The starting web app was dependency-free browser JavaScript, not React or a
bundled TypeScript application. `public/elf.js` parsed ELF64 little-endian headers,
sections, symbols, and relocations. Its top-level parse failed on malformed
payloads, which also prevented invoking the Rust analyzer. The 29-line Rust
bridge serialized untyped JSON and Rust Debug strings from sbpf-eye. File and
virtual offsets were mixed in relocation navigation; function/block selection
only appended raw JSON. The server spawned the bridge with a temporary file.

The existing sbpf-eye library already depends on Blueshift's 0.1.9 crates.
`analyze_program` loads `Program::from_bytes`, finds `.text`, decodes through
`sbpf-common`, then runs private function-discovery, block-construction,
reachability, call-edge, and stack algorithms. Its public metadata/accessor APIs
are sufficient for the adapter. No algorithms were copied or changed. Its CLI
uses those APIs in a ratatui TUI; `compiler-diff` calls the public compiler
comparison module. Compiler comparison invokes `cargo-build-sbf` and has separate
build/output models. There is no compute-unit profiling API in these sources.

Blueshift is https://github.com/blueshift-gg/sbpf. The inspected published
`sbpf-disassembler` 0.1.9 source, recorded at commit
`fe93514d96b3bdd56091351aa42a18769303bb15`, exposes public serde-capable Rust
structs and component parsing functions. Dependencies include `sbpf-common`,
`object`, `either`, serde, and thiserror; WASM bindings are target-gated. There is
no need to install or spawn its `sbpf disassemble` CLI.

The available 0.3.0 source was also compared: it changes errors/results to vectors
and `Parsed<Disassembly>`, and `Program::from_bytes` synthesizes section views
for sectionless v3 binaries. This integration deliberately pins 0.1.9 to the
existing sbpf-eye decoder rather than silently upgrading the CLI or using two
versions of the instruction model. Supporting the newer version is a separate
adapter/version migration; sectionless binaries remain structurally inspectable.

### What is and is not reused

- Header, program-header, and section-header APIs are used directly where safe.
  `object` parsing supplies bounds-checked structural recovery and supplemental
  fields. Raw file ranges avoid shipping all section payloads again as JSON.
- Blueshift's section reader slices all declared payloads, including NOBITS,
  without sufficient bounds checks. The bridge checks copy bounds/size first,
  skips this path for NOBITS, and catches recoverable upstream panics. Structural
  inspection does not require successful strict Blueshift parsing.
- `Relocation::from_elf_file` only reads `.rel.dyn` and accepts types 0, 1, 8,
  and 10; symbol names are resolved for calls only. It does not expose general
  symbol tables, RELA addends, or arbitrary relocation-table identity. Those
  records are retained in the bridge's structural fallback. A record is credited
  to Blueshift only when the parsed offset/type/symbol match the raw record.
- `Instruction::from_bytes[_sbpf_v2]` and `to_asm` provide actual disassembly.
  The bridge iterates bounded instruction windows; it contains no opcode decoder.
  `Instruction::to_bytes` exists upstream but is not used as a substitute for
  original bytes: it normalizes encodings and is not a version-preserving round trip.
- `Program::to_ixs` rewrites branch/call offsets to instruction indices and
  resolves references; `to_ixs_raw` avoids some rewrites but still handles syscall
  relocations and rodata. Neither is a Solana loader simulation. sbpf-eye's
  `Program::from_bytes` and direct decoder do not apply relocations either.

## Execution flow

```text
upload / paste
  → Node size limit and temporary immutable file
  → Rust structural inspection + Blueshift component adapters
  → Blueshift instruction decoding (retains successful prefix)
  → symbols/relocations mapped to sections, file bytes, and instructions
  → low-level JSON checkpoint
  → sbpf-eye::analyze_program on the same unmodified file
  → compare instruction boundaries/counts and attach analysis IDs
  → unified schema-v1 report
  → frontend API adapter → engine-independent views
```

`bridge/src/lib.rs` makes this ordering explicit. `models.rs` is the wire contract;
`blueshift.rs` and `eye.rs` contain engine calls, `elf.rs` handles structural
fallback and unsupported tables, `addresses.rs` owns conversions, and `errors.rs`
contains the panic boundary. `main.rs` only handles file/JSON I/O.

The original sbpf-eye CLI sources and algorithms are untouched, including any
pre-existing working-tree modifications. There is no new JS disassembler,
vendor copy, fork, or frontend framework.

Structural failures, strict parsing failures, decoding failures, static analysis,
loader validation, and relocation application have distinct stage records. Empty
and invalid files still return a report with stage errors and preserve raw bytes
for the hex view. If sbpf-eye returns an error/panics, existing results survive.
The server can recover a completed low-level checkpoint on later process exit,
timeout, or output-limit termination. A failure before any checkpoint falls back
to the original browser structural inspector; its existing ELF64/LE limits apply.

## Address contract

- ELF `u64` values use hexadecimal JSON strings; signed addends use decimal
  strings. No 64-bit address passes through JavaScript `Number`.
- Validated file ranges use bounded numeric offsets/lengths (uploads ≤8 MiB).
- Instruction `pc` and block `[startPc, endPc)` are **byte offsets in `.text`**,
  not 8-byte slot indices or virtual addresses. `lddw` occupies 16 bytes.
- `Location` separately stores section ID, section-relative offset, optional
  file offset, and optional virtual address.
- A file-backed section maps relative byte `r` to `sh_offset + r`; an allocated
  linked section maps to VA `sh_addr + r`. Bounds and addition are checked.
- ET_REL relocation offsets are relative to the section named by `sh_info`.
  ET_EXEC/ET_DYN relocation offsets are VAs; only a unique allocated-section
  mapping is accepted. Overlapping candidates remain unresolved, never guessed.
- NOBITS can have a memory location but never file bytes. Absolute, undefined,
  and reserved-index symbols do not receive invented section mappings.
- Relocations in data are not forced onto instructions. A target in a decoded
  instruction can link to that instruction; known field widths get byte ranges.
  LDDW's two immediate fields are highlighted separately. Unknown relocation
  kinds preserve the record/location without inventing a write width.
- Function membership is a set of block ranges, not a fabricated contiguous
  function extent. Instruction/block linkage requires matching engine boundaries.

## Version and analysis limitations

The bridge identifies the ELF flag as an sBPF version only for the supported
machine/flag combinations below. This is header evidence, not loader validation.

| Machine | Flags | Decoding path |
|---|---|---|
| EM_BPF (247) | 0, 3 | Standard Blueshift decoder |
| EM_SBPF (263) | 0, 1 | Standard Blueshift decoder |
| EM_SBPF (263) | 2 | Blueshift v2 opcode compatibility adapter |
| Other combinations | Any | Structural inspection; decode/analysis skipped |

The 0.1.9 decoder is not a complete version-specific ISA validator. v2 rewrites
some opcode encodings internally, while the report retains the original bytes.
The adapter does not claim that successful decoding proves loader acceptance.
Sectionless binaries retain headers/segments/hex but are not decoded by this
pinned adapter. Big-endian ELF64 structure is inspectable through `object`, but
sBPF decoding is skipped. ELF32 is not supported. Malformed whole tables can be
unavailable while the header and independent tables remain accessible.

sbpf-eye assumes a root at `.text+0`, discovers direct relative call targets,
and reports function reachability via CFG edges only, excluding calls. The
bridge exposes this exact scope and warns when ELF `e_entry` differs from the
text start. It does not infer definitive dead code, indirect-call targets, or
block reachability not supplied by the public API. Direct call edges remain
available separately. Symbol names label addresses but do not replace discovery.

Local stack usage is a static maximum negative r10 memory offset. Following
sbpf-eye's own compiler comparison policy, fixed-frame estimates are displayed
and dynamic/unknown-frame estimates are withheld; raw offsets are kept in the
model as diagnostics. Cumulative stack estimates remain available through the
existing library/CLI and are not added to every function in this web flow.

Both engine instruction lists are reconciled by byte offset and span. Differences
produce an explicit warning with counts and the first differing pair; only exact
matches acquire block/function links. No disagreements were found in the four
tracked fixtures. A mutated final partial slot demonstrates that sbpf-eye ignores
trailing bytes while the bridge reports a partial decode; the complete instruction
prefix still agrees. No failed stage erases a successful one.

## Validation and future WASM work

Integration tests use all four tracked `samples/*.so` fixtures and byte-level
mutations for malformed records, invalid branches/opcodes, unsupported relocation
types, ET_REL, RELA, NOBITS, sectionless files, high addresses, and v2 decoding.
They check raw offsets against upstream structs, Blueshift `to_ixs_raw` counts,
byte round trips to the original file, membership links, and independent failures.
Node tests cover transport, typed schema shape, navigation helpers, upload limits,
and real checkpoint recovery. Browser tests exercise the connected UI rather than
mock report data. The extra untracked `account_data_upstream_program.so` was
manually inspected: headers/segments survive; sectionless analysis is unavailable.

Blueshift already has target-gated WASM bindings. A future client-side adapter
would need sbpf-eye to expose a bytes-based analysis entry point, separate its
terminal/compiler-process dependencies for WASM, compile this normalization layer
with browser-safe error handling, and run it in a worker with resource limits.
It would retain the same wire schema and replace only the API transport. A WASM
rewrite, compiler execution, loader simulation, and runtime CU profiling are not
part of this integration.
