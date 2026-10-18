mod backend;
pub mod profiles;
pub mod render;
use crate::{ElfSizes, ProgramAnalysis, StackModel, analyze_program, cumulative_stack_usage};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct SbpfVersion(u32);

impl SbpfVersion {
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    pub fn number(self) -> u32 {
        self.0
    }

    pub fn as_arch(self) -> String {
        format!("v{}", self.0)
    }
}

impl std::fmt::Display for SbpfVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(&format!("v{}", self.0))
    }
}

impl std::str::FromStr for SbpfVersion {
    type Err = CompilerDiffError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let trimmed = value.trim();
        let number = trimmed
            .strip_prefix('v')
            .or_else(|| trimmed.strip_prefix('V'))
            .unwrap_or(trimmed)
            .parse::<u32>()
            .map_err(|_| CompilerDiffError::InvalidVersion(trimmed.to_string()))?;
        if number > 4 {
            return Err(CompilerDiffError::InvalidVersion(trimmed.to_string()));
        }
        Ok(Self(number))
    }
}

#[derive(Debug, Clone, Default)]
pub struct CompilerDiffOptions {
    /// Empty selects supported v0–v3 architectures; v4 requires explicit selection.
    pub requested_versions: Vec<SbpfVersion>,
    pub release: bool,
    pub keep_builds: bool,
}

#[derive(Debug, Error)]
pub enum CompilerDiffError {
    #[error("invalid sBPF version `{0}`")]
    InvalidVersion(String),
    #[error("no versions requested")]
    NoVersionsRequested,
    #[error("no successful builds to compare")]
    NoSuccessfulBuilds,
    #[error("failed to inspect cargo-build-sbf support: {0}")]
    ToolchainProbe(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Analysis(#[from] crate::AnalyzerError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum BuildState {
    Compiled,
    Unsupported,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuildResult {
    pub version: SbpfVersion,
    pub state: BuildState,
    pub elf_path: Option<PathBuf>,
    pub detected_version: Option<u32>,
    pub stdout: String,
    pub stderr: String,
    pub message: Option<String>,
}

impl BuildResult {
    pub fn compiled(version: SbpfVersion, elf_path: PathBuf, detected_version: u32) -> Self {
        Self {
            version,
            state: BuildState::Compiled,
            elf_path: Some(elf_path),
            detected_version: Some(detected_version),
            stdout: String::new(),
            stderr: String::new(),
            message: None,
        }
    }

    pub fn unsupported(version: SbpfVersion, message: impl Into<String>) -> Self {
        Self {
            version,
            state: BuildState::Unsupported,
            elf_path: None,
            detected_version: None,
            stdout: String::new(),
            stderr: String::new(),
            message: Some(message.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompilerDiff {
    options: CompilerDiffOptions,
}

impl CompilerDiff {
    pub fn new(options: CompilerDiffOptions) -> Result<Self, CompilerDiffError> {
        Ok(Self { options })
    }

    fn legacy_report(named: profiles::ProfileReport) -> CompilerDiffReport {
        let mut versions: Vec<_> = named
            .profiles
            .iter()
            .filter_map(|r| r.analysis.clone())
            .collect();
        versions.sort_by_key(|a| a.version);
        let baseline = versions
            .first()
            .map(|a| a.version)
            .unwrap_or(SbpfVersion::new(0));
        let deltas = versions
            .first()
            .map(|base| {
                versions
                    .iter()
                    .skip(1)
                    .map(|a| VersionDelta::from_summaries(base, a))
                    .collect()
            })
            .unwrap_or_default();
        let builds = named
            .profiles
            .iter()
            .map(|r| BuildResult {
                version: SbpfVersion::new(r.profile.sbpf_version.number()),
                state: match r.status {
                    profiles::ProfileStatus::Analyzed | profiles::ProfileStatus::Built => {
                        BuildState::Compiled
                    }
                    profiles::ProfileStatus::Unsupported => BuildState::Unsupported,
                    _ => BuildState::Failed,
                },
                elf_path: r.elf_path.clone(),
                detected_version: r.actual_architecture,
                stdout: r
                    .build
                    .as_ref()
                    .map(|b| b.stdout.clone())
                    .unwrap_or_default(),
                stderr: r
                    .build
                    .as_ref()
                    .map(|b| b.stderr.clone())
                    .unwrap_or_default(),
                message: r.diagnostic.clone(),
            })
            .collect();
        CompilerDiffReport {
            build_root: named.build_root.clone(),
            profile_report: Some(named),
            baseline,
            builds,
            versions,
            deltas,
        }
    }

    pub fn compile_and_compare(
        &self,
        program_dir: &Path,
    ) -> Result<CompilerDiffReport, CompilerDiffError> {
        let named = self.profile_report(program_dir, self.options.keep_builds)?;
        Ok(Self::legacy_report(named))
    }

    fn profile_report(
        &self,
        program_dir: &Path,
        keep: bool,
    ) -> Result<profiles::ProfileReport, CompilerDiffError> {
        let supported = detect_supported_architectures()?;
        let versions = versions_to_build(&self.options.requested_versions, &supported);
        let config = profiles::ProfileConfig {
            profiles: versions
                .into_iter()
                .map(|version| {
                    let arch = match version.number() {
                        0 => profiles::Architecture::V0,
                        1 => profiles::Architecture::V1,
                        2 => profiles::Architecture::V2,
                        3 => profiles::Architecture::V3,
                        4 => profiles::Architecture::V4,
                        _ => return Err(CompilerDiffError::InvalidVersion(version.to_string())),
                    };
                    Ok(profiles::CompilerProfile {
                        name: version.as_arch(),
                        backend: profiles::BuilderSettings::Anza {
                            platform_tools_version: None,
                        },
                        builder_path: None,
                        sbpf_version: arch,
                        release: true,
                        opt_level: None,
                        builder_args: vec![],
                        cargo_args: vec![],
                        env: BTreeMap::new(),
                    })
                })
                .collect::<Result<Vec<_>, CompilerDiffError>>()?,
        };
        profiles::compare_profiles(program_dir, config, None, keep)
            .map_err(|e| CompilerDiffError::ToolchainProbe(format!("{e:#}")))
    }

    pub fn build_versions(
        &self,
        program_dir: &Path,
    ) -> Result<Vec<BuildResult>, CompilerDiffError> {
        // This low-level API returns artifact paths; callers own cleanup, as before.
        Ok(Self::legacy_report(self.profile_report(program_dir, true)?).builds)
    }

    pub fn compare_binaries(
        &self,
        binaries: Vec<(SbpfVersion, PathBuf)>,
    ) -> Result<CompilerDiffReport, CompilerDiffError> {
        compare_binaries(binaries)
    }
}

pub fn compile_and_compare(
    program_dir: &Path,
    options: CompilerDiffOptions,
) -> Result<CompilerDiffReport, CompilerDiffError> {
    CompilerDiff::new(options)?.compile_and_compare(program_dir)
}

pub fn compare_binaries(
    mut binaries: Vec<(SbpfVersion, PathBuf)>,
) -> Result<CompilerDiffReport, CompilerDiffError> {
    binaries.sort_by_key(|(version, _)| *version);
    let build_root = binaries
        .first()
        .and_then(|(_, path)| path.parent().and_then(Path::parent).map(Path::to_path_buf))
        .unwrap_or_else(compiler_diff_build_root);

    let mut versions = Vec::new();
    let mut builds = Vec::new();
    for (version, path) in binaries {
        match analyze_binary(version, &path) {
            Ok(summary) => {
                builds.push(BuildResult::compiled(
                    version,
                    path.clone(),
                    summary.detected_sbpf_version,
                ));
                versions.push(summary);
            }
            Err(error) => builds.push(BuildResult {
                version,
                state: BuildState::Failed,
                elf_path: Some(path),
                detected_version: None,
                stdout: String::new(),
                stderr: String::new(),
                message: Some(format!("analysis failed: {error}")),
            }),
        }
    }

    if versions.is_empty() {
        return Err(CompilerDiffError::NoSuccessfulBuilds);
    }

    let baseline = versions[0].version;
    let deltas = versions
        .iter()
        .skip(1)
        .map(|summary| VersionDelta::from_summaries(&versions[0], summary))
        .collect();

    Ok(CompilerDiffReport {
        profile_report: None,
        build_root,
        baseline,
        builds,
        versions,
        deltas,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct BinaryAnalysisSummary {
    pub version: SbpfVersion,
    pub path: PathBuf,
    pub detected_sbpf_version: u32,
    pub file_size: usize,
    pub text_section_size: usize,
    pub elf_sizes: ElfSizesSummary,
    pub instruction_count: usize,
    pub opcode_counts: BTreeMap<String, usize>,
    pub function_count: usize,
    pub basic_block_count: usize,
    pub cfg_edge_count: usize,
    pub reachable_block_count: usize,
    pub unreachable_block_count: usize,
    pub reachable_instruction_count: usize,
    pub unreachable_instruction_count: usize,
    pub stack: StackAnalysis,
    pub functions: BTreeMap<FunctionKey, FunctionSummary>,
    pub decode_failures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FunctionKey {
    Symbol(String),
    Structural(String),
}

impl Serialize for FunctionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl std::fmt::Display for FunctionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FunctionKey::Symbol(name) | FunctionKey::Structural(name) => f.pad(name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionSummary {
    pub key: FunctionKey,
    pub instruction_count: usize,
    pub block_count: usize,
    pub local_stack_usage: Option<usize>,
    pub cumulative_stack_usage: Option<usize>,
    pub reachable_from_program_entry: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StackModelSummary {
    FixedFrame,
    DynamicFrame,
    Unknown,
}

impl std::fmt::Display for StackModelSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::FixedFrame => "fixed",
            Self::DynamicFrame => "dynamic",
            Self::Unknown => "unknown",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StackAnalysis {
    pub model: StackModelSummary,
    pub estimated_local_usage: Option<usize>,
    pub frame_capacity: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ElfSizesSummary {
    pub file: usize,
    pub code: usize,
    pub read_only_data: usize,
    pub writable_data: usize,
    pub metadata: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionDelta {
    pub baseline: SbpfVersion,
    pub version: SbpfVersion,
    pub file_size_delta: isize,
    pub code_size_delta: isize,
    pub instruction_count_delta: isize,
    pub function_count_delta: isize,
    pub basic_block_count_delta: isize,
    pub cfg_edge_count_delta: isize,
    pub max_local_stack_usage_delta: Option<isize>,
    pub opcode_deltas: BTreeMap<String, OpcodeDelta>,
    pub introduced_opcodes: Vec<String>,
    pub disappeared_opcodes: Vec<String>,
    pub function_instruction_changes: Vec<FunctionMetricDelta>,
    pub function_stack_changes: Vec<FunctionMetricDelta>,
    pub only_in_baseline: Vec<FunctionKey>,
    pub only_in_version: Vec<FunctionKey>,
}

impl VersionDelta {
    pub fn from_summaries(
        baseline: &BinaryAnalysisSummary,
        version: &BinaryAnalysisSummary,
    ) -> Self {
        let opcode_deltas = map_count_deltas(&baseline.opcode_counts, &version.opcode_counts);
        let introduced_opcodes = opcode_deltas
            .iter()
            .filter(|(_, delta)| delta.baseline_count == 0 && delta.version_count > 0)
            .map(|(opcode, _)| opcode.clone())
            .collect();
        let disappeared_opcodes = opcode_deltas
            .iter()
            .filter(|(_, delta)| delta.baseline_count > 0 && delta.version_count == 0)
            .map(|(opcode, _)| opcode.clone())
            .collect();

        let mut only_in_baseline = Vec::new();
        let mut only_in_version = Vec::new();
        let mut instruction_changes = Vec::new();
        let mut stack_changes = Vec::new();

        for (key, base_func) in &baseline.functions {
            match version.functions.get(key) {
                Some(version_func) => {
                    if base_func.instruction_count != version_func.instruction_count {
                        instruction_changes.push(FunctionMetricDelta {
                            key: key.clone(),
                            baseline_value: base_func.instruction_count,
                            version_value: version_func.instruction_count,
                            delta: diff(
                                version_func.instruction_count,
                                base_func.instruction_count,
                            ),
                        });
                    }
                    if let (Some(baseline_value), Some(version_value)) =
                        (base_func.local_stack_usage, version_func.local_stack_usage)
                        && baseline_value != version_value
                    {
                        stack_changes.push(FunctionMetricDelta {
                            key: key.clone(),
                            baseline_value,
                            version_value,
                            delta: diff(version_value, baseline_value),
                        });
                    }
                }
                None => only_in_baseline.push(key.clone()),
            }
        }

        for key in version.functions.keys() {
            if !baseline.functions.contains_key(key) {
                only_in_version.push(key.clone());
            }
        }

        instruction_changes.sort_by_key(|change| std::cmp::Reverse(change.delta.unsigned_abs()));
        stack_changes.sort_by_key(|change| std::cmp::Reverse(change.delta.unsigned_abs()));

        Self {
            baseline: baseline.version,
            version: version.version,
            file_size_delta: diff(version.file_size, baseline.file_size),
            code_size_delta: diff(version.elf_sizes.code, baseline.elf_sizes.code),
            instruction_count_delta: diff(version.instruction_count, baseline.instruction_count),
            function_count_delta: diff(version.function_count, baseline.function_count),
            basic_block_count_delta: diff(version.basic_block_count, baseline.basic_block_count),
            cfg_edge_count_delta: diff(version.cfg_edge_count, baseline.cfg_edge_count),
            max_local_stack_usage_delta: match (
                version.stack.estimated_local_usage,
                baseline.stack.estimated_local_usage,
            ) {
                (Some(new), Some(old)) => Some(diff(new, old)),
                _ => None,
            },
            opcode_deltas,
            introduced_opcodes,
            disappeared_opcodes,
            function_instruction_changes: instruction_changes,
            function_stack_changes: stack_changes,
            only_in_baseline,
            only_in_version,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpcodeDelta {
    pub baseline_count: usize,
    pub version_count: usize,
    pub delta: isize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionMetricDelta {
    pub key: FunctionKey,
    pub baseline_value: usize,
    pub version_value: usize,
    pub delta: isize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompilerDiffReport {
    pub build_root: PathBuf,
    pub baseline: SbpfVersion,
    pub builds: Vec<BuildResult>,
    pub versions: Vec<BinaryAnalysisSummary>,
    pub deltas: Vec<VersionDelta>,
    /// Full build provenance when produced by the compilation pipeline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_report: Option<profiles::ProfileReport>,
}

impl CompilerDiffReport {
    pub fn cleanup_builds(&self) {
        remove_transient_build_root(&self.build_root);
    }

    pub fn render_report(&self) -> String {
        self.render_compact()
    }

    pub fn render_compact(&self) -> String {
        let mut out = String::from("Compiler / sBPF diff\n\nBuild status:\n");
        for build in &self.builds {
            let marker = match build.state {
                BuildState::Compiled => "✓",
                BuildState::Unsupported => "✗ unsupported",
                BuildState::Failed => "✗ failed",
            };
            writeln!(&mut out, "  {:<3} {marker}", build.version).unwrap();
            if let Some(message) = &build.message {
                writeln!(&mut out, "      {message}").unwrap();
            }
        }
        writeln!(&mut out).unwrap();
        self.render_metric_table(&mut out);
        if !self.deltas.is_empty() {
            writeln!(&mut out, "\nImportant deltas (vs {}):", self.baseline).unwrap();
        }
        for delta in &self.deltas {
            writeln!(&mut out, "  {} vs {}", delta.version, delta.baseline).unwrap();
            render_nonzero_delta(&mut out, "instructions", delta.instruction_count_delta, "");
            render_nonzero_delta(&mut out, "binary size", delta.file_size_delta, " B");
            render_nonzero_delta(&mut out, "code size", delta.code_size_delta, " B");
            if !delta.introduced_opcodes.is_empty() {
                writeln!(
                    &mut out,
                    "    {:<16} +{}",
                    "new opcodes",
                    delta.introduced_opcodes.len()
                )
                .unwrap();
            }
            if let Some(value) = delta.max_local_stack_usage_delta {
                render_nonzero_delta(&mut out, "local stack", value, " B");
            }
        }
        out
    }

    pub fn render_verbose(&self) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Compiler / sBPF diff").unwrap();
        writeln!(&mut out).unwrap();
        writeln!(&mut out, "Build status:").unwrap();
        for build in &self.builds {
            let marker = match build.state {
                BuildState::Compiled => "✓ compiled",
                BuildState::Unsupported => "✗ unsupported by installed toolchain",
                BuildState::Failed => "✗ failed",
            };
            writeln!(&mut out, "  {:<3} {marker}", build.version).unwrap();
            if let Some(message) = &build.message {
                writeln!(&mut out, "      {message}").unwrap();
            }
            if let Some(message) = &build.message {
                writeln!(&mut out, "      {message}").unwrap();
            }
        }

        writeln!(&mut out).unwrap();
        writeln!(&mut out, "Baseline: {}", self.baseline).unwrap();
        writeln!(&mut out, "Build artifacts: {}", self.build_root.display()).unwrap();
        writeln!(&mut out).unwrap();
        self.render_metric_table(&mut out);
        writeln!(&mut out, "\nELF size breakdown (bytes):").unwrap();
        self.render_metric_row(&mut out, "Read-only data", |summary| {
            summary.elf_sizes.read_only_data
        });
        self.render_metric_row(&mut out, "Writable data", |summary| {
            summary.elf_sizes.writable_data
        });
        self.render_metric_row(&mut out, "Metadata/other", |summary| {
            summary.elf_sizes.metadata
        });

        for delta in &self.deltas {
            writeln!(&mut out).unwrap();
            writeln!(
                &mut out,
                "Comparison: {} -> {}",
                delta.baseline, delta.version
            )
            .unwrap();
            writeln!(&mut out, "{}", "-".repeat(72)).unwrap();
            writeln!(&mut out, "Summary deltas:").unwrap();
            render_summary_delta(&mut out, "Binary size", delta.file_size_delta, " bytes");
            render_summary_delta(&mut out, "Instructions", delta.instruction_count_delta, "");
            render_summary_delta(&mut out, "Functions", delta.function_count_delta, "");
            render_summary_delta(&mut out, "Basic blocks", delta.basic_block_count_delta, "");
            render_summary_delta(&mut out, "CFG edges", delta.cfg_edge_count_delta, "");
            render_summary_delta(
                &mut out,
                "Max local stack",
                delta.max_local_stack_usage_delta.unwrap_or_default(),
                " bytes",
            );

            writeln!(&mut out).unwrap();
            writeln!(&mut out, "Opcode changes:").unwrap();
            writeln!(
                &mut out,
                "  {:<18} {:>10} {:>10} {:>10}",
                "Opcode", delta.baseline, delta.version, "Delta"
            )
            .unwrap();
            let mut opcode_changes = delta
                .opcode_deltas
                .iter()
                .filter(|(_, change)| change.delta != 0)
                .collect::<Vec<_>>();
            opcode_changes
                .sort_by_key(|(_, change)| std::cmp::Reverse(change.delta.unsigned_abs()));
            for (opcode, change) in opcode_changes.into_iter().take(30) {
                writeln!(
                    &mut out,
                    "  {:<18} {:>10} {:>10} {:>+10}",
                    opcode, change.baseline_count, change.version_count, change.delta
                )
                .unwrap();
            }
            if !delta.introduced_opcodes.is_empty() {
                render_name_list(&mut out, "Introduced", &delta.introduced_opcodes);
            }
            if !delta.disappeared_opcodes.is_empty() {
                render_name_list(&mut out, "Disappeared", &delta.disappeared_opcodes);
            }

            writeln!(&mut out).unwrap();
            writeln!(&mut out, "Function changes:").unwrap();
            render_function_changes(
                &mut out,
                "Instruction count",
                &delta.function_instruction_changes,
            );
            render_function_changes(&mut out, "Stack usage", &delta.function_stack_changes);
            render_function_set(
                &mut out,
                &format!("Only in {}", delta.baseline),
                &delta.only_in_baseline,
            );
            render_function_set(
                &mut out,
                &format!("Only in {}", delta.version),
                &delta.only_in_version,
            );
        }

        let decode_failures = self
            .versions
            .iter()
            .flat_map(|summary| {
                summary
                    .decode_failures
                    .iter()
                    .map(move |failure| format!("{}: {failure}", summary.version))
            })
            .collect::<Vec<_>>();
        if !decode_failures.is_empty() {
            writeln!(&mut out).unwrap();
            writeln!(&mut out, "Decode failures:").unwrap();
            for failure in decode_failures {
                writeln!(&mut out, "  {failure}").unwrap();
            }
        }

        out
    }

    pub fn to_json(&self) -> Result<String, CompilerDiffError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    fn render_metric_table(&self, out: &mut String) {
        let metric_width = 24;
        write!(
            out,
            "{:<metric_width$}",
            "Metric",
            metric_width = metric_width
        )
        .unwrap();
        for summary in &self.versions {
            write!(out, "{:>12}", summary.version).unwrap();
        }
        writeln!(out).unwrap();
        writeln!(
            out,
            "{}",
            "-".repeat(metric_width + self.versions.len() * 12)
        )
        .unwrap();
        self.render_metric_row(out, "Binary size (bytes)", |summary| summary.file_size);
        self.render_metric_row(out, "Code size (bytes)", |summary| summary.elf_sizes.code);
        self.render_metric_row(out, "Instructions", |summary| summary.instruction_count);
        self.render_metric_row(out, "Functions", |summary| summary.function_count);
        self.render_metric_row(out, "Basic blocks", |summary| summary.basic_block_count);
        self.render_metric_row(out, "Reachable instrs", |summary| {
            summary.reachable_instruction_count
        });
        render_text_row(out, "Stack model", &self.versions, |summary| {
            summary.stack.model.to_string()
        });
        render_text_row(out, "Max local stack", &self.versions, |summary| {
            optional_bytes(summary.stack.estimated_local_usage)
        });
        render_text_row(out, "Frame capacity", &self.versions, |summary| {
            optional_bytes(summary.stack.frame_capacity)
        });
    }

    fn render_metric_row<F>(&self, out: &mut String, label: &str, value: F)
    where
        F: Fn(&BinaryAnalysisSummary) -> usize,
    {
        write!(out, "{label:<24}").unwrap();
        for summary in &self.versions {
            write!(out, "{:>12}", value(summary)).unwrap();
        }
        writeln!(out).unwrap();
    }
}

fn render_text_row<F>(out: &mut String, label: &str, versions: &[BinaryAnalysisSummary], value: F)
where
    F: Fn(&BinaryAnalysisSummary) -> String,
{
    write!(out, "{label:<24}").unwrap();
    for summary in versions {
        write!(out, "{:>12}", value(summary)).unwrap();
    }
    writeln!(out).unwrap();
}

fn optional_bytes(value: Option<usize>) -> String {
    value.map_or_else(|| "?".to_string(), |bytes| bytes.to_string())
}

fn render_nonzero_delta(out: &mut String, label: &str, delta: isize, unit: &str) {
    if delta != 0 {
        writeln!(out, "    {label:<16} {delta:+}{unit}").unwrap();
    }
}

pub fn analyze_binary(
    version: SbpfVersion,
    path: &Path,
) -> Result<BinaryAnalysisSummary, CompilerDiffError> {
    let analysis = analyze_program_path(path)?;
    Ok(summary_from_analysis(version, path.to_path_buf(), analysis))
}

fn analyze_program_path(path: &Path) -> Result<ProgramAnalysis, crate::AnalyzerError> {
    analyze_program(&path.to_string_lossy())
}

fn summary_from_analysis(
    version: SbpfVersion,
    path: PathBuf,
    analysis: ProgramAnalysis,
) -> BinaryAnalysisSummary {
    let binary_info = analysis.binary_info();
    let opcode_counts = analysis
        .instructions()
        .iter()
        .map(|ix| format!("{:?}", ix.instruction().opcode).to_ascii_lowercase())
        .fold(BTreeMap::new(), |mut counts, opcode| {
            *counts.entry(opcode).or_insert(0) += 1;
            counts
        });

    let cfg_edge_count = analysis
        .blocks()
        .iter()
        .map(|block| block.successors().len())
        .sum();

    let reachable_blocks = analysis
        .functions()
        .iter()
        .filter(|func| func.reachable_from_program_entry())
        .flat_map(|func| func.blocks().iter().copied())
        .collect::<BTreeSet<_>>();

    let reachable_instruction_count = instruction_count_for_blocks(&analysis, &reachable_blocks);
    let all_blocks = analysis
        .blocks()
        .iter()
        .map(|block| block.id())
        .collect::<BTreeSet<_>>();
    let unreachable_blocks = all_blocks
        .difference(&reachable_blocks)
        .copied()
        .collect::<BTreeSet<_>>();
    let unreachable_instruction_count =
        instruction_count_for_blocks(&analysis, &unreachable_blocks);

    let stack_model = stack_model_summary(binary_info.stack_model());
    let raw_max_stack = analysis
        .functions()
        .iter()
        .map(|func| func.local_stack_usage())
        .max()
        .unwrap_or(0);
    let stack = normalize_stack_analysis(stack_model, raw_max_stack);
    let stack_estimate_reliable = stack.estimated_local_usage.is_some();
    let mut matcher = FunctionMatcher::default();
    let mut functions = BTreeMap::new();
    for (ordinal, func) in analysis.functions().iter().enumerate() {
        let block_ids = func.blocks().iter().copied().collect::<BTreeSet<_>>();
        let instruction_count = instruction_count_for_blocks(&analysis, &block_ids);
        let key = matcher.identity(&analysis, ordinal);
        let local_stack_usage = stack_estimate_reliable.then_some(func.local_stack_usage());
        let cumulative_stack_usage = stack_estimate_reliable
            .then(|| cumulative_stack_usage(analysis.functions(), func.id()).ok())
            .flatten();
        functions.insert(
            key.clone(),
            FunctionSummary {
                key,
                instruction_count,
                block_count: func.blocks().len(),
                local_stack_usage,
                cumulative_stack_usage,
                reachable_from_program_entry: func.reachable_from_program_entry(),
            },
        );
    }

    let elf_sizes = elf_sizes_summary(binary_info.elf_sizes());

    BinaryAnalysisSummary {
        version,
        path,
        detected_sbpf_version: binary_info.sbpf_version(),
        file_size: binary_info.size(),
        text_section_size: binary_info.text_section_size(),
        elf_sizes,
        instruction_count: binary_info.ix_count(),
        opcode_counts,
        function_count: analysis.functions().len(),
        basic_block_count: analysis.blocks().len(),
        cfg_edge_count,
        reachable_block_count: reachable_blocks.len(),
        unreachable_block_count: unreachable_blocks.len(),
        reachable_instruction_count,
        unreachable_instruction_count,
        stack,
        functions,
        decode_failures: Vec::new(),
    }
}

fn instruction_count_for_blocks(analysis: &ProgramAnalysis, block_ids: &BTreeSet<usize>) -> usize {
    analysis
        .blocks()
        .iter()
        .filter(|block| block_ids.contains(&block.id()))
        .map(|block| {
            analysis
                .instructions()
                .iter()
                .filter(|ix| ix.pc() >= block.start_pc() && ix.pc() < block.end_pc_exclusive())
                .count()
        })
        .sum()
}

#[derive(Default)]
pub struct FunctionMatcher {
    occurrences: BTreeMap<String, usize>,
}

impl FunctionMatcher {
    fn identity(&mut self, analysis: &ProgramAnalysis, function_index: usize) -> FunctionKey {
        let function = &analysis.functions()[function_index];
        let block_ids = function.blocks().iter().copied().collect::<BTreeSet<_>>();
        let blocks = function
            .blocks()
            .iter()
            .map(|id| &analysis.blocks()[*id])
            .collect::<Vec<_>>();
        let internal_edges = blocks
            .iter()
            .flat_map(|block| block.successors())
            .filter(|successor| block_ids.contains(successor))
            .count();
        let external_edges = blocks
            .iter()
            .flat_map(|block| block.successors())
            .filter(|successor| !block_ids.contains(successor))
            .count();
        let branches = blocks
            .iter()
            .filter(|block| block.successors().len() > 1)
            .count();
        let exits = blocks
            .iter()
            .filter(|block| block.successors().is_empty())
            .count();
        let fingerprint = format!(
            "b{}-e{}-x{}-br{}-ret{}-c{}-live{}",
            function.blocks().len(),
            internal_edges,
            external_edges,
            branches,
            exits,
            function.callees().len(),
            function.reachable_from_program_entry()
        );
        let occurrence = self.occurrences.entry(fingerprint.clone()).or_default();
        let key = FunctionKey::Structural(format!("cfg:{fingerprint}#{occurrence}"));
        *occurrence += 1;
        key
    }
}

fn stack_model_summary(model: StackModel) -> StackModelSummary {
    match model {
        StackModel::FixedFrame => StackModelSummary::FixedFrame,
        StackModel::DynamicFrame => StackModelSummary::DynamicFrame,
        StackModel::Unknown => StackModelSummary::Unknown,
    }
}

fn normalize_stack_analysis(model: StackModelSummary, raw_max: usize) -> StackAnalysis {
    StackAnalysis {
        model,
        estimated_local_usage: (raw_max < 4096).then_some(raw_max),
        frame_capacity: (model == StackModelSummary::FixedFrame).then_some(4096),
    }
}

fn elf_sizes_summary(sizes: ElfSizes) -> ElfSizesSummary {
    ElfSizesSummary {
        file: sizes.file,
        code: sizes.code,
        read_only_data: sizes.read_only_data,
        writable_data: sizes.writable_data,
        metadata: sizes.metadata,
    }
}

fn map_count_deltas(
    baseline: &BTreeMap<String, usize>,
    version: &BTreeMap<String, usize>,
) -> BTreeMap<String, OpcodeDelta> {
    let keys = baseline
        .keys()
        .chain(version.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    keys.into_iter()
        .map(|key| {
            let baseline_count = baseline.get(&key).copied().unwrap_or(0);
            let version_count = version.get(&key).copied().unwrap_or(0);
            (
                key,
                OpcodeDelta {
                    baseline_count,
                    version_count,
                    delta: diff(version_count, baseline_count),
                },
            )
        })
        .collect()
}

fn diff(new: usize, old: usize) -> isize {
    new as isize - old as isize
}

pub fn parse_versions(value: &str) -> Result<Vec<SbpfVersion>, CompilerDiffError> {
    let versions = value
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(str::parse)
        .collect::<Result<Vec<_>, _>>()?;
    if versions.is_empty() {
        return Err(CompilerDiffError::NoVersionsRequested);
    }
    Ok(versions)
}

fn detect_supported_architectures() -> Result<BTreeSet<SbpfVersion>, CompilerDiffError> {
    let output = Command::new("cargo")
        .arg("build-sbf")
        .arg("--help")
        .output()?;
    if !output.status.success() {
        return Err(CompilerDiffError::ToolchainProbe(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }
    let help = String::from_utf8_lossy(&output.stdout);
    let mut supported = BTreeSet::new();
    for arch in ["v0", "v1", "v2", "v3", "v4"] {
        if help.contains(arch) {
            supported.insert(arch.parse()?);
        }
    }
    if supported.is_empty() {
        return Err(CompilerDiffError::ToolchainProbe(
            "no --arch values found in cargo build-sbf --help".to_string(),
        ));
    }
    Ok(supported)
}

fn versions_to_build(
    requested: &[SbpfVersion],
    supported: &BTreeSet<SbpfVersion>,
) -> Vec<SbpfVersion> {
    if requested.is_empty() {
        supported
            .iter()
            .copied()
            .filter(|version| version.0 < 4)
            .collect()
    } else {
        requested.to_vec()
    }
}

fn is_unsupported_target_error(stderr: &str) -> bool {
    stderr.contains("target may not be installed")
        || (stderr.contains("can't find crate for `core`") && stderr.contains("sbpfv"))
}

fn compiler_diff_build_root() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    std::env::temp_dir().join(format!(
        "sbpf-eye-compiler-diff-{}-{stamp}",
        std::process::id()
    ))
}

fn remove_transient_build_root(path: &Path) {
    if path.starts_with(std::env::temp_dir()) {
        let _ = fs::remove_dir_all(path);
    }
}

fn render_summary_delta(out: &mut String, label: &str, delta: isize, unit: &str) {
    if delta != 0 {
        writeln!(out, "  {label:<24} {delta:>+10}{unit}").unwrap();
    }
}

fn render_name_list(out: &mut String, label: &str, names: &[String]) {
    if names.is_empty() {
        writeln!(out, "  {label:<12} none").unwrap();
        return;
    }

    for (index, chunk) in names.chunks(5).enumerate() {
        let prefix = if index == 0 { label } else { "" };
        writeln!(out, "  {prefix:<12} {}", chunk.join(", ")).unwrap();
    }
}

fn render_function_changes(out: &mut String, title: &str, changes: &[FunctionMetricDelta]) {
    if changes.is_empty() {
        return;
    }
    writeln!(out, "  {title}:").unwrap();
    for change in changes.iter().take(10) {
        writeln!(
            out,
            "    {:<44} {:>6} -> {:<6} ({:+})",
            change.key, change.baseline_value, change.version_value, change.delta
        )
        .unwrap();
    }
}

fn render_function_set(out: &mut String, title: &str, functions: &[FunctionKey]) {
    if functions.is_empty() {
        return;
    }
    writeln!(out, "  {title}:").unwrap();
    for key in functions.iter().take(10) {
        writeln!(out, "    {key}").unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(
        version: u32,
        opcodes: &[(&str, usize)],
        functions: &[(&str, usize, usize)],
    ) -> BinaryAnalysisSummary {
        BinaryAnalysisSummary {
            version: SbpfVersion::new(version),
            path: PathBuf::from(format!("v{version}.so")),
            detected_sbpf_version: version,
            file_size: 100 + version as usize,
            text_section_size: 80,
            elf_sizes: ElfSizesSummary {
                file: 100 + version as usize,
                code: 80 + version as usize,
                read_only_data: 10,
                writable_data: 0,
                metadata: 10,
            },
            instruction_count: opcodes.iter().map(|(_, count)| *count).sum(),
            opcode_counts: opcodes
                .iter()
                .map(|(opcode, count)| ((*opcode).to_string(), *count))
                .collect(),
            function_count: functions.len(),
            basic_block_count: 3,
            cfg_edge_count: 2,
            reachable_block_count: 2,
            unreachable_block_count: 1,
            reachable_instruction_count: 7,
            unreachable_instruction_count: 1,
            stack: StackAnalysis {
                model: if version == 0 {
                    StackModelSummary::FixedFrame
                } else {
                    StackModelSummary::DynamicFrame
                },
                estimated_local_usage: functions.iter().map(|(_, _, stack)| *stack).max(),
                frame_capacity: (version == 0).then_some(4096),
            },
            functions: functions
                .iter()
                .map(|(name, ix_count, stack)| {
                    let key = FunctionKey::Structural((*name).to_string());
                    (
                        key.clone(),
                        FunctionSummary {
                            key,
                            instruction_count: *ix_count,
                            block_count: 1,
                            local_stack_usage: Some(*stack),
                            cumulative_stack_usage: Some(*stack),
                            reachable_from_program_entry: true,
                        },
                    )
                })
                .collect(),
            decode_failures: Vec::new(),
        }
    }

    #[test]
    fn version_parsing_and_ordering() {
        let mut versions = parse_versions("v3,v0,2").unwrap();
        versions.sort();
        assert_eq!(
            versions,
            vec![
                SbpfVersion::new(0),
                SbpfVersion::new(2),
                SbpfVersion::new(3)
            ]
        );
        assert!(parse_versions("").is_err());
        assert!("vx".parse::<SbpfVersion>().is_err());
    }

    #[test]
    fn automatic_versions_exclude_v4_but_explicit_selection_preserves_it() {
        let supported = [0, 1, 2, 3, 4]
            .into_iter()
            .map(SbpfVersion::new)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            versions_to_build(&[], &supported),
            vec![
                SbpfVersion::new(0),
                SbpfVersion::new(1),
                SbpfVersion::new(2),
                SbpfVersion::new(3),
            ]
        );
        assert_eq!(
            versions_to_build(&[SbpfVersion::new(4)], &supported),
            vec![SbpfVersion::new(4)]
        );
    }

    #[test]
    fn missing_rust_target_is_classified_as_unsupported() {
        let stderr = "can't find crate for `core`\n= note: the `sbpfv9-solana-solana` target may not be installed";
        assert!(is_unsupported_target_error(stderr));
        assert!(!is_unsupported_target_error("program failed to compile"));
    }

    #[test]
    fn delta_calculation_tracks_opcode_introduction_and_removal() {
        let base = summary(0, &[("add64", 10), ("mov64", 5)], &[("f0", 10, 32)]);
        let next = summary(3, &[("add64", 7), ("jmp32", 2)], &[("f0", 8, 64)]);
        let delta = VersionDelta::from_summaries(&base, &next);

        assert_eq!(delta.instruction_count_delta, -6);
        assert_eq!(delta.opcode_deltas["add64"].delta, -3);
        assert_eq!(delta.introduced_opcodes, vec!["jmp32"]);
        assert_eq!(delta.disappeared_opcodes, vec!["mov64"]);
        assert_eq!(delta.function_instruction_changes[0].delta, -2);
        assert_eq!(delta.function_stack_changes[0].delta, 32);
        assert_eq!(delta.only_in_baseline, Vec::<FunctionKey>::new());
        assert_eq!(delta.only_in_version, Vec::<FunctionKey>::new());
    }

    #[test]
    fn stable_identity_matches_changed_function_measurements() {
        let base = summary(0, &[("add64", 10)], &[("cfg:diamond#0", 502, 24)]);
        let next = summary(1, &[("add64", 11)], &[("cfg:diamond#0", 503, 32)]);
        let delta = VersionDelta::from_summaries(&base, &next);

        assert_eq!(delta.function_instruction_changes[0].delta, 1);
        assert_eq!(delta.function_stack_changes[0].delta, 8);
        assert!(delta.only_in_baseline.is_empty());
        assert!(delta.only_in_version.is_empty());
    }

    #[test]
    fn frame_capacity_is_not_reported_as_local_usage() {
        let stack = normalize_stack_analysis(StackModelSummary::FixedFrame, 4096);
        assert_eq!(stack.estimated_local_usage, None);
        assert_eq!(stack.frame_capacity, Some(4096));
    }

    #[test]
    fn stack_deltas_require_comparable_measurements() {
        let cases = [
            (None, None, None),
            (None, Some(8), None),
            (Some(8), None, None),
            (Some(8), Some(8), Some(0)),
            (Some(8), Some(16), Some(8)),
        ];

        for (baseline_stack, version_stack, expected_delta) in cases {
            let mut base = summary(0, &[("exit", 1)], &[("entry", 1, 0)]);
            let mut next = summary(1, &[("exit", 1)], &[("entry", 1, 0)]);
            base.stack.estimated_local_usage = baseline_stack;
            next.stack.estimated_local_usage = version_stack;
            let delta = VersionDelta::from_summaries(&base, &next);
            assert_eq!(delta.max_local_stack_usage_delta, expected_delta);

            let report = CompilerDiffReport {
                profile_report: None,
                build_root: PathBuf::from("/tmp/builds"),
                baseline: base.version,
                builds: vec![],
                versions: vec![base, next],
                deltas: vec![delta],
            };
            assert_eq!(
                report.render_compact().contains("    local stack"),
                expected_delta.is_some_and(|value| value != 0)
            );
        }
    }

    #[test]
    fn elf_code_size_delta_is_independent_from_file_size() {
        let base = summary(0, &[("exit", 1)], &[("entry", 1, 0)]);
        let mut next = summary(1, &[("exit", 1)], &[("entry", 1, 0)]);
        next.file_size = 140;
        next.elf_sizes.file = 140;
        next.elf_sizes.code = 75;
        let delta = VersionDelta::from_summaries(&base, &next);
        assert_eq!(delta.file_size_delta, 40);
        assert_eq!(delta.code_size_delta, -5);
    }

    #[test]
    fn compact_suppresses_details_while_verbose_exposes_them() {
        let base = summary(0, &[("add64", 10)], &[("same", 10, 8)]);
        let next = summary(1, &[("add64", 8), ("jmp32", 2)], &[("same", 11, 8)]);
        let report = CompilerDiffReport {
            profile_report: None,
            build_root: PathBuf::from("/tmp/builds"),
            baseline: base.version,
            builds: vec![],
            deltas: vec![VersionDelta::from_summaries(&base, &next)],
            versions: vec![base, next],
        };

        let compact = report.render_compact();
        assert!(!compact.contains("Opcode changes:"));
        assert!(!compact.contains("Introduced"));
        assert!(!compact.contains("Functions only"));
        let verbose = report.render_verbose();
        assert!(verbose.contains("Opcode changes:"));
        assert!(verbose.contains("Instruction count:"));
        assert!(report.to_json().unwrap().contains("opcode_deltas"));
    }

    #[test]
    fn function_sets_track_missing_functions() {
        let base = summary(0, &[("add64", 1)], &[("entry", 1, 0), ("old", 1, 0)]);
        let next = summary(1, &[("add64", 1)], &[("entry", 1, 0), ("new", 1, 0)]);
        let delta = VersionDelta::from_summaries(&base, &next);

        assert_eq!(
            delta.only_in_baseline,
            vec![FunctionKey::Structural("old".to_string())]
        );
        assert_eq!(
            delta.only_in_version,
            vec![FunctionKey::Structural("new".to_string())]
        );
    }

    #[test]
    fn report_renders_failed_and_unsupported_versions() {
        let report = CompilerDiffReport {
            profile_report: None,
            build_root: PathBuf::from("/tmp/builds"),
            baseline: SbpfVersion::new(0),
            builds: vec![
                BuildResult::compiled(SbpfVersion::new(0), PathBuf::from("v0.so"), 0),
                BuildResult::unsupported(
                    SbpfVersion::new(2),
                    "unsupported by installed cargo-build-sbf toolchain",
                ),
                BuildResult {
                    version: SbpfVersion::new(3),
                    state: BuildState::Failed,
                    elf_path: None,
                    detected_version: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    message: Some("compile error".to_string()),
                },
            ],
            versions: vec![summary(0, &[("exit", 1)], &[("entry", 1, 0)])],
            deltas: vec![],
        };
        let rendered = report.render_report();
        assert!(rendered.contains("v0") && rendered.contains('✓'));
        assert!(rendered.contains("v2") && rendered.contains("unsupported"));
        assert!(rendered.contains("v3") && rendered.contains("failed"));
    }
}
