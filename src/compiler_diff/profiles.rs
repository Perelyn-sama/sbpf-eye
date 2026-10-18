//! Named compiler comparisons. JSON schema version 1; unknown metadata is null.
use super::backend::{BuildBackend, NativeBackend, copy_source};
use super::{BinaryAnalysisSummary, CompilerDiffReport, SbpfVersion, VersionDelta, analyze_binary};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    V0,
    V1,
    V2,
    V3,
    V4,
}
impl Architecture {
    pub fn number(self) -> u32 {
        self as u32
    }
    pub fn arch(self) -> String {
        format!("v{}", self.number())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "builder", deny_unknown_fields)]
pub enum BuilderSettings {
    #[serde(rename = "cargo-build-sbf")]
    Anza {
        #[serde(default)]
        platform_tools_version: Option<String>,
    },
    #[serde(rename = "cargo-build-sbpf")]
    Blueshift {
        #[serde(default)]
        rust_toolchain: Option<String>,
    },
}
impl BuilderSettings {
    pub fn executable(&self) -> &'static str {
        match self {
            Self::Anza { .. } => "cargo-build-sbf",
            Self::Blueshift { .. } => "cargo-build-sbpf",
        }
    }
}
fn yes() -> bool {
    true
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerProfile {
    pub name: String,
    #[serde(flatten)]
    pub backend: BuilderSettings,
    pub builder_path: Option<PathBuf>,
    pub sbpf_version: Architecture,
    #[serde(default = "yes")]
    pub release: bool,
    pub opt_level: Option<String>,
    #[serde(default)]
    pub builder_args: Vec<String>,
    #[serde(default)]
    pub cargo_args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    pub profiles: Vec<CompilerProfile>,
}
impl ProfileConfig {
    pub fn parse(input: &str) -> Result<Self> {
        // Validate field names explicitly: serde flatten cannot combine with deny_unknown_fields.
        let value: toml::Value = toml::from_str(input)?;
        if let Some(profiles) = value.get("profiles").and_then(toml::Value::as_array) {
            for p in profiles {
                for key in p.as_table().context("profile must be a table")?.keys() {
                    if ![
                        "name",
                        "builder",
                        "builder_path",
                        "sbpf_version",
                        "release",
                        "opt_level",
                        "builder_args",
                        "cargo_args",
                        "env",
                        "platform_tools_version",
                        "rust_toolchain",
                    ]
                    .contains(&key.as_str())
                    {
                        bail!("unknown profile field `{key}`");
                    }
                }
            }
        }
        let config: Self = toml::from_str(input)?;
        let mut names = BTreeSet::new();
        for p in &config.profiles {
            if p.name.is_empty()
                || !p
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                bail!("profile name must contain only letters, digits, '-' or '_'");
            }
            if !names.insert(&p.name) {
                bail!("duplicate profile name `{}`", p.name);
            }
        }
        if names.is_empty() {
            bail!("no profiles configured");
        }
        Ok(config)
    }
    pub fn select(mut self, names: &[String]) -> Result<Self> {
        for name in names {
            if !self.profiles.iter().any(|p| &p.name == name) {
                bail!("unknown selected profile `{name}`");
            }
        }
        if !names.is_empty() {
            self.profiles.retain(|p| names.contains(&p.name));
        }
        Ok(self)
    }
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct ResolvedToolchain {
    pub builder_path: Option<PathBuf>,
    pub builder_version: Option<String>,
    pub rust_toolchain: Option<String>,
    pub rustc_path: Option<PathBuf>,
    pub rustc_version: Option<String>,
    pub rustc_commit: Option<String>,
    pub llvm_version: Option<String>,
    pub linker_path: Option<PathBuf>,
    pub linker_version: Option<String>,
    pub platform_tools_version: Option<String>,
    pub diagnostics: Vec<String>,
    pub target_spec: Option<serde_json::Value>,
    pub cargo_configs: BTreeMap<PathBuf, String>,
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct CommandRecord {
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub environment: BTreeMap<String, String>,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileStatus {
    Unsupported,
    BuildFailed,
    Built,
    AnalysisFailed,
    Analyzed,
}
#[derive(Debug, Clone, Serialize)]
pub struct ProfileResult {
    pub profile: CompilerProfile,
    pub resolved: ResolvedToolchain,
    pub status: ProfileStatus,
    pub build: Option<CommandRecord>,
    pub elf_path: Option<PathBuf>,
    pub elf_sha256: Option<String>,
    pub actual_architecture: Option<u32>,
    pub analysis: Option<BinaryAnalysisSummary>,
    pub diagnostic: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct MetricDelta {
    pub baseline: usize,
    pub value: usize,
    pub delta: i128,
    pub percent: Option<f64>,
}
impl MetricDelta {
    fn new(baseline: usize, value: usize) -> Self {
        Self {
            baseline,
            value,
            delta: value as i128 - baseline as i128,
            percent: (baseline != 0)
                .then(|| (value as f64 - baseline as f64) * 100.0 / baseline as f64),
        }
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct ProfileDelta {
    pub baseline: String,
    pub profile: String,
    pub metrics: BTreeMap<String, MetricDelta>,
    /// Existing opcode/function comparison engine; architecture fields describe artifacts, not identities.
    pub detail: VersionDelta,
    pub configuration_changes: BTreeMap<String, (serde_json::Value, serde_json::Value)>,
    pub resolved_environment_changes: BTreeMap<String, (serde_json::Value, serde_json::Value)>,
    pub multiple_variables_changed: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct ProfileReport {
    pub schema_version: u32,
    pub baseline: String,
    pub build_root: PathBuf,
    pub artifacts_preserved: bool,
    pub source_sha256: String,
    pub cargo_lock_sha256: String,
    pub reproducibility: Vec<String>,
    pub profiles: Vec<ProfileResult>,
    pub deltas: Vec<ProfileDelta>,
}
impl ProfileReport {
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
    pub fn render(&self, verbose: bool) -> String {
        super::render::render(
            self,
            &super::render::RenderOptions {
                verbose,
                ..Default::default()
            },
        )
    }
}

/// Adapt legacy results for human-readable formats. Legacy JSON remains unchanged.
/// No build or analysis is repeated; missing legacy environment metadata stays unknown.
pub fn legacy_presentation(report: &CompilerDiffReport, preserved: bool) -> ProfileReport {
    let profiles = report
        .builds
        .iter()
        .map(|b| {
            let a = report
                .versions
                .iter()
                .find(|a| a.version == b.version)
                .cloned();
            let arch = match b.version.number() {
                1 => Architecture::V1,
                2 => Architecture::V2,
                3 => Architecture::V3,
                4 => Architecture::V4,
                _ => Architecture::V0,
            };
            ProfileResult {
                profile: CompilerProfile {
                    name: b.version.as_arch(),
                    backend: BuilderSettings::Anza {
                        platform_tools_version: None,
                    },
                    builder_path: None,
                    sbpf_version: arch,
                    release: true,
                    opt_level: None,
                    builder_args: vec![],
                    cargo_args: vec![],
                    env: BTreeMap::new(),
                },
                resolved: ResolvedToolchain::default(),
                status: if a.is_some() {
                    ProfileStatus::Analyzed
                } else {
                    match b.state {
                        super::BuildState::Unsupported => ProfileStatus::Unsupported,
                        super::BuildState::Compiled => ProfileStatus::Built,
                        super::BuildState::Failed => ProfileStatus::BuildFailed,
                    }
                },
                build: None,
                elf_path: b.elf_path.clone(),
                elf_sha256: None,
                actual_architecture: b.detected_version,
                analysis: a,
                diagnostic: b.message.clone(),
            }
        })
        .collect::<Vec<_>>();
    let baseline = report.baseline.as_arch();
    ProfileReport { schema_version:1,baseline:baseline.clone(),build_root:report.build_root.clone(),artifacts_preserved:preserved,source_sha256:String::new(),cargo_lock_sha256:String::new(),reproducibility:vec!["Legacy reports do not retain resolved toolchain metadata or build duration. Use --profiles for complete provenance.".into()],deltas:deltas(&profiles,&baseline),profiles }
}

fn metrics(a: &BinaryAnalysisSummary) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::from([
        ("elf_bytes".into(), a.file_size),
        ("text_bytes".into(), a.text_section_size),
        ("rodata_bytes".into(), a.elf_sizes.read_only_data),
        ("data_bytes".into(), a.elf_sizes.writable_data),
        ("instructions".into(), a.instruction_count),
        ("functions".into(), a.function_count),
        ("blocks".into(), a.basic_block_count),
        ("cfg_edges".into(), a.cfg_edge_count),
        ("reachable_blocks".into(), a.reachable_block_count),
        ("unreachable_blocks".into(), a.unreachable_block_count),
        (
            "reachable_instructions".into(),
            a.reachable_instruction_count,
        ),
        (
            "unreachable_instructions".into(),
            a.unreachable_instruction_count,
        ),
    ]);
    if let Some(s) = a.stack.estimated_local_usage {
        m.insert("local_stack_bytes".into(), s);
    }
    m
}
fn deltas(results: &[ProfileResult], baseline: &str) -> Vec<ProfileDelta> {
    let Some(base) = results.iter().find(|r| r.profile.name == baseline) else {
        return vec![];
    };
    let Some(a) = &base.analysis else {
        return vec![];
    };
    results
        .iter()
        .filter(|r| r.profile.name != baseline)
        .filter_map(|r| {
            let b = r.analysis.as_ref()?;
            let am = metrics(a);
            let mut metrics: BTreeMap<String, MetricDelta> = metrics(b)
                .into_iter()
                .filter_map(|(k, v)| am.get(&k).map(|old| (k.clone(), MetricDelta::new(*old, v))))
                .collect();
            if let (Some(old), Some(new)) = (&base.build, &r.build) {
                metrics.insert(
                    "build_duration_ms".into(),
                    MetricDelta::new(old.duration_ms as usize, new.duration_ms as usize),
                );
            }
            let ar = serde_json::to_value(&base.resolved).unwrap();
            let br = serde_json::to_value(&r.resolved).unwrap();
            let resolved_environment_changes: BTreeMap<_, _> = [
                "builder_version",
                "rustc_version",
                "rustc_commit",
                "llvm_version",
                "linker_version",
                "platform_tools_version",
                "rust_toolchain",
            ]
            .into_iter()
            .filter(|k| ar[*k] != br[*k])
            .map(|k| (k.to_string(), (ar[k].clone(), br[k].clone())))
            .collect();
            let av = serde_json::to_value(&base.profile).unwrap();
            let bv = serde_json::to_value(&r.profile).unwrap();
            let changes: BTreeMap<_, _> = av
                .as_object()
                .unwrap()
                .keys()
                .chain(bv.as_object().unwrap().keys())
                .filter(|k| k.as_str() != "name")
                .filter(|k| av[*k] != bv[*k])
                .map(|k| (k.clone(), (av[k].clone(), bv[k].clone())))
                .collect();
            Some(ProfileDelta {
                baseline: baseline.into(),
                profile: r.profile.name.clone(),
                metrics,
                detail: VersionDelta::from_summaries(a, b),
                multiple_variables_changed: changes.len() > 1
                    || resolved_environment_changes.len() > 1,
                resolved_environment_changes,
                configuration_changes: changes,
            })
        })
        .collect()
}
pub fn compare_profiles(
    program: &Path,
    config: ProfileConfig,
    baseline: Option<&str>,
    keep: bool,
) -> Result<ProfileReport> {
    compare_with_backend(program, config, baseline, keep, &NativeBackend)
}
fn compare_with_backend(
    program: &Path,
    config: ProfileConfig,
    baseline: Option<&str>,
    keep: bool,
    backend: &dyn BuildBackend,
) -> Result<ProfileReport> {
    let config = ProfileConfig::parse(&toml::to_string(&config)?)?;
    let baseline = baseline
        .map(str::to_owned)
        .or_else(|| config.profiles.first().map(|p| p.name.clone()))
        .context("no profiles selected")?;
    if !config.profiles.iter().any(|p| p.name == baseline) {
        bail!("baseline `{baseline}` is not selected");
    }
    let original = program.canonicalize().with_context(|| {
        format!("cannot open program directory `{}`; pass the path to your program or workspace containing Cargo.toml", program.display())
    })?;
    if !original.is_dir() {
        bail!(
            "program path `{}` must be a directory containing Cargo.toml",
            program.display()
        );
    }
    let workspace = super::backend::workspace_root(&original, &config.profiles[0])?;
    let member = original.strip_prefix(&workspace)?;
    let temp = tempfile::Builder::new()
        .prefix("sbpf-eye-profiles-")
        .tempdir()?;
    let root = temp.path().canonicalize()?;
    // Persist before work so --keep-builds also preserves failed runs.
    let _guard = if keep {
        let _ = temp.keep();
        None
    } else {
        Some(temp)
    };
    for ancestor in workspace.ancestors().skip(1) {
        for name in [".cargo/config", ".cargo/config.toml"] {
            if ancestor.join(name).is_file() {
                bail!(
                    "ancestor Cargo config {} would be lost by snapshotting; pass a self-contained workspace root",
                    ancestor.join(name).display()
                );
            }
        }
    }
    let snapshot = root.join("snapshot");
    copy_source(&workspace, &snapshot)?;
    let generated_lock = !snapshot.join("Cargo.lock").is_file();
    if generated_lock {
        super::backend::generate_lockfile(&snapshot).context("no Cargo.lock: unable to resolve dependencies once offline in snapshot; generate the lockfile manually")?;
    }
    let source_sha256 = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&super::backend::source_hashes(
            &snapshot
        )?)?)
    );
    let cargo_lock_sha256 = format!(
        "{:x}",
        Sha256::digest(fs::read(snapshot.join("Cargo.lock"))?)
    );
    let mut results = Vec::new();
    for (i, profile) in config.profiles.into_iter().enumerate() {
        let dir = root.join(format!("profile-{i}"));
        fs::create_dir(&dir)?;
        let source = dir.join("source");
        copy_source(&snapshot, &source)?;
        let mut result = backend.build(&profile, &source.join(member), &source, &dir);
        if result.status == ProfileStatus::Built
            && let Some(path) = &result.elf_path
        {
            match analyze_binary(SbpfVersion::new(profile.sbpf_version.number()), path) {
                Ok(a) => {
                    result.actual_architecture = Some(a.detected_sbpf_version);
                    if a.detected_sbpf_version != profile.sbpf_version.number() {
                        result.status = ProfileStatus::AnalysisFailed;
                        result.diagnostic = Some(format!(
                            "architecture mismatch: requested {}, artifact v{}",
                            profile.sbpf_version.arch(),
                            a.detected_sbpf_version
                        ));
                    } else {
                        result.status = ProfileStatus::Analyzed;
                        result.analysis = Some(a);
                    }
                }
                Err(e) => {
                    result.status = ProfileStatus::AnalysisFailed;
                    result.diagnostic = Some(e.to_string());
                }
            }
        }
        results.push(result);
    }
    let mut warnings=vec!["A single source snapshot and existing Cargo.lock are used; builds are locked and offline. Build scripts and external tools are not hermetic.".into()];
    if generated_lock {
        warnings.push("Input had no Cargo.lock; generated one offline in the snapshot and reused it for every profile. Dependency resolution was not pinned by the input.".into());
    }
    if results
        .iter()
        .any(|r| matches!(r.profile.backend, BuilderSettings::Blueshift { .. }))
    {
        warnings.push("Blueshift's compiler-builtins dependency has its own lockfile outside the application's dependency graph; full cross-backend reproducibility is not guaranteed.".into());
    }
    if !results
        .iter()
        .any(|r| r.profile.name == baseline && r.analysis.is_some())
    {
        warnings.push(
            "Baseline analysis failed; no deltas computed and no replacement baseline selected."
                .into(),
        );
    }
    Ok(ProfileReport {
        schema_version: 1,
        baseline: baseline.clone(),
        build_root: root,
        artifacts_preserved: keep,
        source_sha256,
        cargo_lock_sha256,
        reproducibility: warnings,
        deltas: deltas(&results, &baseline),
        profiles: results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> ProfileConfig {
        ProfileConfig::parse(
            r#"
[[profiles]]
name = "a"
builder = "cargo-build-sbf"
sbpf_version = "v0"
platform_tools_version = "v1.54"
[[profiles]]
name = "b"
builder = "cargo-build-sbpf"
sbpf_version = "v0"
rust_toolchain = "nightly"
[[profiles]]
name = "c"
builder = "cargo-build-sbf"
sbpf_version = "v0"
"#,
        )
        .unwrap()
    }
    #[test]
    fn parses_tagged_backends_and_defaults() {
        let c = config();
        assert_eq!(c.profiles.len(), 3);
        assert!(c.profiles[0].release);
        assert!(
            matches!(&c.profiles[1].backend,BuilderSettings::Blueshift {rust_toolchain:Some(t)} if t=="nightly")
        );
        let encoded = toml::to_string(&c).unwrap();
        assert_eq!(ProfileConfig::parse(&encoded).unwrap().profiles.len(), 3);
    }
    #[test]
    fn rejects_duplicates_architectures_typos_and_cross_backend_fields() {
        let base = "[[profiles]]\nname='a'\nbuilder='cargo-build-sbf'\nsbpf_version='v0'\n";
        assert!(ProfileConfig::parse(&base.repeat(2)).is_err());
        assert!(ProfileConfig::parse(&base.replace("v0", "v9")).is_err());
        assert!(ProfileConfig::parse(&(base.to_string() + "rust_toolchain='nightly'\n")).is_err());
        assert!(ProfileConfig::parse(&(base.to_string() + "releas=true\n")).is_err());
    }
    #[test]
    fn selection_and_baseline_validation() {
        assert_eq!(
            config()
                .select(&["c".into(), "a".into()])
                .unwrap()
                .profiles
                .len(),
            2
        );
        assert!(config().select(&["missing".into()]).is_err());
        assert!(
            compare_profiles(
                Path::new("/does/not/exist"),
                config(),
                Some("absent"),
                false
            )
            .unwrap_err()
            .to_string()
            .contains("baseline")
        );
    }
    #[test]
    fn absolute_and_percentage_deltas() {
        let d = MetricDelta::new(80, 60);
        assert_eq!(d.delta, -20);
        assert_eq!(d.percent, Some(-25.0));
        assert_eq!(MetricDelta::new(0, 10).percent, None);
    }
    struct Mock {
        failure: Option<&'static str>,
        wrong_arch: bool,
    }
    impl BuildBackend for Mock {
        fn build(
            &self,
            p: &CompilerProfile,
            source: &Path,
            workspace: &Path,
            dir: &Path,
        ) -> ProfileResult {
            assert!(workspace.join("Cargo.lock").exists());
            assert!(!source.join("target/stale.so").exists());
            let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("samples/hello_solana_pinocchio_program.so");
            let elf = dir.join("program.so");
            if p.name == "invalid" {
                fs::write(&elf, b"not an ELF").unwrap();
            } else {
                fs::copy(fixture, &elf).unwrap();
            }
            let mut p = p.clone();
            if self.wrong_arch {
                p.sbpf_version = Architecture::V4;
            }
            ProfileResult {
                status: if self.failure == Some(p.name.as_str()) {
                    ProfileStatus::BuildFailed
                } else {
                    ProfileStatus::Built
                },
                profile: p,
                resolved: ResolvedToolchain::default(),
                build: Some(CommandRecord::default()),
                elf_path: Some(elf),
                elf_sha256: None,
                actual_architecture: None,
                analysis: None,
                diagnostic: None,
            }
        }
    }
    fn source() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("Cargo.lock"), "# fixture").unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[workspace]\nmembers = []\n",
        )
        .unwrap();
        fs::create_dir(temp.path().join("target")).unwrap();
        fs::write(temp.path().join("target/stale.so"), "stale").unwrap();
        temp
    }
    #[test]
    fn workspace_member_preserves_inheritance_siblings_and_shared_lockfile() {
        struct WorkspaceMock;
        impl BuildBackend for WorkspaceMock {
            fn build(
                &self,
                p: &CompilerProfile,
                source: &Path,
                workspace: &Path,
                dir: &Path,
            ) -> ProfileResult {
                assert_eq!(source, workspace.join("program"));
                assert!(workspace.join("shared/src/lib.rs").is_file());
                assert!(workspace.join("Cargo.lock").is_file());
                assert!(!source.join("Cargo.lock").exists());
                // Cargo must resolve workspace inheritance from the copied member,
                // with all path dependencies contained in the isolated snapshot.
                let output = std::process::Command::new("cargo")
                    .args(["metadata", "--offline", "--locked", "--format-version", "1"])
                    .env("RUSTUP_AUTO_INSTALL", "0")
                    .current_dir(source)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                for package in metadata["packages"].as_array().unwrap() {
                    assert!(
                        Path::new(package["manifest_path"].as_str().unwrap())
                            .starts_with(workspace)
                    );
                }
                Mock {
                    failure: None,
                    wrong_arch: false,
                }
                .build(p, source, workspace, dir)
            }
        }
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("Cargo.toml"), "[workspace]\nmembers = [\"program\", \"shared\"]\nresolver = \"2\"\n[workspace.dependencies]\nshared = { path = \"shared\" }\n").unwrap();
        for name in ["program", "shared"] {
            fs::create_dir_all(root.path().join(name).join("src")).unwrap();
            fs::write(root.path().join(name).join("src/lib.rs"), "").unwrap();
            let dependencies = if name == "program" {
                "[dependencies]\nshared.workspace = true\n"
            } else {
                ""
            };
            fs::write(root.path().join(name).join("Cargo.toml"), format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n{dependencies}")).unwrap();
        }
        let before = super::super::backend::source_hashes(root.path()).unwrap();
        // Missing lockfiles are generated only inside the full workspace snapshot.
        let report = compare_with_backend(
            &root.path().join("program"),
            config(),
            None,
            false,
            &WorkspaceMock,
        )
        .unwrap();
        assert!(
            report
                .profiles
                .iter()
                .all(|p| p.status == ProfileStatus::Analyzed)
        );
        assert_eq!(
            before,
            super::super::backend::source_hashes(root.path()).unwrap()
        );
        assert!(!root.path().join("Cargo.lock").exists());
        // An existing shared lockfile must be reused byte-for-byte.
        super::super::backend::generate_lockfile(root.path()).unwrap();
        let lock = fs::read(root.path().join("Cargo.lock")).unwrap();
        let report = compare_with_backend(
            &root.path().join("program"),
            config(),
            None,
            false,
            &WorkspaceMock,
        )
        .unwrap();
        assert_eq!(
            report.cargo_lock_sha256,
            format!("{:x}", Sha256::digest(&lock))
        );
        assert_eq!(fs::read(root.path().join("Cargo.lock")).unwrap(), lock);
    }
    #[test]
    fn mock_comparison_failure_isolation_baseline_json_and_cleanup() {
        let src = source();
        let r = compare_with_backend(
            src.path(),
            config(),
            Some("c"),
            false,
            &Mock {
                failure: Some("b"),
                wrong_arch: false,
            },
        )
        .unwrap();
        assert_eq!(r.profiles[0].status, ProfileStatus::Analyzed);
        assert_eq!(r.profiles[1].status, ProfileStatus::BuildFailed);
        assert_eq!(r.profiles[2].status, ProfileStatus::Analyzed);
        assert_eq!(r.deltas.len(), 1);
        assert_eq!(r.deltas[0].baseline, "c");
        assert_eq!(r.deltas[0].profile, "a");
        assert_eq!(r.deltas[0].metrics["instructions"].delta, 0);
        assert_ne!(r.profiles[0].elf_path, r.profiles[2].elf_path);
        assert!(!r.build_root.exists());
        let json: serde_json::Value = serde_json::from_str(&r.to_json().unwrap()).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["baseline"], "c");
        assert!(r.render(true).contains("Opcode"));
        // The general-diff adapter must retain command records and provenance.
        let legacy = super::super::CompilerDiff::legacy_report(r.clone());
        let saved = serde_json::to_value(&legacy).unwrap();
        assert_eq!(saved["profile_report"], json);
        for format in [
            super::super::render::OutputFormat::Terminal,
            super::super::render::OutputFormat::Markdown,
        ] {
            let options = super::super::render::RenderOptions {
                format,
                ..Default::default()
            };
            assert_eq!(
                super::super::render::render_legacy(&legacy, false, &options),
                super::super::render::render(&r, &options)
            );
        }
    }
    #[test]
    fn successful_build_with_invalid_elf_is_distinct_from_compile_failure() {
        let src = source();
        let mut c = config();
        c.profiles[0].name = "invalid".into();
        let r = compare_with_backend(
            src.path(),
            c,
            None,
            false,
            &Mock {
                failure: Some("b"),
                wrong_arch: false,
            },
        )
        .unwrap();
        assert_eq!(r.profiles[0].status, ProfileStatus::AnalysisFailed);
        assert!(r.profiles[0].build.is_some());
        assert!(r.profiles[0].analysis.is_none());
        assert_eq!(r.profiles[1].status, ProfileStatus::BuildFailed);
        assert_eq!(r.profiles[2].status, ProfileStatus::Analyzed);
    }
    #[test]
    fn three_successful_profiles_compare_against_one_named_baseline() {
        let src = source();
        let r = compare_with_backend(
            src.path(),
            config(),
            Some("b"),
            false,
            &Mock {
                failure: None,
                wrong_arch: false,
            },
        )
        .unwrap();
        assert_eq!(r.deltas.len(), 2);
        assert!(r.deltas.iter().all(|d| d.baseline == "b"));
        assert_eq!(
            r.profiles
                .iter()
                .filter(|r| r.status == ProfileStatus::Analyzed)
                .count(),
            3
        );
    }
    #[test]
    fn failed_baseline_never_falls_back_and_keep_preserves_artifacts() {
        let src = source();
        let r = compare_with_backend(
            src.path(),
            config(),
            Some("b"),
            true,
            &Mock {
                failure: Some("b"),
                wrong_arch: false,
            },
        )
        .unwrap();
        assert!(r.deltas.is_empty());
        assert!(r.build_root.exists());
        assert!(r.profiles[0].elf_path.as_ref().unwrap().is_file());
        fs::remove_dir_all(r.build_root).unwrap();
    }
    #[test]
    fn actual_architecture_mismatch_is_analysis_failure() {
        let src = source();
        let mut c = config();
        c.profiles[0].sbpf_version = Architecture::V4;
        let r = compare_with_backend(
            src.path(),
            c,
            None,
            false,
            &Mock {
                failure: None,
                wrong_arch: false,
            },
        )
        .unwrap();
        assert_eq!(r.profiles[0].status, ProfileStatus::AnalysisFailed);
        assert_eq!(r.profiles[0].actual_architecture, Some(0));
        assert!(
            r.profiles[0]
                .diagnostic
                .as_deref()
                .unwrap()
                .contains("architecture mismatch")
        );
    }
}
