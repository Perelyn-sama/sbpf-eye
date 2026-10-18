use super::profiles::*;
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

pub(super) trait BuildBackend {
    fn build(
        &self,
        profile: &CompilerProfile,
        source: &Path,
        workspace: &Path,
        directory: &Path,
    ) -> ProfileResult;
}
pub(super) struct NativeBackend;
struct AnzaBackend;
struct BlueshiftBackend;
impl BuildBackend for NativeBackend {
    fn build(
        &self,
        p: &CompilerProfile,
        source: &Path,
        workspace: &Path,
        dir: &Path,
    ) -> ProfileResult {
        match p.backend {
            BuilderSettings::Anza { .. } => AnzaBackend.build(p, source, workspace, dir),
            BuilderSettings::Blueshift { .. } => BlueshiftBackend.build(p, source, workspace, dir),
        }
    }
}
impl BuildBackend for AnzaBackend {
    fn build(
        &self,
        p: &CompilerProfile,
        source: &Path,
        workspace: &Path,
        dir: &Path,
    ) -> ProfileResult {
        build_result(p, source, workspace, dir)
    }
}
impl BuildBackend for BlueshiftBackend {
    fn build(
        &self,
        p: &CompilerProfile,
        source: &Path,
        workspace: &Path,
        dir: &Path,
    ) -> ProfileResult {
        build_result(p, source, workspace, dir)
    }
}
fn build_result(p: &CompilerProfile, source: &Path, workspace: &Path, dir: &Path) -> ProfileResult {
    let mut r = ProfileResult {
        profile: p.clone(),
        resolved: ResolvedToolchain::default(),
        status: ProfileStatus::Unsupported,
        build: None,
        elf_path: None,
        elf_sha256: None,
        actual_architecture: None,
        analysis: None,
        diagnostic: None,
    };
    if let Err(e) = build(p, source, workspace, dir, &mut r) {
        r.diagnostic = Some(format!("{e:#}"));
    }
    r
}
fn validate_toolchain_selector(selector: Option<&str>) -> Result<()> {
    if selector.is_some_and(|s| s != "nightly") {
        bail!(
            "upstream cargo-build-sbpf hardcodes +nightly; requested rust_toolchain cannot be honored. Select nightly; dated/custom selectors require a verified upstream interface"
        );
    }
    Ok(())
}
fn validate_linker_version(version: &str) -> Result<()> {
    let number = version
        .strip_prefix("sbpf-linker ")
        .and_then(|s| s.split_whitespace().next())
        .context("cannot identify sbpf-linker version")?;
    let parts = number
        .split('.')
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("cannot identify sbpf-linker version")?;
    if parts.len() != 3 || parts.as_slice() < [0, 2, 3].as_slice() {
        bail!("sbpf-linker >=0.2.3 is required; install it manually");
    }
    Ok(())
}
fn validate(p: &CompilerProfile) -> Result<()> {
    if let BuilderSettings::Blueshift { rust_toolchain } = &p.backend {
        validate_toolchain_selector(rust_toolchain.as_deref())?;
    }

    if let Some(level) = &p.opt_level
        && !["0", "1", "2", "3", "s", "z"].contains(&level.as_str())
    {
        bail!("invalid opt_level `{level}`");
    }
    // Explicit allowlists prevent arguments from redirecting output, selecting another compiler,
    // rewriting config, or changing dependency resolution behind the profile's back.
    for (key, value) in &p.env {
        if ![
            "CARGO_PROFILE_RELEASE_CODEGEN_UNITS",
            "CARGO_PROFILE_RELEASE_LTO",
            "CARGO_PROFILE_RELEASE_DEBUG",
            "CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS",
        ]
        .contains(&key.as_str())
        {
            bail!(
                "environment override `{key}` is unsupported; compiler, flags, paths and setup controls must not be overridden"
            );
        }
        if value.contains('\0') || value.contains('\n') {
            bail!("invalid environment value for {key}");
        }
        let valid = match key.as_str() {
            "CARGO_PROFILE_RELEASE_CODEGEN_UNITS" => value.parse::<u32>().is_ok_and(|n| n > 0),
            "CARGO_PROFILE_RELEASE_LTO" => {
                ["true", "false", "thin", "fat", "off"].contains(&value.as_str())
            }
            "CARGO_PROFILE_RELEASE_DEBUG" => [
                "0",
                "1",
                "2",
                "true",
                "false",
                "none",
                "limited",
                "full",
                "line-tables-only",
            ]
            .contains(&value.as_str()),
            _ => ["true", "false"].contains(&value.as_str()),
        };
        if !valid {
            bail!("invalid value `{value}` for {key}");
        }
    }
    for arg in &p.builder_args {
        let allowed = match p.backend {
            BuilderSettings::Anza { .. } => {
                ["--optimize-size", "--lto", "--disable-remap-cwd"].contains(&arg.as_str())
            }
            BuilderSettings::Blueshift { .. } => arg == "--simd-0460",
        };
        if !allowed {
            bail!("unsupported builder argument `{arg}`; setup and output overrides are forbidden");
        }
    }
    for arg in &p.cargo_args {
        if arg != "--no-default-features"
            && arg != "--all-features"
            && !arg.strip_prefix("--features=").is_some_and(|v| {
                !v.is_empty()
                    && v.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_-,/ ".contains(c))
            })
            && !arg.strip_prefix("--package=").is_some_and(|v| {
                !v.is_empty()
                    && v.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c))
            })
        {
            bail!(
                "unsupported Cargo argument `{arg}`; allowed: --features=..., --package=..., --all-features, --no-default-features"
            );
        }
    }
    if matches!(p.backend, BuilderSettings::Blueshift { .. }) && !p.release {
        bail!("cargo-build-sbpf always builds --release; release=false is unsupported");
    }
    Ok(())
}
fn environment(p: &CompilerProfile) -> BTreeMap<String, String> {
    // Start clean, preserving only OS/tool discovery and the existing tool caches.
    let mut env: BTreeMap<_, _> = [
        "PATH",
        "HOME",
        "USERPROFILE",
        "SystemRoot",
        "TMPDIR",
        "TEMP",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "SOLANA_PLATFORM_TOOLS_DIR",
    ]
    .into_iter()
    .filter_map(|k| std::env::var(k).ok().map(|v| (k.into(), v)))
    .collect();
    env.extend(p.env.clone());
    env.insert("CARGO_NET_OFFLINE".into(), "true".into());
    env.insert("CARGO_TERM_COLOR".into(), "never".into());
    env.insert("RUSTUP_AUTO_INSTALL".into(), "0".into());
    if let Some(level) = &p.opt_level {
        env.insert(
            format!(
                "CARGO_PROFILE_{}_OPT_LEVEL",
                if p.release { "RELEASE" } else { "DEV" }
            ),
            level.clone(),
        );
    }
    env
}
fn command(exe: &Path, args: &[String], cwd: &Path, env: &BTreeMap<String, String>) -> Command {
    let mut c = Command::new(exe);
    c.args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(env)
        .stdin(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid is async-signal-safe; no allocation or locks in the child hook.
        // Closing stdin alone is insufficient: dialoguer can open /dev/tty.
        unsafe {
            c.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    c
}
fn run(
    exe: &Path,
    args: &[String],
    cwd: &Path,
    env: &BTreeMap<String, String>,
) -> Result<CommandRecord> {
    let start = Instant::now();
    let output = command(exe, args, cwd, env)
        .output()
        .with_context(|| format!("cannot run {}", exe.display()))?;
    Ok(CommandRecord {
        argv: std::iter::once(exe.display().to_string())
            .chain(args.iter().cloned())
            .collect(),
        cwd: cwd.into(),
        environment: env.clone(),
        stdout: String::from_utf8_lossy(&output.stdout).into(),
        stderr: String::from_utf8_lossy(&output.stderr).into(),
        exit_code: output.status.code(),
        duration_ms: start.elapsed().as_millis(),
    })
}
fn probe(exe: &Path, args: &[&str], cwd: &Path, env: &BTreeMap<String, String>) -> Result<String> {
    let r = run(
        exe,
        &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        cwd,
        env,
    )?;
    if r.exit_code != Some(0) {
        bail!("probe {:?} failed: {}{}", r.argv, r.stdout, r.stderr);
    }
    Ok(format!("{}{}", r.stdout, r.stderr).trim().into())
}
fn executable(path: &Path, env: &BTreeMap<String, String>) -> Result<PathBuf> {
    fn usable(p: &Path) -> bool {
        if !p.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            p.metadata()
                .is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
        }
        #[cfg(not(unix))]
        {
            true
        }
    }
    if path.is_absolute() && usable(path) {
        return Ok(path.to_path_buf());
    }
    if path.components().count() != 1 {
        bail!(
            "builder/tool path {} must be absolute or a PATH name",
            path.display()
        );
    }
    if let Some(paths) = env.get("PATH") {
        for dir in std::env::split_paths(paths) {
            let candidate = dir.join(path);
            if candidate.is_absolute() && usable(&candidate) {
                return Ok(candidate);
            }
        }
    }
    bail!(
        "executable `{}` unavailable; install it manually or specify an absolute builder_path",
        path.display()
    )
}
fn rust_metadata(text: &str, r: &mut ResolvedToolchain) -> Result<()> {
    let field = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key).map(|s| s.trim().to_string()))
            .filter(|v| !v.is_empty() && v != "unknown")
    };
    r.rustc_version = field("release:");
    r.rustc_commit = field("commit-hash:");
    r.llvm_version = field("LLVM version:");
    if r.rustc_version.is_none() || r.llvm_version.is_none() {
        bail!("unable to identify compiler release and LLVM version from rustc -vV");
    }
    if r.rustc_commit.is_none() {
        r.diagnostics.push(
            "rustc reports an unknown commit; exact compiler provenance is unavailable".into(),
        );
    }
    Ok(())
}
fn require(help: &str, flag: &str) -> Result<()> {
    if !help.split_whitespace().any(|s| s.trim_matches(',') == flag) {
        bail!(
            "installed builder does not advertise required option {flag}; use a compatible builder"
        );
    }
    Ok(())
}
fn architecture(
    exe: &Path,
    prefix: &[&str],
    p: &CompilerProfile,
    cwd: &Path,
    env: &BTreeMap<String, String>,
) -> Result<()> {
    // Invalid enum parsing exits before setup, including for Blueshift's hidden --arch.
    let args: Vec<String> = prefix
        .iter()
        .map(|s| s.to_string())
        .chain(["--arch".into(), "sbpf-eye-invalid-probe".into()])
        .collect();
    let r = run(exe, &args, cwd, env)?;
    let diagnostic = format!("{}{}", r.stdout, r.stderr);
    let supported = diagnostic
        .split("possible values:")
        .nth(1)
        .and_then(|s| s.split(']').next())
        .unwrap_or("");
    if !supported
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|s| s == p.sbpf_version.arch())
    {
        bail!(
            "installed builder did not confirm architecture {} in argument parser diagnostics: {}",
            p.sbpf_version.arch(),
            diagnostic
        );
    }
    Ok(())
}
fn build(
    p: &CompilerProfile,
    source: &Path,
    workspace: &Path,
    dir: &Path,
    r: &mut ProfileResult,
) -> Result<()> {
    validate(p)?;
    #[cfg(not(unix))]
    {
        bail!("non-interactive builder isolation currently requires Unix");
    }
    let mut env = environment(p);
    inspect_configs(source, &env, &mut r.resolved)?;
    let exe = executable(
        p.builder_path
            .as_deref()
            .unwrap_or(Path::new(p.backend.executable())),
        &env,
    )?;
    r.resolved.builder_path = Some(exe.clone());
    let prefix = if matches!(p.backend, BuilderSettings::Blueshift { .. }) {
        vec!["build-sbpf"]
    } else {
        vec![]
    };
    let mut help_args = prefix.clone();
    help_args.push("--help");
    let help = probe(&exe, &help_args, source, &env)?;
    let mut version_args = prefix.clone();
    version_args.push("--version");
    r.resolved.builder_version = Some(probe(&exe, &version_args, source, &env)?);
    architecture(&exe, &prefix, p, source, &env)?;
    let mut args: Vec<String> = prefix.iter().map(|s| s.to_string()).collect();
    args.extend(["--arch".into(), p.sbpf_version.arch()]);
    let out = dir.join("elf");
    fs::create_dir(&out)?;
    let target = dir.join("target");
    fs::create_dir(&target)?;
    env.insert("CARGO_TARGET_DIR".into(), target.display().to_string());
    match &p.backend {
        BuilderSettings::Anza {
            platform_tools_version,
        } => {
            for flag in [
                "--skip-tools-install",
                "--no-rustup-override",
                "--sbf-out-dir",
                "--tools-version",
                "--offline",
                "--verbose",
            ] {
                require(&help, flag)?;
            }
            let manifest: toml::Value =
                toml::from_str(&fs::read_to_string(source.join("Cargo.toml"))?)?;
            let metadata_version = manifest
                .get("package")
                .and_then(|p| p.get("metadata"))
                .or_else(|| manifest.get("workspace").and_then(|w| w.get("metadata")))
                .and_then(|m| m.get("solana"))
                .and_then(|m| m.get("tools-version"))
                .and_then(toml::Value::as_str)
                .map(str::to_owned);
            let version=platform_tools_version.clone().or(metadata_version).or_else(||r.resolved.builder_version.as_ref().and_then(|s|s.lines().find_map(|l|l.strip_prefix("Default platform-tools: ").or_else(||l.strip_prefix("platform-tools ")).map(str::to_string)))).context("cannot resolve default platform-tools version; explicitly configure platform_tools_version")?;
            if !version.starts_with('v')
                || !version[1..].chars().all(|c| c.is_ascii_digit() || c == '.')
                || !version[1..].contains('.')
            {
                bail!("platform_tools_version must be an exact version such as v1.53");
            }
            let cache = env
                .get("SOLANA_PLATFORM_TOOLS_DIR")
                .map(PathBuf::from)
                .or_else(|| {
                    env.get("HOME")
                        .map(|h| PathBuf::from(h).join(".cache/solana"))
                })
                .context("cannot locate platform-tools cache")?;
            let parts = version[1..]
                .split('.')
                .map(str::parse::<u32>)
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("invalid platform-tools version")?;
            if !(2..=3).contains(&parts.len()) {
                bail!("platform_tools_version must have two or three numeric components");
            }
            r.resolved.platform_tools_version = Some(version.clone());
            let tools = cache.join(&version).join("platform-tools");
            let rustc=executable(&tools.join("rust/bin/rustc"),&env).context("requested platform-tools are not installed; install them manually before comparing")?;
            executable(&tools.join("rust/bin/cargo"), &env)?;
            r.resolved.rustc_path = Some(rustc.clone());
            rust_metadata(&probe(&rustc, &["-vV"], source, &env)?, &mut r.resolved)?;
            let target_name = if p.sbpf_version == Architecture::V0 {
                if parts.as_slice() < [1, 44].as_slice() {
                    "sbf-solana-solana".into()
                } else {
                    "sbpf-solana-solana".into()
                }
            } else {
                format!("sbpf{}-solana-solana", p.sbpf_version.arch())
            };
            let spec = probe(
                &rustc,
                &[
                    "-Z",
                    "unstable-options",
                    "--print",
                    "target-spec-json",
                    "--target",
                    &target_name,
                ],
                source,
                &env,
            )
            .context("requested compiler does not support the target")?;
            let spec: serde_json::Value = serde_json::from_str(&spec)?;
            if spec["linker"] != "rust-lld" {
                bail!("cannot resolve compiler target linker: {}", spec["linker"]);
            }
            r.resolved.target_spec = Some(spec);
            let compiler_info = probe(&rustc, &["-vV"], source, &env)?;
            let host = compiler_info
                .lines()
                .find_map(|l| l.strip_prefix("host: "))
                .context("rustc did not report host")?;
            let linker = tools
                .join("rust/lib/rustlib")
                .join(host)
                .join("bin/rust-lld");
            r.resolved.linker_path = Some(linker.clone());
            r.resolved.linker_version = Some(
                probe(&linker, &["-flavor", "gnu", "--version"], source, &env)
                    .context("cannot identify platform-tools linker")?,
            );
            r.resolved.platform_tools_version = Some(version.clone());
            let paths = std::iter::once(tools.join("rust/bin")).chain(std::env::split_paths(
                env.get("PATH").map(String::as_str).unwrap_or(""),
            ));
            env.insert(
                "PATH".into(),
                std::env::join_paths(paths)?.to_string_lossy().into(),
            );
            env.insert("RUSTC".into(), rustc.display().to_string());
            args.extend([
                "--skip-tools-install".into(),
                "--no-rustup-override".into(),
                "--offline".into(),
                "--verbose".into(),
                "--tools-version".into(),
                version,
                "--sbf-out-dir".into(),
                out.display().to_string(),
            ]);
            if !p.release {
                require(&help, "--debug")?;
                args.push("--debug".into());
            }
        }
        BuilderSettings::Blueshift { .. } => {
            // Config discovery can trigger write prompts, including in CARGO_HOME. Reject before launch.
            for ancestor in source.ancestors() {
                for name in [".cargo/config", ".cargo/config.toml"] {
                    if ancestor.join(name).exists() {
                        bail!(
                            "Blueshift setup may edit Cargo config at {}; prepare a config-free source snapshot manually",
                            ancestor.join(name).display()
                        );
                    }
                }
            }
            let cargo_home = env
                .get("CARGO_HOME")
                .map(PathBuf::from)
                .or_else(|| env.get("HOME").map(|h| PathBuf::from(h).join(".cargo")))
                .context("cannot locate Cargo home")?;
            for name in ["config", "config.toml"] {
                if cargo_home.join(name).exists() {
                    bail!(
                        "Blueshift may prompt to edit {}; global Cargo config is unsupported for non-interactive comparison",
                        cargo_home.join(name).display()
                    );
                }
            }
            let rustup = executable(Path::new("rustup"), &env)?;
            let compiler = probe(
                &rustup,
                &["which", "--toolchain", "nightly", "rustc"],
                source,
                &env,
            )
            .context("nightly is unavailable; install it manually")?;
            let rustc = PathBuf::from(compiler);
            r.resolved.rustc_path = Some(rustc.clone());
            r.resolved.rust_toolchain = Some("nightly".into());
            rust_metadata(&probe(&rustc, &["-vV"], source, &env)?, &mut r.resolved)?;
            if !r
                .resolved
                .llvm_version
                .as_deref()
                .is_some_and(|v| v.starts_with("23."))
            {
                bail!(
                    "Blueshift setup prompts to update nightly unless it uses LLVM 23; manually prepare a compatible nightly before comparing"
                );
            }
            let sysroot = probe(&rustc, &["--print", "sysroot"], source, &env)?;
            if !Path::new(&sysroot)
                .join("lib/rustlib/src/rust/library/core/Cargo.toml")
                .is_file()
            {
                bail!("nightly rust-src is missing; install it manually before comparing");
            }
            let linker = executable(Path::new("sbpf-linker"), &env)
                .or_else(|_| executable(&cargo_home.join("bin/sbpf-linker"), &env))?;
            let version = probe(&linker, &["--version"], source, &env)?;
            r.resolved.linker_path = Some(linker.clone());
            r.resolved.linker_version = Some(version.clone());
            validate_linker_version(&version)?;
            env.insert(
                "SBPF_COMPILER_BUILTINS_CACHE".into(),
                dir.join("builtins").display().to_string(),
            );
            args.push("--verbose".into());
        }
    }
    for arg in &p.builder_args {
        if arg != "--simd-0460" {
            require(&help, arg)?;
        } else {
            bail!(
                "hidden --simd-0460 cannot be validated safely on the installed builder; unsupported"
            );
        }
    }
    args.extend(p.builder_args.clone());
    args.extend([
        "--".into(),
        "--locked".into(),
        "--offline".into(),
        "--target-dir".into(),
        target.display().to_string(),
    ]);
    args.extend(p.cargo_args.clone());
    validate_snapshot(source, workspace, &env)?;
    let before = source_hashes(workspace)?;
    r.status = ProfileStatus::BuildFailed;
    r.build = Some(run(&exe, &args, source, &env)?);
    let after = source_hashes(workspace)?;
    let build = r.build.as_ref().unwrap();
    if build.exit_code != Some(0) {
        verify_source_unchanged(&before, &after, None)?;
        if super::is_unsupported_target_error(&build.stderr) {
            r.status = ProfileStatus::Unsupported;
        }
        bail!(
            "builder failed; see captured stdout/stderr. Setup prompts are never accepted; install prerequisites and prepare Cargo configuration manually"
        );
    }
    let artifact_dir = match p.backend {
        BuilderSettings::Anza { .. } => {
            if p.release {
                out
            } else {
                out.join("debug")
            }
        }
        BuilderSettings::Blueshift { .. } => target.join("bpfel-unknown-none/release"),
    };
    let elf = find_elf(&artifact_dir)?;
    let elf_hash = format!("{:x}", Sha256::digest(fs::read(&elf)?));
    // Some installed Blueshift builders/linkers also export a deployment copy
    // beneath cwd, despite Cargo's explicit --target-dir. Accept only that exact
    // new file, and only if it matches the fresh Cargo artifact byte-for-byte.
    let deployment = if matches!(p.backend, BuilderSettings::Blueshift { .. }) {
        let stem = elf
            .file_stem()
            .and_then(|s| s.to_str())
            .context("invalid ELF filename")?;
        let name = stem.strip_prefix("lib").unwrap_or(stem);
        Some((
            source
                .strip_prefix(workspace)?
                .join("target/deploy")
                .join(format!("{name}.so")),
            elf_hash.clone(),
        ))
    } else {
        None
    };
    verify_source_unchanged(&before, &after, deployment.as_ref())?;
    r.elf_sha256 = Some(elf_hash);
    r.elf_path = Some(elf);
    r.status = ProfileStatus::Built;
    Ok(())
}
fn verify_source_unchanged(
    before: &BTreeMap<PathBuf, String>,
    after: &BTreeMap<PathBuf, String>,
    deployment: Option<&(PathBuf, String)>,
) -> Result<()> {
    let changed: std::collections::BTreeSet<_> = before
        .keys()
        .chain(after.keys())
        .filter(|path| before.get(*path) != after.get(*path))
        .filter(|path| {
            !deployment.is_some_and(|(allowed, hash)| {
                *path == allowed && !before.contains_key(*path) && after.get(*path) == Some(hash)
            })
        })
        .map(|p| p.display().to_string())
        .collect();
    if !changed.is_empty() {
        bail!(
            "builder modified files in isolated source copy: {}; result rejected (original source was not changed)",
            changed.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
    Ok(())
}

fn find_elf(dir: &Path) -> Result<PathBuf> {
    let mut candidates = Vec::new();
    for entry in
        fs::read_dir(dir).with_context(|| format!("no artifact directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file() && path.extension().is_some_and(|e| e == "so") {
            candidates.push(path);
        }
    }
    if candidates.len() != 1 {
        bail!(
            "expected exactly one fresh .so in {}, found {}; select one program with cargo_args=['--package=...']",
            dir.display(),
            candidates.len()
        );
    }
    Ok(candidates.remove(0))
}
fn validate_snapshot(
    source: &Path,
    workspace: &Path,
    env: &BTreeMap<String, String>,
) -> Result<()> {
    let cargo = executable(Path::new("cargo"), env)?;
    let output = run(
        &cargo,
        &["metadata", "--format-version", "1", "--offline", "--locked"].map(str::to_owned),
        source,
        env,
    )?;
    if output.exit_code != Some(0) {
        bail!("snapshot dependency validation failed: {}", output.stderr);
    }
    let metadata: serde_json::Value = serde_json::from_str(&output.stdout)?;
    for package in metadata["packages"]
        .as_array()
        .context("invalid cargo metadata")?
    {
        if package["source"].is_null() {
            let manifest = Path::new(
                package["manifest_path"]
                    .as_str()
                    .context("missing manifest path")?,
            )
            .canonicalize()?;
            if !manifest.starts_with(workspace) {
                bail!(
                    "path dependency {} is outside source snapshot; pass a common workspace root",
                    manifest.display()
                );
            }
        }
    }
    Ok(())
}
pub(super) fn copy_source(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if ["target", ".git"].iter().any(|n| name == *n) {
            continue;
        }
        let ty = entry.file_type()?;
        let to = dst.join(&name);
        if ty.is_symlink() {
            bail!(
                "source symlink {} cannot be safely isolated; use a self-contained workspace",
                entry.path().display()
            );
        }
        if ty.is_dir() {
            copy_source(&entry.path(), &to)?;
        } else if ty.is_file() {
            fs::copy(entry.path(), to)?;
        }
    }
    Ok(())
}
pub(super) fn source_hashes(root: &Path) -> Result<BTreeMap<PathBuf, String>> {
    fn walk(root: &Path, path: &Path, m: &mut BTreeMap<PathBuf, String>) -> Result<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let p = entry.path();
            let ty = entry.file_type()?;
            if ty.is_symlink() {
                bail!("builder created source symlink {}", p.display());
            }
            if ty.is_dir() {
                walk(root, &p, m)?;
            } else if ty.is_file() {
                m.insert(
                    p.strip_prefix(root)?.into(),
                    format!("{:x}", Sha256::digest(fs::read(p)?)),
                );
            }
        }
        Ok(())
    }
    let mut m = BTreeMap::new();
    walk(root, root, &mut m)?;
    Ok(m)
}

/// Locate the workspace without resolving dependencies or writing a lockfile.
pub(super) fn workspace_root(source: &Path, profile: &CompilerProfile) -> Result<PathBuf> {
    if !source.join("Cargo.toml").is_file() {
        bail!(
            "program directory {} does not contain Cargo.toml",
            source.display()
        );
    }
    let env = environment(profile);
    let cargo = executable(Path::new("cargo"), &env)?;
    let manifest = probe(
        &cargo,
        &["locate-project", "--workspace", "--message-format", "plain"],
        source,
        &env,
    )
    .context("cannot locate Cargo workspace for the selected program")?;
    let manifest = PathBuf::from(manifest).canonicalize()?;
    let root = manifest
        .parent()
        .context("workspace manifest has no parent")?;
    if !source.starts_with(root) {
        bail!(
            "program is outside its Cargo workspace root {}; use a self-contained workspace",
            root.display()
        );
    }
    Ok(root.to_path_buf())
}

pub(super) fn generate_lockfile(source: &Path) -> Result<()> {
    let p = CompilerProfile {
        name: "snapshot".into(),
        backend: BuilderSettings::Anza {
            platform_tools_version: None,
        },
        builder_path: None,
        sbpf_version: Architecture::V0,
        release: true,
        opt_level: None,
        builder_args: vec![],
        cargo_args: vec![],
        env: BTreeMap::new(),
    };
    let env = environment(&p);
    let cargo = executable(Path::new("cargo"), &env)?;
    probe(&cargo, &["generate-lockfile", "--offline"], source, &env)?;
    Ok(())
}
fn inspect_configs(
    source: &Path,
    env: &BTreeMap<String, String>,
    resolved: &mut ResolvedToolchain,
) -> Result<()> {
    let mut paths = Vec::new();
    for dir in source.ancestors() {
        for name in [".cargo/config", ".cargo/config.toml"] {
            let path = dir.join(name);
            if path.is_file() {
                paths.push(path);
            }
        }
    }
    let home = env
        .get("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env.get("HOME").map(|h| PathBuf::from(h).join(".cargo")));
    if let Some(home) = home {
        for name in ["config", "config.toml"] {
            let path = home.join(name);
            if path.is_file() {
                paths.push(path);
            }
        }
    }
    for path in paths {
        let text = fs::read_to_string(&path)?;
        let config: toml::Value = toml::from_str(&text)?;
        fn check(v: &toml::Value) -> Result<()> {
            if let Some(table) = v.as_table() {
                for (k, v) in table {
                    if [
                        "rustc",
                        "rustc-wrapper",
                        "rustc-workspace-wrapper",
                        "linker",
                        "rustflags",
                        "target-dir",
                        "env",
                        "paths",
                    ]
                    .contains(&k.as_str())
                    {
                        bail!(
                            "Cargo config `{k}` can override the measured compiler/environment; express settings in profiles or use a self-contained config without overrides"
                        );
                    }
                    check(v)?;
                }
            }
            Ok(())
        }
        check(&config).with_context(|| format!("unsupported Cargo config {}", path.display()))?;
        resolved.cargo_configs.insert(path, text);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> CompilerProfile {
        super::super::profiles::ProfileConfig::parse(
            "[[profiles]]\nname='test'\nbuilder='cargo-build-sbf'\nsbpf_version='v0'\n",
        )
        .unwrap()
        .profiles
        .remove(0)
    }
    #[test]
    fn invalid_or_unhonored_rustup_toolchain_is_rejected() {
        for t in ["", "stable", "does-not-exist", "nightly-2026-10-04"] {
            assert!(validate_toolchain_selector(Some(t)).is_err());
        }
        assert!(validate_toolchain_selector(Some("nightly")).is_ok());
    }
    #[test]
    fn missing_or_incompatible_linker_metadata_is_rejected() {
        for v in ["", "LLD 23", "sbpf-linker unknown", "sbpf-linker 0.2.2"] {
            assert!(validate_linker_version(v).is_err());
        }
        assert!(validate_linker_version("sbpf-linker 0.2.3\nLLVM 23.1.0").is_ok());
    }
    #[test]
    fn unknown_commit_is_reported_without_inventing_provenance() {
        let mut r = ResolvedToolchain::default();
        rust_metadata(
            "release: 1.89.0-dev\ncommit-hash: unknown\nLLVM version: 20.1.7",
            &mut r,
        )
        .unwrap();
        assert!(r.rustc_commit.is_none());
        assert!(!r.diagnostics.is_empty());
    }
    #[test]
    fn missing_executable_is_actionable() {
        let e = executable(Path::new("sbpf-eye-no-such-builder"), &BTreeMap::new()).unwrap_err();
        assert!(e.to_string().contains("install it manually"));
    }
    #[test]
    fn exact_rust_metadata_is_required() {
        let mut r = ResolvedToolchain::default();
        assert!(rust_metadata("rustc 1.2 nightly", &mut r).is_err());
        assert!(r.rustc_version.is_none());
        rust_metadata(
            "release: 1.99-nightly\ncommit-hash: abcdef\nLLVM version: 23.1.0",
            &mut r,
        )
        .unwrap();
        assert_eq!(r.rustc_commit.as_deref(), Some("abcdef"));
    }
    #[test]
    fn arguments_and_environment_cannot_bypass_isolation() {
        for arg in [
            "--force-tools-install",
            "--yes",
            "--sbf-out-dir=/tmp",
            "--manifest-path=elsewhere",
        ] {
            let mut p = profile();
            p.builder_args.push(arg.into());
            assert!(validate(&p).is_err());
        }
        for arg in [
            "--target-dir=/tmp",
            "--config=env.RUSTC='other'",
            "+nightly",
            "--manifest-path=elsewhere",
        ] {
            let mut p = profile();
            p.cargo_args.push(arg.into());
            assert!(validate(&p).is_err());
        }
        for key in [
            "PATH",
            "RUSTC",
            "RUSTFLAGS",
            "CARGO_HOME",
            "RUSTUP_TOOLCHAIN",
        ] {
            let mut p = profile();
            p.env.insert(key.into(), "other".into());
            assert!(validate(&p).is_err());
        }
        let mut p = profile();
        p.env
            .insert("CARGO_PROFILE_RELEASE_LTO".into(), "thin".into());
        assert!(validate(&p).is_ok());
    }
    #[test]
    fn snapshot_excludes_stale_artifacts_and_rejects_symlinks() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        fs::create_dir(src.path().join("target")).unwrap();
        fs::write(src.path().join("target/stale.so"), "stale").unwrap();
        fs::write(src.path().join("Cargo.toml"), "test").unwrap();
        copy_source(src.path(), dst.path()).unwrap();
        assert!(!dst.path().join("target").exists());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/tmp", src.path().join("escape")).unwrap();
            assert!(copy_source(src.path(), dst.path()).is_err());
        }
    }
    #[test]
    fn ambiguous_or_missing_artifact_is_never_silently_selected() {
        let dir = tempfile::tempdir().unwrap();
        assert!(find_elf(dir.path()).is_err());
        fs::write(dir.path().join("one.so"), b"elf").unwrap();
        assert!(find_elf(dir.path()).is_ok());
        fs::write(dir.path().join("two.so"), b"elf").unwrap();
        assert!(find_elf(dir.path()).is_err());
    }
    #[test]
    #[cfg(unix)]
    fn child_has_no_interactive_input_or_controlling_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let record = run(
            Path::new("/bin/sh"),
            &["-c".into(), "test ! -t 0 && ! (exec 3</dev/tty)".into()],
            dir.path(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(record.exit_code, Some(0));
    }
    #[test]
    fn deployment_copy_is_allowed_only_when_new_and_matching_fresh_elf() {
        let before = BTreeMap::from([(PathBuf::from("Cargo.lock"), "lock".into())]);
        let deployment: (PathBuf, String) = (
            PathBuf::from("target/deploy/program.so"),
            "fresh-elf".into(),
        );
        let mut after = before.clone();
        after.insert(deployment.0.clone(), deployment.1.clone());
        assert!(verify_source_unchanged(&before, &after, Some(&deployment)).is_ok());
        assert!(verify_source_unchanged(&before, &after, None).is_err());
        after.insert(deployment.0.clone(), "different-elf".into());
        assert!(verify_source_unchanged(&before, &after, Some(&deployment)).is_err());
        after.insert(deployment.0.clone(), deployment.1.clone());
        for path in [
            "Cargo.lock",
            "Cargo.toml",
            "src/lib.rs",
            ".cargo/config.toml",
            "target/unexpected.so",
        ] {
            let mut modified = after.clone();
            modified.insert(path.into(), "changed".into());
            let error = verify_source_unchanged(&before, &modified, Some(&deployment)).unwrap_err();
            assert!(error.to_string().contains(path));
        }
        let mut stale = before.clone();
        stale.insert(deployment.0.clone(), "old-elf".into());
        assert!(verify_source_unchanged(&stale, &after, Some(&deployment)).is_err());
    }

    #[test]
    fn source_mutation_is_detected() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("Cargo.toml"), "before").unwrap();
        let before = source_hashes(d.path()).unwrap();
        fs::write(d.path().join("Cargo.toml"), "after").unwrap();
        assert_ne!(before, source_hashes(d.path()).unwrap());
    }
}
