//! Pure presentation of compiler comparisons. No tool probes, builds, or analysis.
use super::profiles::{MetricDelta, ProfileReport, ProfileResult, ProfileStatus};
use super::{BinaryAnalysisSummary, StackModelSummary};
use std::fmt::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Terminal,
    Json,
    Markdown,
}
#[derive(Debug, Clone)]
pub struct RenderOptions {
    pub format: OutputFormat,
    pub program: Option<String>,
    pub width: usize,
    pub color: bool,
    pub verbose: bool,
    pub show_config: bool,
    pub show_build_log: bool,
    pub show_target_spec: bool,
}
impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            format: OutputFormat::Terminal,
            program: None,
            width: 100,
            color: false,
            verbose: false,
            show_config: false,
            show_build_log: false,
            show_target_spec: false,
        }
    }
}
/// Inputs are supplied by the CLI so tests need not mutate global environment.
pub fn colors_enabled(is_tty: bool, no_color: bool, term: Option<&str>) -> bool {
    is_tty && !no_color && term.is_some_and(|t| !t.is_empty() && t != "dumb")
}
#[derive(Clone, Copy, Default)]
enum Tone {
    #[default]
    Plain,
    Good,
    Bad,
    Warning,
    Dim,
    Heading,
}
#[derive(Clone)]
struct Cell {
    text: String,
    tone: Tone,
}
impl From<String> for Cell {
    fn from(text: String) -> Self {
        Self {
            text,
            tone: Tone::Plain,
        }
    }
}
fn cell(text: impl Into<String>) -> Cell {
    text.into().into()
}
fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}
fn integer(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}
fn signed(n: i128) -> String {
    format!(
        "{}{}",
        if n < 0 { "-" } else { "+" },
        integer(n.unsigned_abs() as usize)
    )
}
fn delta(d: Option<&MetricDelta>, preferred_lower: bool) -> Cell {
    let Some(d) = d else { return cell("n/a") };
    let text = if d.delta == 0 {
        "unchanged".into()
    } else if let Some(p) = d.percent {
        format!("{} ({p:+.2}%)", signed(d.delta))
    } else {
        format!("{} (from zero)", signed(d.delta))
    };
    let tone = if preferred_lower && d.delta < 0 {
        Tone::Good
    } else if preferred_lower && d.delta > 0 {
        Tone::Bad
    } else {
        Tone::Plain
    };
    Cell { text, tone }
}
fn optional(v: Option<usize>, bytes: bool) -> String {
    v.map_or("unknown".into(), |v| {
        format!("{}{}", integer(v), if bytes { " B" } else { "" })
    })
}
fn status(p: &ProfileResult) -> &'static str {
    match p.status {
        ProfileStatus::Analyzed => "analyzed",
        ProfileStatus::Built => "built",
        ProfileStatus::Unsupported => "unsupported",
        ProfileStatus::BuildFailed => "build failed",
        ProfileStatus::AnalysisFailed => "analysis failed",
    }
}
fn analysis(p: &ProfileResult) -> Option<&BinaryAnalysisSummary> {
    (p.status == ProfileStatus::Analyzed)
        .then_some(p.analysis.as_ref())
        .flatten()
}
fn metric(p: &ProfileResult, key: &str) -> Option<usize> {
    let a = analysis(p)?;
    Some(match key {
        "elf_bytes" => a.file_size,
        "text_bytes" => a.text_section_size,
        "rodata_bytes" => a.elf_sizes.read_only_data,
        "data_bytes" => a.elf_sizes.writable_data,
        "instructions" => a.instruction_count,
        "functions" => a.function_count,
        "blocks" => a.basic_block_count,
        "cfg_edges" => a.cfg_edge_count,
        "reachable_blocks" => a.reachable_block_count,
        "unreachable_blocks" => a.unreachable_block_count,
        "reachable_instructions" => a.reachable_instruction_count,
        "unreachable_instructions" => a.unreachable_instruction_count,
        "local_stack_bytes" => return a.stack.estimated_local_usage,
        "build_duration_ms" => return p.build.as_ref().map(|b| b.duration_ms as usize),
        _ => return None,
    })
}
struct Writer<'a> {
    out: String,
    options: &'a RenderOptions,
}
impl Writer<'_> {
    fn markdown(&self) -> bool {
        self.options.format == OutputFormat::Markdown
    }
    fn paint(&self, c: &Cell) -> String {
        let text = clean(&c.text);
        if !self.options.color || self.markdown() {
            return text;
        }
        let code = match c.tone {
            Tone::Plain => return text,
            Tone::Good => "32",
            Tone::Bad => "31",
            Tone::Warning => "33",
            Tone::Dim => "2",
            Tone::Heading => "1",
        };
        format!("\x1b[{code}m{text}\x1b[0m")
    }
    fn line(&mut self, text: &str, tone: Tone) {
        if self.markdown() {
            writeln!(self.out, "{}\n", escape(text)).unwrap();
            return;
        }
        let width = self.options.width.max(1);
        // Wrap even long paths/names rather than truncating essential values.
        let text = clean(text);
        let mut rest = text.as_str();
        while !rest.is_empty() {
            let limit = rest
                .char_indices()
                .nth(width)
                .map_or(rest.len(), |(i, _)| i);
            let split = if limit < rest.len() {
                rest[..limit].rfind(' ').filter(|i| *i > 0).unwrap_or(limit)
            } else {
                limit
            };
            let text = rest[..split].to_string();
            writeln!(self.out, "{}", self.paint(&Cell { text, tone })).unwrap();
            rest = rest[split..].trim_start();
        }
    }
    fn heading(&mut self, title: &str) {
        if !self.out.is_empty() {
            self.out.push('\n');
        }
        if self.markdown() {
            writeln!(self.out, "## {}\n", escape(title)).unwrap();
        } else {
            self.line(title, Tone::Heading);
            self.line(&"─".repeat(self.options.width.min(72)), Tone::Dim);
        }
    }
    fn table(&mut self, headers: Vec<String>, rows: Vec<Vec<Cell>>, numeric: bool) {
        if self.markdown() {
            writeln!(
                self.out,
                "| {} |",
                headers
                    .iter()
                    .map(|s| escape(s))
                    .collect::<Vec<_>>()
                    .join(" | ")
            )
            .unwrap();
            writeln!(
                self.out,
                "| {} |",
                (0..headers.len())
                    .map(|i| if numeric && i > 0 { "---:" } else { "---" })
                    .collect::<Vec<_>>()
                    .join(" | ")
            )
            .unwrap();
            for row in rows {
                writeln!(
                    self.out,
                    "| {} |",
                    row.iter()
                        .map(|c| escape(&c.text))
                        .collect::<Vec<_>>()
                        .join(" | ")
                )
                .unwrap();
            }
            self.out.push('\n');
            return;
        }
        let mut widths: Vec<_> = headers.iter().map(|s| clean(s).chars().count()).collect();
        for row in &rows {
            for (i, c) in row.iter().enumerate() {
                widths[i] = widths[i].max(clean(&c.text).chars().count());
            }
        }
        if widths.iter().sum::<usize>() + 2 * (widths.len() - 1) > self.options.width {
            for row in rows {
                self.line(&row[0].text, Tone::Heading);
                for (i, c) in row.iter().enumerate().skip(1) {
                    self.line(&format!("  {}: {}", headers[i], c.text), c.tone);
                }
            }
            return;
        }
        let header: Vec<_> = headers
            .into_iter()
            .map(|text| Cell {
                text,
                tone: Tone::Dim,
            })
            .collect();
        for row in std::iter::once(header).chain(rows) {
            let mut line = String::new();
            for (i, c) in row.iter().enumerate() {
                if i > 0 {
                    line.push_str("  ");
                }
                let pad = " ".repeat(widths[i] - clean(&c.text).chars().count());
                if numeric && i > 0 {
                    line.push_str(&pad);
                }
                line.push_str(&self.paint(c));
                if !(numeric && i > 0) {
                    line.push_str(&pad);
                }
            }
            writeln!(self.out, "{}", line.trim_end()).unwrap();
        }
    }
    fn block(&mut self, label: &str, text: &str) {
        self.heading(label);
        if self.markdown() {
            // Variable fence prevents logs/config from closing the block.
            let fence = "`".repeat(
                text.split(|c| c != '`')
                    .map(str::len)
                    .max()
                    .unwrap_or(0)
                    .max(2)
                    + 1,
            );
            writeln!(
                self.out,
                "{fence}text\n{}\n{fence}\n",
                text.chars()
                    .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
                    .collect::<String>()
            )
            .unwrap();
        } else {
            for line in text.lines() {
                self.line(line, Tone::Plain);
            }
        }
    }
}
fn escape(text: &str) -> String {
    clean(&text.replace('\n', " "))
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('|', "\\|")
        .replace('`', "\\`")
}

const BINARY: &[(&str, &str, bool)] = &[
    ("ELF bytes", "elf_bytes", true),
    (".text bytes", "text_bytes", true),
    (".rodata bytes", "rodata_bytes", true),
    (".data bytes", "data_bytes", true),
];
const FLOW: &[(&str, &str, bool)] = &[
    ("Instructions", "instructions", true),
    ("Functions", "functions", false),
    ("Basic blocks", "blocks", false),
    ("CFG edges", "cfg_edges", false),
    ("Reachable blocks", "reachable_blocks", false),
    ("Unreachable blocks", "unreachable_blocks", false),
    ("Reachable instr.", "reachable_instructions", false),
    ("Unreachable instr.", "unreachable_instructions", false),
];
fn metric_table(
    w: &mut Writer<'_>,
    report: &ProfileReport,
    profiles: &[&ProfileResult],
    metrics: &[(&str, &str, bool)],
) {
    let mut headers = vec!["Metric".into()];
    for p in profiles {
        headers.push(p.profile.name.clone());
        if p.profile.name != report.baseline {
            headers.push("Delta vs baseline".into());
        }
    }
    let rows = metrics
        .iter()
        .map(|(label, key, lower)| {
            let mut row = vec![cell(*label)];
            for p in profiles {
                let value = metric(p, key);
                row.push(cell(if *key == "build_duration_ms" {
                    value.map_or("unknown".into(), |v| format!("{:.2} s", v as f64 / 1000.0))
                } else {
                    optional(value, false)
                }));
                if p.profile.name != report.baseline {
                    let d = report
                        .deltas
                        .iter()
                        .find(|d| d.profile == p.profile.name)
                        .and_then(|d| d.metrics.get(*key));
                    // No recomputation: use the engine's signed delta and percentage.
                    let mut formatted = delta(d, *lower);
                    if *key == "build_duration_ms"
                        && let Some(d) = d
                        && d.delta != 0
                    {
                        let amount = format!("{:+.2} s", d.delta as f64 / 1000.0);
                        formatted.text = d.percent.map_or_else(
                            || format!("{amount} (from zero)"),
                            |p| format!("{amount} ({p:+.2}%)"),
                        );
                    }
                    row.push(formatted);
                }
            }
            row
        })
        .collect();
    w.table(headers, rows, true);
}
fn text_table(w: &mut Writer<'_>, profiles: &[&ProfileResult], rows: Vec<(&str, Vec<String>)>) {
    let headers = std::iter::once("Component".into())
        .chain(profiles.iter().map(|p| p.profile.name.clone()))
        .collect();
    w.table(
        headers,
        rows.into_iter()
            .map(|(k, v)| {
                std::iter::once(cell(k))
                    .chain(v.into_iter().map(cell))
                    .collect()
            })
            .collect(),
        false,
    );
}
fn toolchains(w: &mut Writer<'_>, profiles: &[&ProfileResult]) {
    w.heading("TOOLCHAIN DIFFERENCES");
    let field = |f: fn(&ProfileResult) -> String| profiles.iter().map(|p| f(p)).collect();
    text_table(
        w,
        profiles,
        vec![
            ("Builder", field(|p| p.profile.backend.executable().into())),
            (
                "Builder version",
                field(|p| {
                    p.resolved
                        .builder_version
                        .as_deref()
                        .and_then(|s| s.lines().next())
                        .unwrap_or("unknown")
                        .into()
                }),
            ),
            (
                "Rust",
                field(|p| p.resolved.rustc_version.clone().unwrap_or("unknown".into())),
            ),
            (
                "LLVM",
                field(|p| p.resolved.llvm_version.clone().unwrap_or("unknown".into())),
            ),
            (
                "Linker",
                field(|p| {
                    p.resolved
                        .linker_path
                        .as_ref()
                        .and_then(|p| p.file_name())
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or("unknown".into())
                }),
            ),
            (
                "Platform tools",
                field(|p| {
                    p.resolved
                        .platform_tools_version
                        .clone()
                        .unwrap_or("n/a".into())
                }),
            ),
            ("Requested arch", field(|p| p.profile.sbpf_version.arch())),
            (
                "Actual arch",
                field(|p| {
                    p.actual_architecture
                        .map_or("unknown".into(), |v| format!("v{v}"))
                }),
            ),
        ],
    );
}
fn stack(w: &mut Writer<'_>, profiles: &[&ProfileResult]) {
    w.heading("STACK ANALYSIS");
    text_table(
        w,
        profiles,
        vec![
            (
                "Frame model",
                profiles
                    .iter()
                    .map(|p| {
                        analysis(p)
                            .map_or("unknown", |a| match a.stack.model {
                                StackModelSummary::FixedFrame => "Fixed frame",
                                StackModelSummary::DynamicFrame => "Dynamic frame",
                                StackModelSummary::Unknown => "unknown",
                            })
                            .into()
                    })
                    .collect(),
            ),
            (
                "Frame capacity",
                profiles
                    .iter()
                    .map(|p| optional(analysis(p).and_then(|a| a.stack.frame_capacity), true))
                    .collect(),
            ),
            (
                "Estimated usage",
                profiles
                    .iter()
                    .map(|p| {
                        optional(
                            analysis(p).and_then(|a| a.stack.estimated_local_usage),
                            true,
                        )
                    })
                    .collect(),
            ),
        ],
    );
}
/// Renderers consume stored deltas; JSON always retains the complete original schema.
pub fn render(report: &ProfileReport, options: &RenderOptions) -> String {
    if options.format == OutputFormat::Json {
        return report.to_json().expect("serializable compiler report");
    }
    let mut w = Writer {
        out: String::new(),
        options,
    };
    w.heading("sbpf-eye  /  compiler diff");
    if let Some(p) = &options.program {
        w.line(&format!("Program      {p}"), Tone::Plain);
    }
    w.line(&format!("Baseline     {}", report.baseline), Tone::Plain);
    w.line(
        &format!(
            "Profiles     {}",
            report
                .profiles
                .iter()
                .map(|p| p.profile.name.as_str())
                .collect::<Vec<_>>()
                .join(" → ")
        ),
        Tone::Plain,
    );
    let arches: std::collections::BTreeSet<_> = report
        .profiles
        .iter()
        .map(|p| p.profile.sbpf_version.arch())
        .collect();
    w.line(
        &format!(
            "Architecture sBPF {}",
            arches.into_iter().collect::<Vec<_>>().join(", ")
        ),
        Tone::Plain,
    );
    w.heading("PROFILE STATUS");
    w.table(
        vec!["Profile".into(), "Status".into(), "Exit".into()],
        report
            .profiles
            .iter()
            .map(|p| {
                vec![
                    cell(&p.profile.name),
                    Cell {
                        text: status(p).into(),
                        tone: if p.status == ProfileStatus::Analyzed {
                            Tone::Plain
                        } else {
                            Tone::Warning
                        },
                    },
                    cell(
                        p.build.as_ref().map_or(
                            if p.status == ProfileStatus::Unsupported {
                                "not run"
                            } else {
                                "unknown"
                            }
                            .into(),
                            |b| {
                                b.exit_code
                                    .map_or("signal/unknown".into(), |v| v.to_string())
                            },
                        ),
                    ),
                ]
            })
            .collect(),
        false,
    );
    let base = report
        .profiles
        .iter()
        .find(|p| p.profile.name == report.baseline);
    let others: Vec<_> = report
        .profiles
        .iter()
        .filter(|p| p.profile.name != report.baseline)
        .collect();
    let all: Vec<_> = base.into_iter().chain(others.iter().copied()).collect();
    let estimated_width = 22
        + all
            .iter()
            .map(|p| {
                p.profile.name.len().max(14)
                    + if p.profile.name == report.baseline {
                        2
                    } else {
                        28
                    }
            })
            .sum::<usize>();
    let groups = if options.format == OutputFormat::Terminal
        && all.len() > 2
        && estimated_width > options.width
    {
        others
            .iter()
            .map(|p| {
                base.into_iter()
                    .chain(std::iter::once(*p))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    } else {
        vec![all]
    };
    for group in groups {
        if report.profiles.len() > 2
            && options.format == OutputFormat::Terminal
            && estimated_width > options.width
        {
            w.heading(&format!(
                "COMPARISON: {}",
                group
                    .iter()
                    .map(|p| p.profile.name.as_str())
                    .collect::<Vec<_>>()
                    .join(" → ")
            ));
        }
        w.heading("SUMMARY");
        metric_table(
            &mut w,
            report,
            &group,
            &[
                ("ELF bytes", "elf_bytes", true),
                ("Instructions", "instructions", true),
                ("Build time", "build_duration_ms", true),
            ],
        );
        w.heading("BINARY SIZE");
        metric_table(&mut w, report, &group, BINARY);
        w.heading("CONTROL FLOW");
        metric_table(&mut w, report, &group, FLOW);
        stack(&mut w, &group);
        toolchains(&mut w, &group);
    }
    if options.verbose {
        for d in &report.deltas {
            w.heading(&format!("OPCODE CHANGES: {} vs {}", d.profile, d.baseline));
            w.table(
                vec![
                    "Opcode".into(),
                    d.baseline.clone(),
                    d.profile.clone(),
                    "Delta".into(),
                ],
                d.detail
                    .opcode_deltas
                    .iter()
                    .map(|(name, m)| {
                        vec![
                            cell(name),
                            cell(integer(m.baseline_count)),
                            cell(integer(m.version_count)),
                            cell(signed(m.delta as i128)),
                        ]
                    })
                    .collect(),
                true,
            );
            for (label, changes) in [
                (
                    "FUNCTION INSTRUCTION CHANGES",
                    &d.detail.function_instruction_changes,
                ),
                ("FUNCTION STACK CHANGES", &d.detail.function_stack_changes),
            ] {
                if !changes.is_empty() {
                    w.heading(&format!("{label}: {} vs {}", d.profile, d.baseline));
                    w.table(
                        vec![
                            "Function".into(),
                            d.baseline.clone(),
                            d.profile.clone(),
                            "Delta".into(),
                        ],
                        changes
                            .iter()
                            .map(|m| {
                                vec![
                                    cell(m.key.to_string()),
                                    cell(integer(m.baseline_value)),
                                    cell(integer(m.version_value)),
                                    cell(signed(m.delta as i128)),
                                ]
                            })
                            .collect(),
                        true,
                    );
                }
            }
            for (label, names) in [
                ("Only in baseline", &d.detail.only_in_baseline),
                ("Only in profile", &d.detail.only_in_version),
            ] {
                if !names.is_empty() {
                    w.line(
                        &format!(
                            "{label}: {}",
                            names
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        Tone::Dim,
                    );
                }
            }
        }
    }
    w.heading("NOTES");
    if !base.is_some_and(|p| analysis(p).is_some()) {
        w.line(
            "! Baseline analysis unavailable; comparison deltas cannot be computed.",
            Tone::Warning,
        );
    }
    if report.deltas.iter().any(|d| d.multiple_variables_changed) {
        w.line("! Multiple toolchain/configuration variables differ; individual optimization effects cannot be isolated.",Tone::Warning);
    }
    w.line(
        "! Reachability is statically inferred. Instruction counts are not measured compute units.",
        Tone::Warning,
    );
    for note in &report.reproducibility {
        let short = if note.starts_with("A single source snapshot") {
            "Builds share a source snapshot and lockfile, and run offline. Build scripts and host tools are not hermetic."
        } else if note.starts_with("Blueshift's compiler-builtins") {
            "Blueshift builtins use independent dependency resolution; the application lockfile does not fully pin them."
        } else {
            note
        };
        w.line(&format!("! {short}"), Tone::Warning);
    }
    if report.artifacts_preserved {
        w.line(
            "Artifacts preserved (--verbose shows the build directory).",
            Tone::Dim,
        );
    }
    for p in &report.profiles {
        for message in p.diagnostic.iter().chain(p.resolved.diagnostics.iter()) {
            w.line(&format!("! {}: {message}", p.profile.name), Tone::Warning);
        }
        if p.status == ProfileStatus::BuildFailed
            && !options.show_build_log
            && let Some(b) = &p.build
        {
            if b.stderr.contains("failed to request permission")
                || b.stdout.contains("failed to request permission")
            {
                // Setup explanations and anyhow error chains often lack an
                // "error:" prefix. Keep their context visible without dumping
                // an entire verbose compiler log.
                for (label, output) in [("stdout", &b.stdout), ("stderr", &b.stderr)] {
                    let lines: Vec<_> = output.lines().collect();
                    if !lines.is_empty() {
                        w.line(
                            &format!("Setup failure context ({label}, last 12 lines):"),
                            Tone::Warning,
                        );
                        for line in lines.iter().skip(lines.len().saturating_sub(12)) {
                            w.line(line, Tone::Warning);
                        }
                    }
                }
            } else {
                for line in b
                    .stderr
                    .lines()
                    .filter(|l| {
                        l.trim_start().starts_with("error:")
                            || l.trim_start().starts_with("error[")
                            || l.trim_start().starts_with("Error:")
                    })
                    .take(4)
                {
                    w.line(line, Tone::Warning);
                }
            }
            w.line(
                "Use --show-build-log for captured stdout and stderr.",
                Tone::Dim,
            );
        }
        details(&mut w, report, p);
    }
    w.out
}
fn details(w: &mut Writer<'_>, report: &ProfileReport, p: &ProfileResult) {
    if w.options.verbose {
        w.heading(&format!("ENVIRONMENT: {}", p.profile.name));
        for (key, value) in [
            (
                "Build directory",
                Some(report.build_root.display().to_string()),
            ),
            (
                "Builder path",
                p.resolved
                    .builder_path
                    .as_ref()
                    .map(|p| p.display().to_string()),
            ),
            (
                "Rustc path",
                p.resolved
                    .rustc_path
                    .as_ref()
                    .map(|p| p.display().to_string()),
            ),
            ("Rust channel", p.resolved.rust_toolchain.clone()),
            ("Rust commit", p.resolved.rustc_commit.clone()),
            ("Linker version", p.resolved.linker_version.clone()),
            ("ELF SHA-256", p.elf_sha256.clone()),
            ("Source SHA-256", Some(report.source_sha256.clone())),
            ("Lock SHA-256", Some(report.cargo_lock_sha256.clone())),
        ] {
            w.line(
                &format!(
                    "{key}: {}",
                    value.filter(|s| !s.is_empty()).unwrap_or("unknown".into())
                ),
                Tone::Dim,
            );
        }
        for note in &report.reproducibility {
            w.line(note, Tone::Dim);
        }
        if let Some(b) = &p.build {
            w.table(
                vec!["Environment".into(), "Value".into()],
                b.environment
                    .iter()
                    .map(|(k, v)| vec![cell(k), cell(v)])
                    .collect(),
                false,
            );
        }
        if let Some(a) = analysis(p) {
            w.heading(&format!("Opcode distribution: {}", p.profile.name));
            w.table(
                vec!["Opcode".into(), "Count".into()],
                a.opcode_counts
                    .iter()
                    .map(|(k, v)| vec![cell(k), cell(integer(*v))])
                    .collect(),
                true,
            );
            w.heading(&format!("Functions: {}", p.profile.name));
            w.table(
                vec![
                    "Function".into(),
                    "Instructions".into(),
                    "Blocks".into(),
                    "Local stack B".into(),
                    "Cumulative B".into(),
                ],
                a.functions
                    .values()
                    .map(|f| {
                        vec![
                            cell(f.key.to_string()),
                            cell(integer(f.instruction_count)),
                            cell(integer(f.block_count)),
                            cell(optional(f.local_stack_usage, false)),
                            cell(optional(f.cumulative_stack_usage, false)),
                        ]
                    })
                    .collect(),
                true,
            );
        }
    }
    if w.options.show_config {
        w.block(
            &format!("CONFIGURATION: {}", p.profile.name),
            &toml::to_string_pretty(&p.profile).expect("serializable profile"),
        );
        if let Some(b) = &p.build {
            w.line(
                &format!("Working directory: {}", b.cwd.display()),
                Tone::Plain,
            );
            w.block("Build argv (one argument per line)", &b.argv.join("\n"));
            w.table(
                vec!["Environment".into(), "Value".into()],
                b.environment
                    .iter()
                    .map(|(k, v)| vec![cell(k), cell(v)])
                    .collect(),
                false,
            );
        }
        for (path, config) in &p.resolved.cargo_configs {
            w.block(&format!("Cargo config: {}", path.display()), config);
        }
    }
    if w.options.show_target_spec {
        w.block(
            &format!("TARGET SPECIFICATION: {}", p.profile.name),
            &p.resolved
                .target_spec
                .as_ref()
                .map_or("unknown".into(), |s| {
                    serde_json::to_string_pretty(s).unwrap()
                }),
        );
    }
    if w.options.show_build_log {
        if let Some(b) = &p.build {
            w.block(&format!("BUILD STDOUT: {}", p.profile.name), &b.stdout);
            w.block(&format!("BUILD STDERR: {}", p.profile.name), &b.stderr);
        } else {
            w.line(
                &format!("{}: no captured build log", p.profile.name),
                Tone::Dim,
            );
        }
    }
}

/// Human-readable legacy adapter; the original legacy JSON schema is untouched.
pub fn render_legacy(
    report: &super::CompilerDiffReport,
    preserved: bool,
    options: &RenderOptions,
) -> String {
    if options.format == OutputFormat::Json {
        return report.to_json().expect("serializable legacy report");
    }
    if let Some(full) = &report.profile_report {
        return render(full, options);
    }
    let mut base = options.clone();
    base.show_build_log = false;
    let mut out = render(
        &super::profiles::legacy_presentation(report, preserved),
        &base,
    );
    if options.show_build_log {
        let mut w = Writer {
            out: String::new(),
            options,
        };
        for b in &report.builds {
            w.block(&format!("BUILD STDOUT: {}", b.version), &b.stdout);
            w.block(&format!("BUILD STDERR: {}", b.version), &b.stderr);
        }
        out.push_str(&w.out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler_diff::{SbpfVersion, compare_binaries};
    fn fixture(n: usize) -> ProfileReport {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/hello_solana_pinocchio_program.so");
        let mut old = compare_binaries(
            (0..n)
                .map(|i| (SbpfVersion::new(i as u32), path.clone()))
                .collect(),
        )
        .unwrap();
        // Deliberately choose a baseline that is not the first profile.
        old.baseline = SbpfVersion::new(1);
        old.versions[0].file_size = 4208;
        old.versions[1].file_size = 9960;
        let mut r = crate::compiler_diff::profiles::legacy_presentation(&old, false);
        r.profiles[0]
            .analysis
            .as_mut()
            .unwrap()
            .stack
            .estimated_local_usage = Some(2288);
        r.profiles[1]
            .analysis
            .as_mut()
            .unwrap()
            .stack
            .estimated_local_usage = None;
        r.profiles[0].resolved.rustc_version = Some("nightly".into());
        r.profiles[0].resolved.target_spec =
            Some(serde_json::json!({"link-script":"SECRET TARGET SPEC"}));
        r.profiles[0].build = Some(crate::compiler_diff::profiles::CommandRecord {
            argv: vec!["SECRET COMMAND".into()],
            stderr: "SECRET LOG".into(),
            ..Default::default()
        });
        r
    }
    #[test]
    fn pair_has_sections_real_values_and_nonfirst_baseline() {
        let r = fixture(2);
        let out = render(&r, &RenderOptions::default());
        for s in [
            "Baseline     v1",
            "SUMMARY",
            "BINARY SIZE",
            "CONTROL FLOW",
            "STACK ANALYSIS",
            "TOOLCHAIN DIFFERENCES",
            "9,960",
            "4,208",
            "-5,752 (-57.75%)",
            "unchanged",
            "unknown",
            "2,288 B",
        ] {
            assert!(out.contains(s), "missing {s}: {out}");
        }
        for s in ["SECRET", "target_spec", "Some(", "StackAnalysis", "\x1b["] {
            assert!(!out.contains(s));
        }
    }
    #[test]
    fn delta_zero_missing_and_signs() {
        let d = |baseline, value, delta, percent| MetricDelta {
            baseline,
            value,
            delta,
            percent,
        };
        assert_eq!(delta(Some(&d(0, 0, 0, None)), true).text, "unchanged");
        assert_eq!(
            delta(Some(&d(0, 120, 120, None)), true).text,
            "+120 (from zero)"
        );
        assert_eq!(
            delta(Some(&d(120, 0, -120, Some(-100.0))), true).text,
            "-120 (-100.00%)"
        );
        assert_eq!(
            delta(Some(&d(100, 125, 25, Some(25.0))), false).text,
            "+25 (+25.00%)"
        );
        assert_eq!(delta(None, true).text, "n/a");
        assert!(matches!(
            delta(Some(&d(100, 50, -50, Some(-50.0))), false).tone,
            Tone::Plain
        ));
    }
    #[test]
    fn many_profiles_wide_and_narrow() {
        let r = fixture(4);
        let wide = render(
            &r,
            &RenderOptions {
                width: 240,
                ..Default::default()
            },
        );
        assert!(!wide.contains("COMPARISON:"));
        let narrow = render(
            &r,
            &RenderOptions {
                width: 60,
                ..Default::default()
            },
        );
        assert_eq!(narrow.matches("COMPARISON:").count(), 3);
        for name in ["v0", "v1", "v2", "v3"] {
            assert!(wide.contains(name) && narrow.contains(name));
        }
        assert!(narrow.lines().all(|l| l.chars().count() <= 60));
    }
    #[test]
    fn long_names_wrap_without_truncating_metrics() {
        let mut r = fixture(2);
        r.profiles[0].profile.name = "a".repeat(140);
        let out = render(
            &r,
            &RenderOptions {
                width: 36,
                ..Default::default()
            },
        );
        assert!(out.lines().all(|l| l.chars().count() <= 36));
        assert!(out.contains("4,208"));
    }
    #[test]
    fn failures_missing_metrics_and_failed_baseline_are_explicit() {
        let mut r = fixture(2);
        r.profiles[1].status = ProfileStatus::BuildFailed;
        r.profiles[1].analysis = None;
        r.profiles[1].diagnostic = Some("compilation stopped".into());
        r.deltas.clear();
        let out = render(&r, &RenderOptions::default());
        assert!(out.contains("build failed"));
        assert!(out.contains("compilation stopped"));
        assert!(out.contains("Baseline analysis unavailable"));
        assert!(out.contains("n/a"));
        assert!(!out.contains("9,960"));
    }
    #[test]
    fn setup_failure_keeps_stdout_and_error_chain_context() {
        let mut r = fixture(2);
        r.profiles[1].status = ProfileStatus::BuildFailed;
        let build = r.profiles[1].build.get_or_insert_with(Default::default);
        build.stdout = "Required dependency is missing from the manifest\n".into();
        build.stderr =
            "Error: failed to request permission\n\nCaused by:\n    not a terminal\n".into();
        let out = render(&r, &RenderOptions::default());
        assert!(out.contains("Required dependency is missing from the manifest"));
        assert!(out.contains("not a terminal"));
        assert!(out.contains("--show-build-log"));
    }
    #[test]
    fn json_preserves_metadata_and_is_unaffected_by_presentation_flags() {
        let r = fixture(2);
        let out = render(
            &r,
            &RenderOptions {
                format: OutputFormat::Json,
                color: true,
                verbose: true,
                show_build_log: true,
                ..Default::default()
            },
        );
        assert_eq!(out, r.to_json().unwrap());
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v["profiles"][1]["resolved"]["rustc_commit"].is_null());
        assert!(!out.contains('\x1b'));
    }
    #[test]
    fn markdown_tables_include_all_profiles_and_escape_diagnostics() {
        let mut r = fixture(3);
        r.profiles[0].diagnostic = Some("bad | <input>".into());
        let out = render(
            &r,
            &RenderOptions {
                format: OutputFormat::Markdown,
                color: true,
                ..Default::default()
            },
        );
        assert!(out.contains("## SUMMARY"));
        assert!(out.contains("| Metric | v1 | v0 | Delta vs baseline | v2 |"));
        assert!(out.contains("bad \\| &lt;input&gt;"));
        assert!(!out.contains('\x1b'));
    }
    #[test]
    fn selective_details_are_independent() {
        let r = fixture(2);
        for (options, expected, absent) in [
            (
                RenderOptions {
                    show_config: true,
                    ..Default::default()
                },
                "SECRET COMMAND",
                "SECRET TARGET SPEC",
            ),
            (
                RenderOptions {
                    show_target_spec: true,
                    ..Default::default()
                },
                "SECRET TARGET SPEC",
                "SECRET LOG",
            ),
            (
                RenderOptions {
                    show_build_log: true,
                    ..Default::default()
                },
                "SECRET LOG",
                "SECRET COMMAND",
            ),
        ] {
            let out = render(&r, &options);
            assert!(out.contains(expected));
            assert!(!out.contains(absent));
        }
    }
    #[test]
    fn tty_no_color_and_capability_policy() {
        assert!(colors_enabled(true, false, Some("xterm-256color")));
        assert!(!colors_enabled(true, true, Some("xterm")));
        assert!(!colors_enabled(false, false, Some("xterm")));
        assert!(!colors_enabled(true, false, Some("dumb")));
        assert!(!colors_enabled(true, false, None));
        let r = fixture(2);
        assert!(!render(&r, &RenderOptions::default()).contains('\x1b'));
        let colored = render(
            &r,
            &RenderOptions {
                color: true,
                ..Default::default()
            },
        );
        assert!(colored.contains("\x1b[32m-5,752"));
    }
}
