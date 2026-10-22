use anyhow::{Context, Result, bail};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use sbpf_eye::compiler_diff::render::{self, OutputFormat, RenderOptions};
use sbpf_eye::{BasicBlock, Function, InstructionMetadata, ProgramAnalysis, analyze_program};
use std::{env, io, io::IsTerminal, path::PathBuf};

mod progress;

const DEFAULT_PROGRAM: &str = "samples/hello_solana_pinocchio_program.so";

fn main() -> Result<()> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == "compiler-diff") {
        args.remove(0);
        return run_compiler_diff(args);
    }

    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h" | "-help"))
        && args.first().is_none_or(|arg| arg != "--")
    {
        println!("{}", usage());
        return Ok(());
    }
    if args.len() == 1 && matches!(args[0].as_str(), "--version" | "-V") {
        println!("sbpf-eye {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "--") {
        args.remove(0);
    } else if let Some(option) = args.iter().find(|arg| arg.starts_with('-')) {
        bail!("unknown option `{option}`\nRun `sbpf-eye --help` for usage.");
    }
    if args.len() > 1 {
        bail!("expected one program path\nRun `sbpf-eye --help` for usage.");
    }

    let path = args
        .first()
        .cloned()
        .unwrap_or_else(|| DEFAULT_PROGRAM.to_string());

    let analysis =
        analyze_program(&path).with_context(|| format!("failed to analyze program at {path}"))?;

    run_tui(path, analysis)?;

    Ok(())
}

fn usage() -> &'static str {
    concat!(
        "sbpf-eye ",
        env!("CARGO_PKG_VERSION"),
        " — Binary Inspection & Compiler Comparisons\n\n",
        "Usage: sbpf-eye [PROGRAM.so]\n",
        "       sbpf-eye compiler-diff <PROGRAM_DIR> [OPTIONS]\n\n",
        "Inspect a compiled sBPF binary in the interactive viewer, or compare compiler output.\n",
        "Without a path, opens samples/hello_solana_pinocchio_program.so from the current directory.\n\n",
        "Options:\n  -h, --help       Show help\n  -V, --version    Show version\n",
        "\n",
        "Run `sbpf-eye compiler-diff --help` for comparison options."
    )
}

fn run_compiler_diff(args: Vec<String>) -> Result<()> {
    if args.iter().any(|arg| arg == "--init-profiles") {
        if args.len() != 1 {
            bail!("--init-profiles cannot be combined with other arguments");
        }
        let path = saved_profiles_path()?;
        let parent = path.parent().context("saved profiles path has no parent")?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create config directory `{}`", parent.display()))?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| {
                format!("cannot create `{}` (it may already exist)", path.display())
            })?;
        use std::io::Write;
        file.write_all(include_str!("../examples/compiler-profiles.toml").as_bytes())?;
        println!("Created compiler profiles at {}", path.display());
        println!("Edit this file once, then use `--saved-profiles` or select profiles by name.");
        return Ok(());
    }
    let (program_dir, options, output) = parse_compiler_diff_args(args)?;
    let presentation = RenderOptions {
        format: output,
        program: Some(program_dir.display().to_string()),
        width: if io::stdout().is_terminal() {
            crossterm::terminal::size()
                .map(|(w, _)| w as usize)
                .unwrap_or(100)
        } else {
            100
        },
        color: render::colors_enabled(
            io::stdout().is_terminal(),
            env::var_os("NO_COLOR").is_some(),
            env::var("TERM").ok().as_deref(),
        ),
        verbose: options.verbose,
        show_config: options.show_config,
        show_build_log: options.show_build_log,
        show_target_spec: options.show_target_spec,
    };
    if let Some(path) = &options.profiles_path {
        use sbpf_eye::compiler_diff::profiles::{ProfileConfig, compare_profiles};
        let contents = std::fs::read_to_string(path).with_context(|| {
            format!(
                "cannot read profiles file `{}`; for the saved user config, create it with `sbpf-eye compiler-diff --init-profiles`",
                path.display()
            )
        })?;
        let config = ProfileConfig::parse(&contents)?.select(&options.selected_profiles)?;
        let progress = progress::Progress::start(output);
        let report = compare_profiles(
            &program_dir,
            config,
            options.baseline_profile.as_deref(),
            options.keep_builds,
        )?;
        drop(progress);
        println!("{}", render::render(&report, &presentation));
        return Ok(());
    }
    let keep_builds = options.keep_builds;
    let progress = progress::Progress::start(output);
    let report = sbpf_eye::compiler_diff::compile_and_compare(&program_dir, options.build)
        .with_context(|| format!("failed to run compiler diff for {}", program_dir.display()))?;
    drop(progress);
    let rendered = render::render_legacy(&report, keep_builds, &presentation);
    println!("{rendered}");
    if !keep_builds {
        report.cleanup_builds();
    }
    Ok(())
}

#[derive(Default)]
struct CompilerDiffCli {
    build: sbpf_eye::compiler_diff::CompilerDiffOptions,
    profiles_path: Option<PathBuf>,
    selected_profiles: Vec<String>,
    baseline_profile: Option<String>,
    verbose: bool,
    show_config: bool,
    show_build_log: bool,
    show_target_spec: bool,
}
impl std::ops::Deref for CompilerDiffCli {
    type Target = sbpf_eye::compiler_diff::CompilerDiffOptions;
    fn deref(&self) -> &Self::Target {
        &self.build
    }
}
impl std::ops::DerefMut for CompilerDiffCli {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.build
    }
}

fn parse_compiler_diff_args(args: Vec<String>) -> Result<(PathBuf, CompilerDiffCli, OutputFormat)> {
    let mut program_dir = None;
    let mut options = CompilerDiffCli::default();
    let mut output = OutputFormat::Terminal;
    let mut use_saved_profiles = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--saved-profiles" => use_saved_profiles = true,
            "--profiles" => {
                i += 1;
                let value = args
                    .get(i)
                    .filter(|v| !v.is_empty() && !v.starts_with('-'))
                    .context("--profiles requires a file path; use --saved-profiles for the saved user config")?;
                options.profiles_path = Some(value.into());
            }
            "--select" | "--baseline" => {
                let flag = args[i].as_str();
                i += 1;
                let value = args
                    .get(i)
                    .filter(|v| !v.is_empty() && !v.starts_with('-'))
                    .with_context(|| format!("{flag} requires a value"))?;
                match flag {
                    "--select" => {
                        options.selected_profiles = value.split(',').map(str::to_owned).collect()
                    }
                    _ => options.baseline_profile = Some(value.clone()),
                }
            }
            "--versions" => {
                i += 1;
                let Some(value) = args.get(i) else {
                    bail!("--versions requires a comma-separated value like v0,v1,v2,v3");
                };
                options.requested_versions = sbpf_eye::compiler_diff::parse_versions(value)?;
            }
            "--release" => {
                options.release = true;
            }
            "--keep-builds" => {
                options.keep_builds = true;
            }
            "--verbose" => options.verbose = true,
            "--show-config" => options.show_config = true,
            "--show-build-log" => options.show_build_log = true,
            "--show-target-spec" => options.show_target_spec = true,
            "--format" => {
                i += 1;
                output = match args.get(i).map(String::as_str) {
                    Some("terminal") => OutputFormat::Terminal,
                    Some("json") => OutputFormat::Json,
                    Some("markdown") => OutputFormat::Markdown,
                    _ => bail!("--format requires terminal, json, or markdown"),
                };
            }
            "--json" => output = OutputFormat::Json,
            "--help" | "-h" => {
                print_compiler_diff_help();
                std::process::exit(0);
            }
            value if value.starts_with('-') => bail!("unknown compiler-diff option `{value}`"),
            value => {
                if program_dir.replace(PathBuf::from(value)).is_some() {
                    bail!("compiler-diff accepts exactly one PROGRAM_DIR");
                }
            }
        }
        i += 1;
    }

    let Some(program_dir) = program_dir else {
        bail!("missing PROGRAM_DIR\n\n{}", compiler_diff_usage());
    };

    if use_saved_profiles && options.profiles_path.is_some() {
        bail!("--saved-profiles cannot be combined with --profiles FILE");
    }
    let profile_mode = use_saved_profiles
        || options.profiles_path.is_some()
        || !options.selected_profiles.is_empty()
        || options.baseline_profile.is_some();
    if profile_mode && (!options.requested_versions.is_empty() || options.release) {
        bail!(
            "profile comparisons cannot be combined with --versions or --release; configure release in the profiles file"
        );
    }
    if profile_mode && options.profiles_path.is_none() {
        options.profiles_path = Some(saved_profiles_path()?);
    }
    Ok((program_dir, options, output))
}

fn print_compiler_diff_help() {
    println!("{}", compiler_diff_usage());
}

fn compiler_diff_usage() -> &'static str {
    r#"Compare the binaries produced by different sBPF architectures or compilers.

Usage: sbpf-eye compiler-diff <PROGRAM_DIR> [OPTIONS]
       sbpf-eye compiler-diff --init-profiles

Arguments:
  <PROGRAM_DIR>              Program directory containing Cargo.toml.
                             Workspace members are supported.

Compare architectures (default):
  With no options, compare supported Anza v0–v3 architectures.
  --versions LIST            Compare selected versions, e.g. v0,v2,v3.
                             Experimental v4 must be selected explicitly.
  --release                  Compatibility flag; Anza builds are already optimized.

Compare compiler profiles:
  --init-profiles            Create a saved starter config and print its path.
                             Run alone, then edit it for your installed tools.
  --saved-profiles           Compare all profiles in your saved config.
  --profiles FILE            Load profiles from a TOML file instead.
  --select NAME,...          Compare only these profiles.
  --baseline NAME            Measure changes against this profile.
                             Default: first selected profile in file order.

  --select and --baseline use the saved config unless --profiles is given.
  Profile mode cannot be combined with --versions or --release.

Output:
  --format FORMAT            terminal (default), json, or markdown.
  --json                     Alias for --format json; includes all metadata.
  --verbose                  Show environment, opcode, and function details.
  --show-config              Show profile configuration and build commands.
  --show-build-log           Show captured compiler stdout and stderr.
  --show-target-spec         Show resolved compiler target specifications.
  --keep-builds              Preserve temporary build files for inspection.
  -h, --help                 Show this help.

Examples:
  # Compare architectures using Anza
  sbpf-eye compiler-diff ./program
  sbpf-eye compiler-diff ./program --versions v0,v3

  # Set up saved profiles once, then compare compilers
  sbpf-eye compiler-diff --init-profiles
  sbpf-eye compiler-diff ./program --select anza-v3,blueshift-v3 --baseline anza-v3

  # Export a report or investigate a failed build
  sbpf-eye compiler-diff ./program --format markdown > comparison.md
  sbpf-eye compiler-diff ./program --show-build-log

Builds run offline. Install toolchains and fetch dependencies before comparing.
Instruction counts are static measurements, not measured compute units."#
}

fn saved_profiles_path() -> Result<PathBuf> {
    if let Some(path) = env::var_os("SBPF_EYE_CONFIG_DIR") {
        return Ok(PathBuf::from(path).join("compiler-profiles.toml"));
    }
    #[cfg(target_os = "windows")]
    let config_root = env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let config_root = env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join("Library/Application Support"));
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    let config_root = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")));
    let root =
        config_root.context("cannot locate user config directory; set SBPF_EYE_CONFIG_DIR")?;
    Ok(root.join("sbpf-eye").join("compiler-profiles.toml"))
}

fn run_tui(path: String, analysis: ProgramAnalysis) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(path, analysis);
    let result = app.run(&mut terminal);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

#[derive(Debug, Clone, Copy)]
enum ActivePane {
    Functions,
    Blocks,
    Instructions,
}

struct App {
    path: String,
    analysis: ProgramAnalysis,
    active_pane: ActivePane,
    function_state: ListState,
    block_state: ListState,
    instruction_state: ListState,
}

impl App {
    fn new(path: String, analysis: ProgramAnalysis) -> Self {
        let mut function_state = ListState::default();
        function_state.select((!analysis.functions().is_empty()).then_some(0));

        let mut block_state = ListState::default();
        block_state.select(
            analysis
                .functions()
                .first()
                .is_some_and(|func| !func.blocks().is_empty())
                .then_some(0),
        );

        let mut instruction_state = ListState::default();
        instruction_state.select(Some(0));

        Self {
            path,
            analysis,
            active_pane: ActivePane::Functions,
            function_state,
            block_state,
            instruction_state,
        }
    }

    fn run(&mut self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
        loop {
            terminal.draw(|frame| self.render(frame))?;

            if let Event::Key(key) = event::read()?
                && self.handle_key(key)
            {
                break;
            }
        }

        Ok(())
    }

    fn render(&mut self, frame: &mut ratatui::Frame) {
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(10),
            ])
            .split(frame.area());

        let info = self.info_line();
        frame.render_widget(
            Paragraph::new(info).block(Block::default().borders(Borders::ALL).title("Program")),
            outer[0],
        );

        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(28),
                Constraint::Percentage(27),
                Constraint::Percentage(45),
            ])
            .split(outer[1]);

        let function_items = self.function_items();
        let mut function_state = self.function_state.clone();
        frame.render_stateful_widget(
            self.list("Functions", ActivePane::Functions, function_items),
            columns[0],
            &mut function_state,
        );
        self.function_state = function_state;

        let block_items = self.block_items();
        let mut block_state = self.block_state.clone();
        frame.render_stateful_widget(
            self.list("Blocks", ActivePane::Blocks, block_items),
            columns[1],
            &mut block_state,
        );
        self.block_state = block_state;

        let instruction_items = self.instruction_items();
        let mut instruction_state = self.instruction_state.clone();
        frame.render_stateful_widget(
            self.list("Instructions", ActivePane::Instructions, instruction_items),
            columns[2],
            &mut instruction_state,
        );
        self.instruction_state = instruction_state;

        let detail = Paragraph::new(self.selected_detail_text())
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(self.selected_detail_title()),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(detail, outer[2]);
    }

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Tab => self.next_pane(),
            KeyCode::BackTab => self.previous_pane(),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
            _ => {}
        }

        false
    }

    fn next_pane(&mut self) {
        self.active_pane = match self.active_pane {
            ActivePane::Functions => ActivePane::Blocks,
            ActivePane::Blocks => ActivePane::Instructions,
            ActivePane::Instructions => ActivePane::Functions,
        };
    }

    fn previous_pane(&mut self) {
        self.active_pane = match self.active_pane {
            ActivePane::Functions => ActivePane::Instructions,
            ActivePane::Blocks => ActivePane::Functions,
            ActivePane::Instructions => ActivePane::Blocks,
        };
    }

    fn move_selection(&mut self, delta: isize) {
        match self.active_pane {
            ActivePane::Functions => {
                move_list_selection(
                    &mut self.function_state,
                    self.analysis.functions().len(),
                    delta,
                );
                self.block_state
                    .select((!self.selected_function_blocks().is_empty()).then_some(0));
                self.instruction_state
                    .select((!self.selected_block_instructions().is_empty()).then_some(0));
            }
            ActivePane::Blocks => {
                let block_count = self.selected_function_blocks().len();
                move_list_selection(&mut self.block_state, block_count, delta);
                self.instruction_state
                    .select((!self.selected_block_instructions().is_empty()).then_some(0));
            }
            ActivePane::Instructions => {
                let instruction_count = self.selected_block_instructions().len();
                move_list_selection(&mut self.instruction_state, instruction_count, delta);
            }
        }
    }

    fn info_line(&self) -> Line<'static> {
        let info = self.analysis.binary_info();
        Line::from(vec![
            Span::styled(self.path.clone(), Style::default().fg(Color::Cyan)),
            Span::raw(format!(
                "  sBPF=v{} size={} text={} instructions={}",
                info.sbpf_version(),
                info.size(),
                info.text_section_size(),
                info.ix_count()
            )),
        ])
    }

    fn list<'a>(&self, title: &'a str, pane: ActivePane, items: Vec<ListItem<'a>>) -> List<'a> {
        let style = if std::mem::discriminant(&self.active_pane) == std::mem::discriminant(&pane) {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };

        List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Span::styled(title, style)),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ")
    }

    fn function_items(&self) -> Vec<ListItem<'static>> {
        self.analysis
            .functions()
            .iter()
            .map(|func| ListItem::new(function_line(func)))
            .collect()
    }

    fn block_items(&self) -> Vec<ListItem<'static>> {
        self.selected_function_blocks()
            .into_iter()
            .filter_map(|block_id| self.analysis.blocks().get(block_id))
            .map(|block| ListItem::new(block_line(block)))
            .collect()
    }

    fn instruction_items(&self) -> Vec<ListItem<'static>> {
        self.selected_block_instructions()
            .into_iter()
            .map(|ix| ListItem::new(instruction_line(ix)))
            .collect()
    }

    fn selected_function(&self) -> Option<&Function> {
        self.function_state
            .selected()
            .and_then(|idx| self.analysis.functions().get(idx))
    }

    fn selected_function_blocks(&self) -> Vec<usize> {
        self.selected_function()
            .map(|func| func.blocks().to_vec())
            .unwrap_or_default()
    }

    fn selected_block(&self) -> Option<&BasicBlock> {
        let blocks = self.selected_function_blocks();
        self.block_state
            .selected()
            .and_then(|idx| blocks.get(idx))
            .and_then(|block_id| self.analysis.blocks().get(*block_id))
    }

    fn selected_block_instructions(&self) -> Vec<&InstructionMetadata> {
        self.selected_block()
            .map(|block| {
                self.analysis
                    .instructions()
                    .iter()
                    .filter(|ix| ix.pc() >= block.start_pc() && ix.pc() < block.end_pc_exclusive())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn selected_instruction(&self) -> Option<&InstructionMetadata> {
        let instructions = self.selected_block_instructions();
        self.instruction_state
            .selected()
            .and_then(|idx| instructions.get(idx).copied())
    }

    fn selected_detail_title(&self) -> &'static str {
        match self.active_pane {
            ActivePane::Functions => "Function Details",
            ActivePane::Blocks => "Block Details",
            ActivePane::Instructions => "Instruction Details",
        }
    }

    fn selected_detail_text(&self) -> String {
        match self.active_pane {
            ActivePane::Functions => self
                .selected_function()
                .map(|func| {
                    let stack = match sbpf_eye::cumulative_stack_usage(
                        self.analysis.functions(),
                        func.id(),
                    ) {
                        Ok(bytes) => format!("{bytes} bytes"),
                        Err(error) => format!("unavailable: {error}"),
                    };
                    format!(
                        "{}\ncumulative_stack_usage (estimate): {stack}",
                        function_detail(func)
                    )
                })
                .unwrap_or_else(|| "No function selected".to_string()),
            ActivePane::Blocks => self
                .selected_block()
                .map(block_detail)
                .unwrap_or_else(|| "No block selected".to_string()),
            ActivePane::Instructions => self
                .selected_instruction()
                .map(instruction_detail)
                .unwrap_or_else(|| "No instruction selected".to_string()),
        }
    }
}

fn move_list_selection(state: &mut ListState, len: usize, delta: isize) {
    if len == 0 {
        state.select(None);
        return;
    }

    let selected = state.selected().unwrap_or(0) as isize;
    let max = len.saturating_sub(1) as isize;
    let next = (selected + delta).clamp(0, max) as usize;
    state.select(Some(next));
}

fn function_line(func: &Function) -> Line<'static> {
    Line::from(format!(
        "#{:<3} pc={:<5} blocks={:<3} stack={:<4} live={} calls={:?}",
        func.id(),
        func.entry_pc(),
        func.blocks().len(),
        func.local_stack_usage(),
        func.reachable_from_program_entry(),
        func.callees()
    ))
}

fn block_line(block: &BasicBlock) -> Line<'static> {
    Line::from(format!(
        "#{:<3} {}..{} succ={:?} pred={:?}",
        block.id(),
        block.start_pc(),
        block.end_pc_exclusive(),
        block.successors(),
        block.predecessors()
    ))
}

fn instruction_line(ix: &InstructionMetadata) -> Line<'static> {
    Line::from(format!(
        "{:<5} {:?} imm={:?}",
        ix.pc(),
        ix.instruction().opcode,
        ix.instruction().imm
    ))
}

fn function_detail(func: &Function) -> String {
    format!(
        "id: {}\nentry_pc: {}\nentry_block: {}\nlocal_stack_usage: {}\nreachable_from_program_entry: {}\nblocks: {:?}\ncallees: {:?}",
        func.id(),
        func.entry_pc(),
        func.entry_block(),
        func.local_stack_usage(),
        func.reachable_from_program_entry(),
        func.blocks(),
        func.callees()
    )
}

fn block_detail(block: &BasicBlock) -> String {
    format!(
        "id: {}\npc_range: {}..{}\nterminator: {:?}\nsuccessors: {:?}\npredecessors: {:?}",
        block.id(),
        block.start_pc(),
        block.end_pc_exclusive(),
        block.terminator(),
        block.successors(),
        block.predecessors()
    )
}

fn instruction_detail(ix: &InstructionMetadata) -> String {
    format!(
        "pc: {}\nlen: {}\nopcode: {:?}\ndst: {:?}\nsrc: {:?}\noff: {:?}\nimm: {:?}\ninstruction: {:#?}",
        ix.pc(),
        ix.len(),
        ix.instruction().opcode,
        ix.instruction().dst,
        ix.instruction().src,
        ix.instruction().off,
        ix.instruction().imm,
        ix.instruction()
    )
}

#[cfg(test)]
mod compiler_profile_cli_tests {
    use super::*;
    fn parse(args: &[&str]) -> Result<(PathBuf, CompilerDiffCli, OutputFormat)> {
        parse_compiler_diff_args(args.iter().map(|s| s.to_string()).collect())
    }
    #[test]
    fn legacy_versions_and_flags_remain_available() {
        let (_, options, output) = parse(&[
            "program",
            "--versions",
            "v0,v2,v3",
            "--keep-builds",
            "--verbose",
        ])
        .unwrap();
        assert_eq!(options.requested_versions.len(), 3);
        assert!(options.keep_builds);
        assert!(options.profiles_path.is_none());
        assert!(matches!(output, OutputFormat::Terminal));
        assert!(options.verbose);
    }
    #[test]
    fn named_profiles_selection_and_baseline() {
        let (_, o, out) = parse(&[
            "program",
            "--profiles",
            "profiles.toml",
            "--select",
            "a,b",
            "--baseline",
            "b",
            "--json",
        ])
        .unwrap();
        assert_eq!(o.selected_profiles, vec!["a", "b"]);
        assert_eq!(o.baseline_profile.as_deref(), Some("b"));
        assert!(matches!(out, OutputFormat::Json));
    }
    #[test]
    fn formats_and_detail_flags_are_independent() {
        for args in [
            vec!["program", "--json", "--verbose"],
            vec!["program", "--verbose", "--format", "json"],
        ] {
            let (_, o, f) = parse(&args).unwrap();
            assert_eq!(f, OutputFormat::Json);
            assert!(o.verbose);
        }
        let (_, o, f) = parse(&[
            "program",
            "--format",
            "markdown",
            "--show-config",
            "--show-build-log",
            "--show-target-spec",
        ])
        .unwrap();
        assert_eq!(f, OutputFormat::Markdown);
        assert!(o.show_config && o.show_build_log && o.show_target_spec);
        assert!(parse(&["program", "--format"]).is_err());
        assert!(parse(&["program", "--format", "csv"]).is_err());
    }
    #[test]
    fn saved_profile_selection_is_order_independent() {
        let expected = saved_profiles_path().unwrap();
        for flags in [
            vec!["--saved-profiles"],
            vec!["--select", "anza-v3,blueshift-v3"],
            vec!["--baseline", "anza-v3"],
        ] {
            for first in [true, false] {
                let mut args = flags.clone();
                if first {
                    args.insert(0, "program");
                } else {
                    args.push("program");
                }
                let (program, options, _) = parse(&args).unwrap();
                assert_eq!(program, PathBuf::from("program"));
                assert_eq!(options.profiles_path.as_ref(), Some(&expected));
            }
        }
        assert!(parse(&["program", "--profiles"]).is_err());
        assert!(parse(&["program", "--profiles", "--saved-profiles"]).is_err());
        let (_, options, _) = parse(&["--profiles", "custom.toml", "program"]).unwrap();
        assert_eq!(options.profiles_path, Some(PathBuf::from("custom.toml")));
    }

    #[test]
    fn all_profile_sources_reject_legacy_flags_in_either_order() {
        for profiles in [
            vec!["--saved-profiles"],
            vec!["--profiles", "custom.toml"],
            vec!["--select", "anza-v3"],
            vec!["--baseline", "anza-v3"],
        ] {
            for legacy in [vec!["--versions", "v0"], vec!["--release"]] {
                for reverse in [false, true] {
                    let mut args = vec!["program"];
                    let (first, second) = if reverse {
                        (&legacy, &profiles)
                    } else {
                        (&profiles, &legacy)
                    };
                    args.extend(first);
                    args.extend(second);
                    let error = parse(&args).err().expect("must reject conflicting flags");
                    assert!(error.to_string().contains("cannot be combined"));
                }
            }
        }
        for args in [
            vec!["program", "--saved-profiles", "--profiles", "custom.toml"],
            vec!["program", "--profiles", "custom.toml", "--saved-profiles"],
        ] {
            assert!(
                parse(&args)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("cannot be combined")
            );
        }
    }

    #[test]
    fn invalid_cli_combinations_fail() {
        for args in [
            vec!["program", "--profiles", "p", "--versions", "v0"],
            vec!["program", "--versions", "v99"],
        ] {
            assert!(parse(&args).is_err());
        }
    }
}
