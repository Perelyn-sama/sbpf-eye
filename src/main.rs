use anyhow::{Context, Result};
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
use sbpf_eye::{BasicBlock, Function, InstructionMetadata, ProgramAnalysis, analyze_program};
use std::{env, io};

const DEFAULT_PROGRAM: &str = "samples/hello_solana_pinocchio_program.so";

fn main() -> Result<()> {
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_PROGRAM.to_string());

    let analysis =
        analyze_program(&path).with_context(|| format!("failed to analyze program at {path}"))?;

    run_tui(path, analysis)?;

    Ok(())
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

            if let Event::Key(key) = event::read()? {
                if self.handle_key(key) {
                    break;
                }
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
                Constraint::Length(9),
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
                "  size={} text={} instructions={}",
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
                .map(function_detail)
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
