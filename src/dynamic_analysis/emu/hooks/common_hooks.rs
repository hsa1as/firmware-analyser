#![allow(unused)]
use std::io;

use unicorn_engine::unicorn_const::MemType;
use unicorn_engine::{Arch, RegisterARM, Unicorn};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem},
    Terminal,
};

use crate::dynamic_analysis::MAP_SIZE;
pub trait CanUpdateMap {
    unsafe fn update_map(&mut self, _: u64);
}

static mut PREV: u64 = 0;
pub fn block_hook<T: CanUpdateMap>(uc: &mut Unicorn<'_, T>, loc: u64, sz: u32) {
    unsafe {
        let mut fud = uc.get_data_mut();
        let hash = (loc ^ PREV) & (MAP_SIZE as u64 - 1);
        fud.update_map(hash);
        PREV = loc >> 1;
    }
    #[cfg(feature = "debug")]
    eprintln!("Block hook : Address = {loc:#08x}, Size = {sz}");
}

pub fn code_hook<T>(uc: &mut Unicorn<'_, T>, loc: u64, sz: u32) {
    println!("Code hook : Address = {loc:#08x}, Size = {sz}");
    println!("{loc:#10x}, {sz}, []");
}

pub fn insn_invalid_hook<T>(uc: &mut Unicorn<'_, T>) -> bool {
    debug_output(uc);
    false
}

pub fn mem_hook<T>(
    uc: &mut Unicorn<'_, T>,
    mem_type: MemType,
    address: u64,
    size: usize,
    value: i64,
) -> bool {
    match mem_type {
        MemType::WRITE_PROT => {
            debug_output(uc);
            println!("Write to non-writeable memory");
            false
        }
        MemType::FETCH_PROT => {
            debug_output(uc);
            println!("Executing non executable memory");
            false
        }
        MemType::READ_UNMAPPED => {
            debug_output(uc);
            println!("Reading unmapped memory");
            false
        }
        MemType::WRITE_UNMAPPED => {
            debug_output(uc);
            println!("Writing to unmapped memory");
            false
        }
        MemType::FETCH_UNMAPPED => {
            debug_output(uc);
            println!("Executing from unmapped memory");
            false
        }
        _ => {
            println!("This shouldn't have happened");
            true
        }
    }
}

pub fn do_interrupt<T>(uc: &mut Unicorn<'_, T>, loc: u64, val: u32) {}

fn dump_arm_registers<T>(uc: &mut Unicorn<'_, T>) {
    let registers = [
        (RegisterARM::R0, "R0"),
        (RegisterARM::R1, "R1"),
        (RegisterARM::R2, "R2"),
        (RegisterARM::R3, "R3"),
        (RegisterARM::R4, "R4"),
        (RegisterARM::R5, "R5"),
        (RegisterARM::R6, "R6"),
        (RegisterARM::R7, "R7"),
        (RegisterARM::R8, "R8"),
        (RegisterARM::R9, "R9"),
        (RegisterARM::R10, "R10"),
        (RegisterARM::R11, "R11"),
        (RegisterARM::R12, "R12"),
        (RegisterARM::SP, "SP"),
        (RegisterARM::LR, "LR"),
        (RegisterARM::PC, "PC"),
        (RegisterARM::CPSR, "CPSR"),
    ];

    println!("ARM CPU Register Dump:");
    for (reg, name) in registers.iter() {
        let value = uc.reg_read(*reg).unwrap();
        println!("{}: {:#010x}", name, value);
    }
}

pub fn debug_output<T>(uc: &mut Unicorn<'_, T>) {
    println!("===== Registers =====");
    let arch = uc.ctl_get_arch().unwrap();
    match arch {
        Arch::ARM => {
            //dump_arm_debug_info(uc);
            println!("Placeholder for ratatui");
        }
        _ => {
            unimplemented!();
        }
    }
}

fn dump_arm_debug_info<T>(uc: &mut Unicorn<'_, T>) -> Result<(), io::Error> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Main loop
    loop {
        #[allow(deprecated)]
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints(
                    [
                        Constraint::Percentage(30),
                        Constraint::Percentage(30),
                        Constraint::Percentage(40),
                    ]
                    .as_ref(),
                )
                .split(f.size());

            // Registers
            let registers = [
                RegisterARM::R0,
                RegisterARM::R1,
                RegisterARM::R2,
                RegisterARM::R3,
                RegisterARM::R4,
                RegisterARM::R5,
                RegisterARM::R6,
                RegisterARM::R7,
                RegisterARM::R8,
                RegisterARM::R9,
                RegisterARM::R10,
                RegisterARM::R11,
                RegisterARM::R12,
                RegisterARM::SP,
                RegisterARM::LR,
                RegisterARM::PC,
                RegisterARM::CPSR,
            ];
            let reg_items: Vec<ListItem> = registers
                .iter()
                .map(|&reg| {
                    let value = uc.reg_read(reg).unwrap();
                    ListItem::new(format!("{:?}: {:#010x}", reg, value))
                })
                .collect();
            let registers_list = List::new(reg_items)
                .block(Block::default().title("Registers").borders(Borders::ALL));
            f.render_widget(registers_list, chunks[0]);

            // Stack
            let sp = uc.reg_read(RegisterARM::SP).unwrap();
            let stack_bytes = uc.mem_read_as_vec(sp, 64).unwrap();
            let stack_items: Vec<ListItem> = stack_bytes
                .chunks(4)
                .enumerate()
                .map(|(i, chunk)| {
                    let value = u32::from_le_bytes(chunk.try_into().unwrap());
                    ListItem::new(format!("{:#010x}: {:#010x}", sp + (i as u64 * 4), value))
                })
                .collect();
            let stack_list =
                List::new(stack_items).block(Block::default().title("Stack").borders(Borders::ALL));
            f.render_widget(stack_list, chunks[1]);

            // Instructions
            let pc = uc.reg_read(RegisterARM::PC).unwrap();
            let instr_start = pc.saturating_sub(40);
            let instr_bytes = uc.mem_read_as_vec(instr_start, 80).unwrap();
            let instr_items: Vec<ListItem> = instr_bytes
                .chunks(4)
                .enumerate()
                .map(|(i, chunk)| {
                    let addr = instr_start + (i as u64 * 4);
                    let instr = u32::from_le_bytes(chunk.try_into().unwrap());
                    let style = if addr == pc {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    ListItem::new(format!("{:#010x}: {:#010x}", addr, instr)).style(style)
                })
                .collect();
            let instructions_list = List::new(instr_items)
                .block(Block::default().title("Instructions").borders(Borders::ALL));
            f.render_widget(instructions_list, chunks[2]);
        })?;

        if let Event::Key(key) = event::read()? {
            if let KeyCode::Char('q') = key.code {
                break;
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}
