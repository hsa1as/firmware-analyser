use unicorn_engine::unicorn_const::uc_error;
use unicorn_engine::{RegisterARM, Unicorn};

const SCB_ICSR: u64 = 0xE000_ED04;
const SCB_VTOR: u64 = 0xE000_ED08;
const ICSR_VECTACTIVE_MASK: u32 = 0x1FF;
const ICSR_RETTOBASE: u32 = 1 << 11;
const ICSR_VECTPENDING_MASK: u32 = 0x1FF << 12;

#[derive(Debug)]
pub struct InterruptState {
    active_interrupts: Vec<u32>,
    pending_interrupts: Vec<u32>,
}

impl InterruptState {
    pub fn new() -> Self {
        Self {
            active_interrupts: Vec::new(),
            pending_interrupts: Vec::new(),
        }
    }
}

pub fn should_preempt(current_isr: u32, pending_isr: u32) -> bool {
    pending_isr > current_isr
}

pub fn handle_interrupt<T>(
    uc: &mut Unicorn<'_, T>,
    state: &mut InterruptState,
) -> Result<(), uc_error> {
    // Check if there are any pending interrupts
    if state.pending_interrupts.is_empty() {
        return Ok(());
    }

    // Read current xPSR
    let xpsr = uc.reg_read(RegisterARM::XPSR)? as u32;
    let current_isr = xpsr & ICSR_VECTACTIVE_MASK;

    // If we're not in Thread mode (current_isr != 0), check interrupt priorities
    if current_isr != 0 && !should_preempt(current_isr, state.pending_interrupts[0]) {
        return Ok(());
    }

    // Exception entry
    let interrupt_number = state.pending_interrupts.remove(0);
    state.active_interrupts.push(interrupt_number);
    let sp = uc.reg_read(RegisterARM::SP)?;
    let pc = uc.reg_read(RegisterARM::PC)?;
    let lr = uc.reg_read(RegisterARM::LR)?;
    let r12 = uc.reg_read(RegisterARM::R12)?;
    let r3 = uc.reg_read(RegisterARM::R3)?;
    let r2 = uc.reg_read(RegisterARM::R2)?;
    let r1 = uc.reg_read(RegisterARM::R1)?;
    let r0 = uc.reg_read(RegisterARM::R0)?;
    let new_sp = sp - 32;
    uc.mem_write(new_sp, &u32::to_le_bytes(r0 as u32))?;
    uc.mem_write(new_sp + 4, &u32::to_le_bytes(r1 as u32))?;
    uc.mem_write(new_sp + 8, &u32::to_le_bytes(r2 as u32))?;
    uc.mem_write(new_sp + 12, &u32::to_le_bytes(r3 as u32))?;
    uc.mem_write(new_sp + 16, &u32::to_le_bytes(r12 as u32))?;
    uc.mem_write(new_sp + 20, &u32::to_le_bytes(lr as u32))?;
    uc.mem_write(new_sp + 24, &u32::to_le_bytes(pc as u32))?;
    uc.mem_write(new_sp + 28, &u32::to_le_bytes(xpsr))?;
    uc.reg_write(RegisterARM::SP, new_sp)?;

    let new_xpsr = (xpsr & !ICSR_VECTACTIVE_MASK) | interrupt_number;
    uc.reg_write(RegisterARM::XPSR, new_xpsr as u64)?;

    // TODO: LR logic is in the arm tech reference manual, match it here
    uc.reg_write(RegisterARM::LR, 0xFFFFFFF9)?;
    let mut buf: [u8; 4] = [0, 0, 0, 0];
    uc.mem_read(SCB_VTOR, &mut buf)?;
    let vtor_value = u32::from_le_bytes(buf);

    let vector_table_entry = vtor_value + (interrupt_number * 4);
    let mut buf: [u8; 4] = [0, 0, 0, 0];
    uc.mem_read(vector_table_entry as u64, &mut buf)?;
    let isr_addr = u32::from_le_bytes(buf);
    // Go to isr
    uc.reg_write(RegisterARM::PC, isr_addr as u64)?;

    Ok(())
}

// fetch_prot hook is not required see : https://github.com/unicorn-engine/unicorn/blob/dev/docs/FAQ.md#how-to-emulate-interrupts-or-ticks-with-unicorn
// Unicorn exposes software exception ( add_intr_hook ) with number 8 for handling exc_return
// Example in unit tests
pub fn handle_exception_return<T>(
    uc: &mut Unicorn<'_, T>,
    state: &mut InterruptState,
    _exc_return: u64,
) -> Result<(), uc_error> {
    state.active_interrupts.pop();

    let sp = uc.reg_read(RegisterARM::SP)?;
    // get context
    let mut buffer = [0u8; 32];
    uc.mem_read(sp, &mut buffer)?;
    let r0 = u32::from_le_bytes(buffer[0..4].try_into().unwrap());
    let r1 = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
    let r2 = u32::from_le_bytes(buffer[8..12].try_into().unwrap());
    let r3 = u32::from_le_bytes(buffer[12..16].try_into().unwrap());
    let r12 = u32::from_le_bytes(buffer[16..20].try_into().unwrap());
    let lr = u32::from_le_bytes(buffer[20..24].try_into().unwrap());
    let pc = u32::from_le_bytes(buffer[24..28].try_into().unwrap());
    let xpsr = u32::from_le_bytes(buffer[28..32].try_into().unwrap());
    uc.reg_write(RegisterARM::R0, r0 as u64)?;
    uc.reg_write(RegisterARM::R1, r1 as u64)?;
    uc.reg_write(RegisterARM::R2, r2 as u64)?;
    uc.reg_write(RegisterARM::R3, r3 as u64)?;
    uc.reg_write(RegisterARM::R12, r12 as u64)?;
    uc.reg_write(RegisterARM::LR, lr as u64)?;
    uc.reg_write(RegisterARM::PC, pc as u64)?;
    uc.reg_write(RegisterARM::XPSR, xpsr as u64)?;

    // adjust stack pointer
    uc.reg_write(RegisterARM::SP, sp + 32)?;

    Ok(())
}
