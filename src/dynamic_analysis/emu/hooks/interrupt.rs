use unicorn_engine::unicorn_const::uc_error;
use unicorn_engine::{RegisterARM, Unicorn};
pub use unicorn_engine::unicorn_const::MemType;

const SCB_ICSR: u64 = 0xE000_ED04;
const SCB_VTOR: u64 = 0xE000_ED08;
const ICSR_VECTACTIVE_MASK: u32 = 0x1FF;
const ICSR_RETTOBASE: u32 = 1 << 11;
const ICSR_VECTPENDING_MASK: u32 = 0x1FF << 12;

// Armv7-M NVIC has 15 32 bit registers for operations on interrupt configs. => 15th register's
// upper 16 bits are reserved. => total of 496 interrupts that are supported

const ARMV7_MAX_INTERRUPTS: usize = 496;

#[allow(non_snake_case)]
pub struct ArmV7Nvic {
    vtor: u32,
    // ARMv7-M B3.4.6 - B3.4.7 Have registers to set/clear pend
    NVIC_Pending: Vec<bool>,
    // Each exception has an 8-bit signed priority number
    // ARmv7-M B3.4.9 has registers to set/read priority of exceptions
    NVIC_ExcPrio: Vec<i16>,
    // ARmv7-M B3.4.8 has registers to show status
    NVIC_ExcAct: Vec<bool>, // Exc active?
    // Armv7-M B3.4.4 - B3.4.5 has registers to enable/disable interrupts
    NVIC_ExcEnabled: Vec<bool>, // Exc enabled?

    // Current pending interrupt number
    current_irqn: Option<u32>,
    // Current pending interrupt's priority
    current_prio: i32,
    //
}

impl ArmV7Nvic {
    pub fn new() -> Self {
        Self {
            vtor: 0,
            NVIC_Pending: vec![false; ARMV7_MAX_INTERRUPTS],
            // I dont think all interrupts have configurable priority, but we will create a
            // vec of full size
            NVIC_ExcPrio: vec![0i16; ARMV7_MAX_INTERRUPTS],
            NVIC_ExcAct: vec![false; ARMV7_MAX_INTERRUPTS],
            NVIC_ExcEnabled: vec![true; ARMV7_MAX_INTERRUPTS],
            current_irqn: None,
            current_prio: 256, // start at highest possible PRIO : 256 for 8 bit priorities :
                               // IMPLEMENTATION_DEFINED number of priority bits
        }
    }

    pub fn exc_active(&mut self, intno: u32, act: bool) {
        self.NVIC_ExcAct[intno as usize] = act;
    }

    pub fn exc_pend(&mut self, intno: u32, pend: bool) {
        self.NVIC_Pending[intno as usize] = pend;
    }

    pub fn exc_enable(&mut self, intno: u32, en: bool) {
        self.NVIC_ExcEnabled[intno as usize] = en;
    }

    pub fn set_prio(&mut self, intno: u32, prio: i16) {
        self.NVIC_ExcPrio[intno as usize] = prio;
    }

    pub fn write_vtor(&mut self, new_vtor: u32) {
        self.vtor = new_vtor;
    }
}


// armv7_nvic modelling
// register map Armv7-M B3.4.3
#[allow(unused)]
pub fn armv7_nvic_hooks<T>(
    uc: &mut unicorn_engine::Unicorn<'_, T>,
    acc_type: MemType,
    loc: u64,
    sz: usize,
    val: i64,
    nvic: &mut crate::dynamic_analysis::emu::hooks::interrupt::ArmV7Nvic,
) -> bool
{
    if loc < 0xE000E100 && loc > 0xE000ECFC {
        println!(
            "This shouldn't have happened: armv7_nvic_hook called from acc to non-nvic address"
        );
        return false;
    }

    // If it is just a read, allow it
    if (acc_type == MemType::READ) {
        return true;
    }

    let mut new_val: u32 = val.try_into().unwrap();
    let mut old_val_buf = vec![0u8; 4];
    uc.mem_read(loc, &mut old_val_buf)
        .expect("Unable to read memory for nvic handling ");
    let mut old_val = u32::from_le_bytes(old_val_buf.try_into().unwrap());
    if loc >= 0xE000E100 && loc <= 0xE000E13C {
        // Interrupt set-enable RW
        let mut i: u64 = 0;
        while (i < 32) {
            // only writes of 1 to this register have an effect
            if (new_val & 1 == 1 && old_val & 1 == 0) {
                nvic.exc_enable((i + 8 * (loc - 0xE000E100)) as u32, true);
            }
            new_val = new_val >> 1;
            old_val = old_val >> 1;
        }
    }
    if loc >= 0xE000E180 && loc <= 0xE000E1BC {
        // Interrupt clear-enable RW
        let mut i: u64 = 0;
        while (i < 32) {
            // only writes of 1 to this register have an effect
            if (new_val & 1 == 1 && old_val & 1 == 0) {
                nvic.exc_enable((i + 8 * (loc - 0xE000E100)) as u32, false);
            }
            new_val = new_val >> 1;
            old_val = old_val >> 1;
        }
    }
    if loc >= 0xE000E200 && loc <= 0xE000E23C {
        // Interrupt set-pending RW
        let mut i: u64 = 0;
        while (i < 32) {
            // only writes of 1 to this register have an effect
            if (new_val & 1 == 1 && old_val & 1 == 0) {
                nvic.exc_pend((i + 8 * (loc - 0xE000E100)) as u32, true);
            }
            new_val = new_val >> 1;
            old_val = old_val >> 1;
        }
    }
    if loc >= 0xE000E280 && loc <= 0xE000E2BC {
        // Interrupt clear-pending RW
        let mut i: u64 = 0;
        while (i < 32) {
            // only writes of 1 to this register have an effect
            if (new_val & 1 == 1 && old_val & 1 == 0) {
                nvic.exc_pend((i + 8 * (loc - 0xE000E100)) as u32, false);
            }
            new_val = new_val >> 1;
            old_val = old_val >> 1;
        }
    }
    if loc >= 0xE000E300 && loc <= 0xE000E33C {
        // Interrupt active-bit RO
        // we should never reach here
        println!("Writing to RO NVIC registesr");
        return false;
    }
    if loc >= 0xE000E340 && loc <= 0xE000E3FC {
        // Reserved
        return false;
    }
    if loc >= 0xE000E400 && loc <= 0xE000E5EC {
        // Interrupt priority registers RW
        let n = (loc - 0xE000E400) / 4;
        let mut i: u64 = 0;
        while (i < 4) {
            if (new_val & 0xFF != old_val & 0xFF) {
                nvic.set_prio(
                    (4 * n + i).try_into().unwrap(),
                    (new_val & 0xFF).try_into().unwrap(),
                );
            }
            new_val = new_val >> 8;
            old_val = old_val >> 8;
        }
    }
    if loc >= 0xE000E5F0 && loc <= 0xE000ECFC {
        // Reserved
        return false;
    }
    true
}

pub fn handle_interrupt<T>(
    uc: &mut Unicorn<'_, T>,
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
    nvic:

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
