#![allow(unused)]
pub use unicorn_engine::unicorn_const::MemType;
use unicorn_engine::{ffi::UcHook, unicorn_const::uc_error};
use unicorn_engine::{RegisterARM, UcHookId, Unicorn};

const SCB_ICSR: u64 = 0xE000_ED04;
const SCB_VTOR: u64 = 0xE000_ED08;
const ICSR_VECTACTIVE_MASK: u32 = 0x1FF;
const ICSR_RETTOBASE: u32 = 1 << 11;
const ICSR_VECTPENDING_MASK: u32 = 0x1FF << 12;

// Armv7-M NVIC has 15 32 bit registers for operations on interrupt configs. => 15th register's
// upper 16 bits are reserved. => total of 496 interrupts that are supported

const ARMV7_MAX_INTERRUPTS: usize = 496;

#[allow(non_snake_case)]
#[derive(Debug)]
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
    current_prio: i16,
    // Active interrupt count
    active_count: u64,

    // Number of priority group bits
    prio_group_bits: u8,
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
            active_count: 0,
            prio_group_bits: 0,
        }
    }

    pub fn get_prio(&self, intno: usize) -> i16 {
        return self.NVIC_ExcPrio[intno];
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

    pub fn is_pending(&self, intno: u32) -> bool {
        return self.NVIC_Pending[intno as usize];
    }

    pub fn is_active(&self, intno: u32) -> bool {
        return self.NVIC_ExcAct[intno as usize];
    }

    pub fn is_enabled(&self, intno: u32) -> bool {
        return self.NVIC_ExcEnabled[intno as usize];
    }

    pub fn which_active(&self) -> Option<(u32, i16)> {
        match self.current_irqn {
            Some(n) => Some((n, self.current_prio)),
            None => None,
        }
    }

    pub fn any_pending(&self) -> bool {
        return self.NVIC_Pending.contains(&true);
    }

    // Identify the next, highest priority exception that is pending
    pub fn get_vectpending(&self) -> u32 {
        let mut least_prio: i16 = 256;
        let mut curr_irqn: u32 = 0;
        for i in 0..ARMV7_MAX_INTERRUPTS {
            if self.NVIC_Pending[i] {
                if (self.NVIC_ExcPrio[i] < least_prio) {
                    least_prio = self.NVIC_ExcPrio[i];
                    curr_irqn = i as u32;
                }
            }
        }
        return curr_irqn;
    }

    pub fn get_num_pending(&self) -> u32 {
        return self.active_count as u32;
    }

    pub fn get_current_irqn(&self) -> Option<u32> {
        return self.current_irqn;
    }

    pub fn set_current_irqn(&mut self, irqn: Option<u32>) {
        match irqn {
            Some(irqn) => {
                self.current_irqn = Some(irqn);
            }
            None => {
                self.current_irqn = None;
            }
        }
    }

    pub fn set_current_prio(&mut self, prio: i16) {
        self.current_prio = prio;
    }

    pub fn set_prio_group_bits(&mut self, bits: u8) {
        self.prio_group_bits = bits;
    }

    pub fn set_active_count(&mut self, count: u64) {
        self.active_count = count;
    }

    pub fn get_active_count(&self) -> u64 {
        return self.active_count;
    }

    pub fn maybe_activate_interrupt<T>(&mut self, uc: &mut Unicorn<'_, T>) -> bool {
        #[cfg(feature = "debug")]
        {
            println!("maybe_activate_interrupt");
        }

        let mut irqn: u32 = 0;
        let mut prio: i16 = 256;
        let mut active_count: u64 = 0;
        let mut found: bool = false;
        for i in 0..ARMV7_MAX_INTERRUPTS {
            if self.NVIC_Pending[i] {
                if self.NVIC_ExcPrio[i] < prio {
                    prio = self.NVIC_ExcPrio[i];
                    irqn = i as u32;
                    found = true;
                }
                active_count += 1;
            }
        }
        if (found) {
            #[cfg(feature = "debug")]
            {
                println!("maybe_activate_interrupt: Activating interrupt: {}", irqn);
            }

            self.set_current_irqn(Some(irqn));
            self.set_current_prio(prio);
            self.set_active_count(active_count);
            do_exc_entry(uc, irqn);
            return true;
        }
        false
    }
}

pub fn do_exc_entry<T>(uc: &mut Unicorn<'_, T>, irq_num: u32) -> Result<(), uc_error> {
    #[cfg(feature = "debug")]
    {
        println!(
            "do_exc_entry: irq_num: {} @ addr: {}",
            irq_num,
            uc.pc_read()?
        );
    }

    // Read current xPSR
    let xpsr = uc.reg_read(RegisterARM::XPSR)? as u32;

    // Exception entry
    let sp = uc.reg_read(RegisterARM::SP)?;
    let pc = uc.reg_read(RegisterARM::PC)?;
    let lr = uc.reg_read(RegisterARM::LR)?;
    let r12 = uc.reg_read(RegisterARM::R12)?;
    let r3 = uc.reg_read(RegisterARM::R3)?;
    let r2 = uc.reg_read(RegisterARM::R2)?;
    let r1 = uc.reg_read(RegisterARM::R1)?;
    let r0 = uc.reg_read(RegisterARM::R0)?;
    let new_sp = sp - 32;
    #[cfg(feature = "debug")]
    {
        println!("do_exc_entry: sp: {:#010x}", sp);
        println!("do_exc_entry: new_sp: {:#010x}", new_sp);
        println!("do_exc_entry: r0: {:#010x}", r0);
        println!("do_exc_entry: r1: {:#010x}", r1);
        println!("do_exc_entry: r2: {:#010x}", r2);
        println!("do_exc_entry: r3: {:#010x}", r3);
        println!("do_exc_entry: r12: {:#010x}", r12);
        println!("do_exc_entry: lr: {:#010x}", lr);
        println!("do_exc_entry: pc: {:#010x}", pc);
        println!("do_exc_entry: xpsr: {:#010x}", xpsr);
    }
    uc.mem_write(new_sp, &u32::to_le_bytes(r0 as u32))?;
    uc.mem_write(new_sp + 4, &u32::to_le_bytes(r1 as u32))?;
    uc.mem_write(new_sp + 8, &u32::to_le_bytes(r2 as u32))?;
    uc.mem_write(new_sp + 12, &u32::to_le_bytes(r3 as u32))?;
    uc.mem_write(new_sp + 16, &u32::to_le_bytes(r12 as u32))?;
    uc.mem_write(new_sp + 20, &u32::to_le_bytes(lr as u32))?;
    uc.mem_write(new_sp + 24, &u32::to_le_bytes(pc as u32))?;
    uc.mem_write(new_sp + 28, &u32::to_le_bytes(xpsr))?;
    uc.reg_write(RegisterARM::SP, new_sp)?;

    let new_xpsr = (xpsr & !ICSR_VECTACTIVE_MASK) | irq_num;
    uc.reg_write(RegisterARM::XPSR, new_xpsr as u64)?;

    // TODO: LR logic is in the arm tech reference manual, match it here
    uc.reg_write(RegisterARM::LR, 0xFFFFFFF9)?;
    let mut buf: [u8; 4] = [0, 0, 0, 0];
    uc.mem_read(SCB_VTOR, &mut buf)?;
    let vtor_value = u32::from_le_bytes(buf);

    let vector_table_entry = vtor_value + (irq_num * 4);
    let mut buf: [u8; 4] = [0, 0, 0, 0];
    uc.mem_read(vector_table_entry as u64, &mut buf)?;
    let isr_addr = u32::from_le_bytes(buf);
    // Go to isr
    uc.reg_write(RegisterARM::PC, isr_addr as u64)?;

    Ok(())
}

pub fn do_exc_return<T>(uc: &mut Unicorn<'_, T>) -> Result<(), uc_error> {
    #[cfg(feature = "debug")]
    {
        println!("do_exc_return");
    }

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

    #[cfg(feature = "debug")]
    {
        println!("do_exc_return: r0: {:#010x}", r0);
        println!("do_exc_return: r1: {:#010x}", r1);
        println!("do_exc_return: r2: {:#010x}", r2);
        println!("do_exc_return: r3: {:#010x}", r3);
        println!("do_exc_return: r12: {:#010x}", r12);
        println!("do_exc_return: lr: {:#010x}", lr);
        println!("do_exc_return: pc: {:#010x}", pc);
        println!("do_exc_return: xpsr: {:#010x}", xpsr);
    }

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
