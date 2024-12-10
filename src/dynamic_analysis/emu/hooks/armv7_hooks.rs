use crate::dynamic_analysis::InputIterator;
use std::cmp::max;
pub use unicorn_engine::unicorn_const::MemType;
use unicorn_engine::RegisterARM;

pub enum ExcNum {
    RESET = 0x1,
    NMI = 0x2,
    HardFault = 0x3,
    MemManage = 0x4,
    BusFault = 0x5,
    UsageFault = 0x6,
    Reserved_7_10 = 0x7, // Reserved (7-10)
    SVCall = 0xB,
    DebugMonitor = 0xC,
    Reserved_13 = 0xD, // Reserved (13)
    PendSV = 0xE,
    SysTick = 0xF,
}

#[allow(non_snake_case, unused_variables)]
pub fn ARM_CORTEX_M3_PERIPHERAL_HOOK<T>(
    uc: &mut unicorn_engine::Unicorn<'_, T>,
    acc_type: MemType,
    loc: u64,
    sz: usize,
    val: i64,
) -> bool
where
    T: InputIterator,
{
    if acc_type == MemType::READ {
        let data = uc.get_data_mut();
        let word = data.get_next_word();
        uc.mem_write(loc, &word)
            .expect("Couldn't write AFL input to memory");
        //println!("Hit peripheral hook with address = {loc} and size = {sz}");
        let word_as_u32 = u32::from_le_bytes(word);
        //println!("Writing word = {word_as_u32}");
    }
    true
}

// armv7_nvic modelling
// register map Armv7-M B3.4.3
#[allow(unused)]
pub fn nvic_hook<T>(
    uc: &mut unicorn_engine::Unicorn<'_, T>,
    acc_type: MemType,
    loc: u64,
    sz: usize,
    val: i64,
    nvic: &mut crate::dynamic_analysis::emu::hooks::interrupt::ArmV7Nvic,
) -> bool {
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

// armv7m System control block modelling
// Armv7-M Technical reference manual B 3.2
// https://www.cse.scu.edu/~dlewis/book3/docs/ARMv7-M_ARM.pdf#E15.Chdhaddf
//
// Setup mem mapped registers
const CPUID: u32 = 0xE000ED00;
const ICSR: u32 = 0xE000ED04;
const VTOR: u32 = 0xE000ED08;
const AIRCR: u32 = 0xE000ED0C;
const SCR: u32 = 0xE000ED10;
const CCR: u32 = 0xE000ED14;
const SHPR1: u32 = 0xE000ED18;
const SHPR2: u32 = 0xE000ED1C;
const SHPR3: u32 = 0xE000ED20;
const SHCSR: u32 = 0xE000ED24;
const CFSR: u32 = 0xE000ED28;
const HFSR: u32 = 0xE000ED2C;
const DFSR: u32 = 0xE000ED30;
const MMFAR: u32 = 0xE000ED34;
const BFAR: u32 = 0xE000ED38;
const AFSR: u32 = 0xE000ED3C;
const CPACR: u32 = 0xE000ED88;

// Maximum possible address for the vector table
// This is needed as the hardware may restrict writes to the Maximum
// See: Armv7-M Technical reference manual page B3-658
// https://www.cse.scu.edu/~dlewis/book3/docs/ARMv7-M_ARM.pdf#E15.Chdhaddf
// Obtained from ChatGPT :P
const VTOR_MAX: u32 = 0x20000000;

// Hook function for system control block
#[allow(unused)]
pub fn scb_hook<T>(
    uc: &mut unicorn_engine::Unicorn<'_, T>,
    acc_type: MemType,
    loc: u64,
    sz: usize,
    val: i64,
    nvic: &mut crate::dynamic_analysis::emu::hooks::interrupt::ArmV7Nvic,
) -> bool {
    // Interrupt control and status registers (ICSR)
    // ARMv7-M Technical reference manual, B3-655
    let mut write_val: u32 = 0;
    if loc == ICSR as u64 {
        let val_u32 = val as u32;

        // NMI_pendset
        if acc_type == MemType::WRITE && ((val_u32 >> 31) & 0x1) == 1 {
            nvic.exc_pend(ExcNum::NMI as u32, true);
        }
        if nvic.is_pending(ExcNum::NMI as u32) {
            write_val = write_val | 1 << 31;
        } else {
            write_val = write_val & (0xFFFFFFFF ^ (1 << 31));
        }

        //PENDSVSET
        if acc_type == MemType::WRITE && ((val_u32 >> 28) & 0x1) == 1 {
            nvic.exc_pend(ExcNum::PendSV as u32, true);
        }
        if nvic.is_pending(ExcNum::PendSV as u32) {
            write_val = write_val | 1 << 28;
        }
        //PENDSVCLR
        if acc_type == MemType::WRITE && ((val_u32 >> 27) & 0x1) == 1 {
            nvic.exc_pend(ExcNum::PendSV as u32, false);
        }

        // PENDSTSET
        if acc_type == MemType::WRITE && ((val_u32 >> 26) & 0x1) == 1 {
            nvic.exc_pend(ExcNum::SysTick as u32, true);
        }
        if nvic.is_pending(ExcNum::SysTick as u32) {
            write_val = write_val | 1 << 26;
        }

        //PENDSTCLR
        if acc_type == MemType::WRITE && ((val_u32 >> 25) & 0x1) == 1 {
            nvic.exc_pend(ExcNum::SysTick as u32, false);
        }

        //ISRPREEMPT
        // RO
        // yet to implement

        //ISRPENDING
        if nvic.any_pending() {
            write_val = write_val | 1 << 22;
        }

        // VECTPENDING
        write_val = write_val | (nvic.get_vectpending() << 12);

        // RETTOBASE
        write_val = write_val | ((nvic.get_num_pending() as u8 <= 1) as u32) << 11;

        // VECTACTIVE
        let vectactive = nvic.get_current_irqn().unwrap_or_else(|| 0);
        write_val = write_val | vectactive;

        if (acc_type == MemType::READ) {
            let le_bytes = write_val.to_le_bytes();
            uc.mem_write(loc, &le_bytes);
        }
        return true;
    }

    // Vector table offset register
    // ARmv7-M Technical Reference Manual B3.2.5
    if loc == VTOR as u64 {
        if (acc_type == MemType::WRITE) {
            let new_vtor = max(val as u64, VTOR_MAX as u64);
            let new_vtor_bytes = new_vtor.to_le_bytes();
            uc.mem_write(loc, &new_vtor_bytes);
        }
        return true;
    }

    // Application Interrupt and Reset Control register
    // Armv7-M Technical Reference Manual B3.2.6
    if loc == AIRCR as u64 {
        // VECTKEY and VECTKEYSTAT
        write_val = 0xFA050000;

        // endiannness, only hw configurable, RO
        // Set to 0, we only do LE,
        // Do nothing
        //
        // PRIGROUP
        if (acc_type == MemType::WRITE) {
            let prigroup_bits: u8 = (((val as u64) >> 8) & 0b111) as u8;
            nvic.set_prio_group_bits(prigroup_bits);
            write_val |= (prigroup_bits as u32) << 8;
        }

        // SYSRESETREQ
        // Game over
        //
        if (acc_type == MemType::WRITE) {
            let reset_req = ((val as u64) >> 2) & 0x1;
            if (reset_req == 1) {
                // TODO: A software requested reset is very different from a normal execution run
                // Have to figure out a way to propagate the uc emu stop's return result, and show
                // LibAFL that this path has caused a software requested reset
                uc.emu_stop();
            }
        }

        // VECTCLRACTIVE
        if (acc_type == MemType::WRITE) {
            let vectclractive: u64 = ((val as u64) >> 1) & 0x1;
            if (vectclractive == 1) {
                // The CPU MUST be in a debug state for this to be predictable behaviour
                // We would like to catch unpredictable behaviour, so we return false here;
                return false;
            }
        }

        // VECTRESET
        if (acc_type == MemType::WRITE) {
            let bit = ((val as u64) & 0x1);
            if (bit == 1) {
                // The CPU MUST be in a debug state for this to be predictable behaviour
                // We would like to catch unpredictable behaviour, so we return false here;
                return false;
            }
        }

        uc.mem_write(loc, &(write_val.to_le_bytes()));
        return true;
    }
    true
}
