use crate::dynamic_analysis::InputIterator;
pub use unicorn_engine::unicorn_const::MemType;

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
pub fn armv7_nvic_hooks<T>(
    uc: &mut unicorn_engine::Unicorn<'_, T>,
    acc_type: MemType,
    loc: u64,
    sz: usize,
    val: i64,
    nvic: &mut crate::dynamic_analysis::emu::hooks::interrupt::ArmV7Nvic,
) -> bool
where
    T: InputIterator,
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
