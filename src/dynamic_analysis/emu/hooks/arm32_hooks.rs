pub use unicorn_engine::unicorn_const::MemType;

use crate::dynamic_analysis::emu::hooks::context;

pub fn ARM_CORTEX_M3_PERIPHERAL_HOOK<'a, T>(uc: &'a mut unicorn_engine::Unicorn<'_, T>,
                           acc_type: MemType, loc: u64, sz: usize, val: i64) -> bool{

    println!("ARM_CORTEX_M3_PERIPHERAL_HOOK");
    return true;
}
