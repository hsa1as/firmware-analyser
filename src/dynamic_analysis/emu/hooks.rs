// TODO: is CPU context correctly saved when emulation stopped inside a hook?

// TODO: start uc_engine with user_data for custom context. Maybe make a wrapper struct with methods

pub use unicorn_engine::RegisterARM;
pub use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission, SECOND_SCALE};


pub fn block_hook<'a, T>(uc: &'a mut unicorn_engine::Unicorn<'_, T>, loc: u64, sz: u32) {
    println!("Block hook : Address = {loc:#08x}, Size = {sz}");
}

pub fn mem_hook<'a, T>(uc: &'a mut unicorn_engine::Unicorn<'_, T>,
                           acc_type: MemType, loc: u64, sz: u32, val: i64){
    println!("Memory hook ! ")
}
