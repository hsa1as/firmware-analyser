pub use unicorn_engine::RegisterARM;
pub use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission, SECOND_SCALE};

use crate::dynamic_analysis::emu::hooks::*;

mod hooks;

pub struct Emulator<'a, T>{
    uc: unicorn_engine::Unicorn<'a, T>,
    arch: Arch,
    mode: Mode,
    entry_point: u64,
}

impl<'a, T> Emulator<'a, T> {
    pub fn new(arch: Arch, mode: Mode, ud: T) -> Emulator<'a, T>{
        let uc_n = unicorn_engine::Unicorn::new_with_data(arch, mode, ud).expect("Unable to create uc emulator");
        Emulator {
            uc: uc_n ,
            arch,
            mode,
            entry_point: 0,
        }
    }

    pub fn setup(&mut self, code: &Vec<u8>){
        match self.arch{
            Arch::ARM => {
                if self.mode == Mode::LITTLE_ENDIAN {
                    // Setup initial stack
                    let sp = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
                    self.entry_point = u32::from_le_bytes([code[4], code[5], code[6], code[7]]) as u64;
                    self.uc.reg_write(RegisterARM::SP, sp as u64)
                        .expect("Failed to write sp");

                    // Write code to memory
                    self.uc.mem_map(0x0, 0x20000000, Permission::EXEC)
                        .expect("Failed to map code section");

                    // Map remaining address space as rw
                    self.uc.mem_map(0x20000000, 0xE0000000, Permission::READ | Permission::WRITE)
                        .expect("Failed to map remaining addr space");
                }
            },
            _ => unimplemented!()
        }
        self.init_basic_hooks();
    }

    fn init_basic_hooks(&mut self){
        self.uc.add_block_hook(hooks::block_hook)
            .expect("Unable to add block hook");
    }
}
