pub use unicorn_engine::{ArmCpuModel, RegisterARM};
pub use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission, SECOND_SCALE};
use std::io;
use crate::dynamic_analysis::emu::hooks::*;

mod hooks;

pub struct Emulator<'a, T>{
    uc: unicorn_engine::Unicorn<'a, T>,
    arch: Arch,
    mode: Mode,
    entry_point: u64,
    timeout: u64,
    count: u64
}

impl<'a, T> Emulator<'a, T> {
    pub fn new(arch: Arch, mode: Mode, ud: T) -> Emulator<'a, T>{
        let uc_n = unicorn_engine::Unicorn::new_with_data(arch, mode, ud).expect("Unable to create uc emulator");
        Emulator {
            uc: uc_n ,
            arch,
            mode,
            entry_point: 0,
            timeout: 0,
            count: 0,
        }
    }

    pub fn setup(&mut self, code: &mut Vec<u8>){
        match self.arch{
            Arch::ARM => {
                // Setup CPU model through ctl_set_cpu_model
                self.uc.ctl_set_cpu_model(ArmCpuModel::UC_CPU_ARM_CORTEX_M3 as i32)
                    .expect("Unable to set CPU Mode");

                // Setup sp and entry point
                let sp = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
                self.entry_point = u32::from_le_bytes([code[4], code[5], code[6], code[7]]) as u64;
                self.uc.reg_write(RegisterARM::SP, sp as u64)
                    .expect("Failed to write sp");

                // Write code to memory
                self.uc.mem_map(0x0, 0x20000000, Permission::EXEC)
                    .expect("Failed to map code section");
                self.uc.mem_write(0, code.as_mut_slice())
                    .expect("Unable to write code");

                // Map remaining address space as rw
                self.uc.mem_map(0x20000000, 0xE0000000, Permission::READ | Permission::WRITE)
                    .expect("Failed to map remaining addr space");

            },
            _ => unimplemented!()
        }
        self.init_basic_hooks();
    }

    fn init_basic_hooks(&mut self){
        self.uc.add_block_hook(0, 0x1FFFFFFF, hooks::common_hooks::block_hook)
            .expect("Unable to add block hook");
        self.uc.add_code_hook(0x0, 0x1FFFFFFF, hooks::common_hooks::code_hook)
            .expect("Unable to add code hook");
        self.uc.add_insn_invalid_hook(hooks::common_hooks::insn_invalid_hook)
            .expect("Unable to add invalid instruction hook");
        self.uc.add_mem_hook(HookType::MEM_INVALID, 0x20000000, 0xFFFFFFFF, hooks::common_hooks::mem_hook);
        match self.arch{
            Arch::ARM => {
                self.uc.add_mem_hook(HookType::MEM_ALL, 0x40000000, 0x20000000, hooks::arm32_hooks::ARM_CORTEX_M3_PERIPHERAL_HOOK);
            },
            _ => unimplemented!()
        }
    }

    pub fn start_emu(&mut self){
        self.uc.emu_start(self.entry_point, 0x1FFFFFFF, self.timeout, self.count as usize).expect("Error while running");
    }


}
