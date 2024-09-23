use crate::FileInfo;
use crate::dynamic_analysis::emu::Emulator;
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission, SECOND_SCALE};

use std::error::Error;
mod emu;
pub fn run(fileinfo: FileInfo) -> Result<(), Box<dyn Error>> {
    let mut code = fileinfo.contents;
    let mut ud: u64 = 0;
    let mut emu = emu::Emulator::new(Arch::ARM, Mode::LITTLE_ENDIAN, ud);
    emu.setup(&mut code);
    emu.start_emu();
/*    let mut code = fileinfo.contents;

    // Get reset vector
    // ARM32
    let reset_handler = u32::from_le_bytes([code[4], code[5], code[6], code[7]]) as u64;
    let sp = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);

    // Setup unicorn engine to run input code
    let mut emu = unicorn_engine::Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN)
        .expect("Couln't init emulator");
    // Memory map
    emu.mem_map(0x0, 0x20000000, Permission::ALL)
        .expect("Memory map failed");
    emu.mem_write(0, code.as_mut_slice())
        .expect("Failed to write code");
    // Setup stack pointer
    emu.reg_write(RegisterARM::SP, sp as u64)
        .expect("Unable to setup stack pointer");
    // Hooks
    // Interrupt hook
    emu.add_intr_hook(hooks::intr_hook)
        .expect("Unable to add interrupt hook");

    // Code hook
    emu.add_code_hook(0, code.len() as u64, hooks::code_hook).expect("Unable to add code hook");
    emu.emu_start(
        reset_handler,
        reset_handler + (code.len() as u64),
        10 * SECOND_SCALE,
        1000,
    )
    .expect("Error while running");
    println!("Stopped running @ PC = {:?}", emu.reg_read(RegisterARM::PC).unwrap());
    println!("Finished running");*/
    Ok(())

}
