use crate::FileInfo;
use std::error::Error;
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};

mod hooks;

pub fn run(fileinfo: FileInfo) -> Result<(), Box<dyn Error>> {
    let mut code = fileinfo.contents;

    // Get reset vector
    // ARM32
    let reset_handler = u32::from_le_bytes([code[4], code[5], code[6], code[7]]) as u64;
    // Setup unicorn engine to run input code
    let mut emu = unicorn_engine::Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN)
        .expect("Couln't init emulator");
    // Memory map
    emu.mem_map(0x0, 0x100000000, Permission::ALL)
        .expect("Memory map failed");
    emu.mem_write(0, code.as_mut_slice())
        .expect("Failed to write code");

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
    println!("Finished running");
    Ok(())

}
