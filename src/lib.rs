use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::vec::Vec;

use clap::Parser;

mod hooks;

use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission, SECOND_SCALE};

use libafl::inputs::BytesInput;

fn fuzz(fileinfo: FileInfo, args: Args) {
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
}
#[derive(Parser, Debug)]
#[command(
    author = "Sai",
    version,
    about = "Automated firmware re-hosting and analysis"
)]
pub struct Args {
    #[arg(short, long)]
    file_name: String,
}

#[derive(Default, Debug)]
pub struct FileInfo {
    name: String,
    size: u64,
    contents: Vec<u8>,
}

impl FileInfo {
    fn init(self: &mut Self, f: &String) {
        self.name = f.clone();
        let mut file_obj = File::open(&self.name).expect("File not found");
        self.size = file_obj.metadata().expect("Could not read metadata").len();
        self.contents = vec![0; self.size as usize];
        file_obj
            .read(&mut self.contents)
            .expect("Error while Reading");
    }
}

pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let mut fileinfo = FileInfo::default();
    fileinfo.init(&args.file_name);
    fuzz(fileinfo, args);
    Ok(())
}
