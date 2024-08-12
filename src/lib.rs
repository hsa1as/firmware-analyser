use std::fs::{File};
use std::vec::Vec;
use std::error::Error;
use std::io::Read;
use unicorn_engine::unicorn_const::{
    uc_error, Arch, HookType, MemType, Mode, Permission, SECOND_SCALE,
};
use unicorn_engine::{
    InsnSysX86, RegisterARM, RegisterPPC, RegisterMIPS, RegisterX86, Unicorn,
};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author = "Sai", version, about = "Automated firmware re-hosting and analysis")]
pub struct Args{
    #[arg(short, long)]
    file_name: String
}

#[derive(Default, Debug)]
struct Fileinfo {
    name: String,
    size: u64,
    contents: Vec<u8>,
}

impl Fileinfo {
    fn init(self: &mut Self, f: String) {
        self.name = f.clone();
        let mut file_obj = File::open(&self.name).expect("File not found");
        self.size = file_obj.metadata().expect("Could not read metadata").len();
        self.contents = vec![0; self.size as usize];
        file_obj.read(&mut self.contents).expect("Error while Reading");
    }
}

pub fn run(args: Args) -> Result<(), Box<dyn Error>>{
    let mut fileinfo = Fileinfo::default();
    fileinfo.init(args.file_name);
    fuzz(fileinfo, args);
    OKu(())
}
