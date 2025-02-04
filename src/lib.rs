use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::vec::Vec;

use clap::{Parser, ValueEnum};

mod dynamic_analysis;
mod static_analysis;

#[derive(Parser, Debug)]
#[command(
    author = "Sai",
    version,
    about = "Automated firmware re-hosting and analysis"
)]
pub struct Args {
    // Firmware filename
    #[arg(short, long)]
    file_name: String,

    // Analysis type
    #[arg(value_enum, short, long)]
    mode: AnalysisMode,

    // Input file name, used only with pure emulation
    #[arg(default_value = "", short, long)]
    input_file: String,

    // Config file name, JSON
    #[arg(default_value = "", short, long)]
    config_file: String,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum AnalysisMode {
    // Static Analyis
    Static,

    // Fuzzing
    Fuzz,

    // Pure emulation
    Emulate,
}

#[derive(Default, Debug)]
pub struct FileInfo {
    name: String,
    size: u64,
    contents: Vec<u8>,
}

impl FileInfo {
    fn init(&mut self, f: &str) {
        self.name = f.to_string();
        let mut file_obj = File::open(&self.name).expect("File not found");
        // TODO: maybe mmap file contents instead of reading
        self.size = file_obj.metadata().expect("Could not read metadata").len();
        self.contents = vec![0; self.size as usize];
        file_obj
            .read_exact(&mut self.contents)
            .expect("Error while Reading file {self.name}");
    }
}

pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let mut firmwarefile = FileInfo::default();
    firmwarefile.init(&args.file_name);

    match args.mode {
        AnalysisMode::Static => {
            let _ = static_analysis::run(firmwarefile);
        }
        AnalysisMode::Fuzz => {
            let _ = dynamic_analysis::run(args, firmwarefile, true);
        }
        AnalysisMode::Emulate => {
            let _ = dynamic_analysis::run(args, firmwarefile, false);
        }
    }
    Ok(())
}
