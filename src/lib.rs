use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::vec::Vec;

use clap::{Parser, ValueEnum};

mod static_analysis;
mod dynamic_analysis;

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
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum AnalysisMode{
    // Fuzzy-hash matching
    Static,

    // Dynamic analysis
    Dynamic,
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
        // TODO: maybe mmap file contents instead of reading
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

    match args.mode{
        AnalysisMode::Static => {
            static_analysis::run(fileinfo);
        }
        AnalysisMode::Dynamic => {
            dynamic_analysis::run(fileinfo);
        }
    }
    Ok(())
}
