use firmware_analyser::{Args, run};
use clap::Parser;

fn main() {
    let args = Args::parse();
    if let Err(e) = run(args){
        println!("Error: {e}");
    }
}
