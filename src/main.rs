use clap::Parser;
use firmware_analyser::{run, Args};

fn main() {
    let args = Args::parse();
    if let Err(e) = run(args) {
        println!("Error: {e}");
    }
    run();
}
