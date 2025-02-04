use std::error::Error;

use crate::FileInfo;

pub fn run(_fileinfo: FileInfo) -> Result<(), Box<dyn Error>> {
    println!("Static");
    Ok(())
}
