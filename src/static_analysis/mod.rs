use std::error::Error;

use crate::FileInfo;

pub fn run(fileinfo: FileInfo) -> Result<(), Box<dyn Error>>{
    println!("Static");
    Ok(())
}
