pub fn intr_hook<'a, 'b>(emu: &'a mut unicorn_engine::Unicorn<'b, ()>, num: u32) {
    println!("Interrupt : {num}");
}

pub fn code_hook<'a, 'b>(emu: &'a mut unicorn_engine::Unicorn<'b, ()>, loc: u64, sz: u32) {
    println!("Code hook : Address = {loc:#08x}, Size = {sz}");
}
