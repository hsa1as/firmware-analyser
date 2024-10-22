pub use unicorn_engine::unicorn_const::MemType;
use crate::dynamic_analysis::InputIterator;

pub fn ARM_CORTEX_M3_PERIPHERAL_HOOK<'a, T>(uc: &'a mut unicorn_engine::Unicorn<'_, T>,
                           acc_type: MemType, loc: u64, sz: usize, val: i64) -> bool where
T: InputIterator
{
    if acc_type == MemType::READ{
        let data = uc.get_data_mut();
        let word = data.get_next_word();
        uc.mem_write(loc, &word)
            .expect("Couldn't write AFL input to memory");
        //println!("Hit peripheral hook with address = {loc} and size = {sz}");
        let word_as_u32 = u32::from_le_bytes(word);
        //println!("Writing word = {word_as_u32}");
    }
    true
}
