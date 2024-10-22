use libafl::inputs::{BytesInput, HasTargetBytes};
use std::error::Error;
use libafl_bolts::AsSlice;
pub trait InputIterator {
    fn get_next_word(&mut self) -> [u8; 4];
    fn reset(&mut self) -> Result<(), Box<dyn Error>>;
}

pub trait CanLoadData{
    fn load_bytes(&mut self, input: &BytesInput);
}

pub struct InputWrapper{
    bytes: Vec<u8>,
    idx: usize,
}

impl InputWrapper{
    pub fn new() -> InputWrapper{
        InputWrapper{bytes: Vec::<u8>::new(), idx: 0}
    }
}
impl CanLoadData for InputWrapper{
    fn load_bytes(&mut self, input: &BytesInput){
        let v = input.target_bytes();
        let buf = v.as_slice();
        self.bytes.extend_from_slice(buf);
    }
}

impl InputIterator for InputWrapper{
    fn get_next_word(&mut self) -> [u8; 4]{
        if self.bytes.is_empty() {
            return [0, 0, 0, 0]
        }
        let mut a: [u8; 4] = [0,0,0,0];
        let mut i: usize = 0;
        while (self.idx < self.bytes.len() && i < 4) {
            a[i] = self.bytes[self.idx];
            self.idx += 1;
            i += 1;
        }
        return a;
    }

    fn reset(&mut self) -> Result<(), Box<dyn Error>>{
        self.idx = 0;
        self.bytes.clear();
        Ok(())
    }
}
