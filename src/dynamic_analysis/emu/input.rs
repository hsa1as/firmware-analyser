
use core::num::NonZeroUsize;
#[allow(unused_imports)]
use std::{
    borrow::Cow,
    hash::{DefaultHasher, Hash, Hasher},
    error::Error,
};

#[allow(unused_imports)]
use libafl::{
    corpus::CorpusId,
    generators::{Generator, RandBytesGenerator},
    inputs::{BytesInput, HasTargetBytes, HasMutatorBytes, Input, MutVecInput},
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error as libAFLError, SerdeAny,
};
use libafl_bolts::{rands::Rand, Named, HasLen, AsSlice};

use serde::{Deserialize, Serialize};


// Crate imports
pub use crate::dynamic_analysis::emu::hooks::common_hooks::CanUpdateMap;
use crate::dynamic_analysis::MAX_NUM_INTERRUPTS;

pub trait InputIterator {
    fn get_next_word(&mut self) -> [u8; 4];
    fn reset(&mut self) -> Result<(), Box<dyn Error>>;
}

// InputWrapper to hold input for peripheral reads, addresses for interrupts, and interrupt numbers
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct InputWrapper{
    bytes: Vec<u8>,
    idx: usize,
    intr_addrs: Vec<(u32,u32)>,
}

impl InputWrapper{
    pub fn new() -> InputWrapper{
        InputWrapper{
            bytes: Vec::<u8>::new(),
            idx: 0,
            intr_addrs: Vec::<(u32, u32)>::new(),
        }
    }
}


impl InputIterator for InputWrapper{
    fn get_next_word(&mut self) -> [u8; 4]{
        if self.bytes.is_empty() {
            return [0, 0, 0, 0]
        }
        let mut a: [u8; 4] = [0,0,0,0];
        let mut i: usize = 0;
        while self.idx < self.bytes.len() && i < 4 {
            a[i] = self.bytes[self.idx];
            self.idx += 1;
            i += 1;
        }
        a
    }

    fn reset(&mut self) -> Result<(), Box<dyn Error>>{
        self.idx = 0;
        self.bytes.clear();
        Ok(())
    }
}

#[allow(dead_code)]
pub struct FuzzUserData<CM>{
    input_object: InputWrapper,
    cov_map:  CM,
    cov_size: u64,
}

impl<'a> CanUpdateMap for FuzzUserData<&'a mut [u8]> {
    unsafe fn update_map(&mut self, hash: u64){
        let mut cur = self.cov_map[hash as usize];
        cur = cur.overflowing_add(1).0;
        self.cov_map[hash as usize] = cur;
    }

}

impl<CM> InputIterator for FuzzUserData<CM>{
   fn get_next_word(&mut self) -> [u8; 4]{
        self.input_object.get_next_word()
   }

    fn reset(&mut self) -> Result<(), Box<dyn Error>>{
        self.input_object.reset()
    }
}

impl<CM> FuzzUserData<CM>{
    pub fn new(input_object: InputWrapper, cov_map:CM, cov_size: u64) -> FuzzUserData<CM>{
        Self{
            input_object,
            cov_map,
            cov_size,
        }
    }
}

impl Input for InputWrapper{
    fn generate_name(&self, _id: Option<CorpusId>) -> String  {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }
}

pub struct FuzzingInputGenerator<S> where S: HasRand{
    pub bytes_generator: RandBytesGenerator<S>,
    pub code_lower: u32,
    pub code_upper: u32,
    pub max_intr_num: u32,
}

impl<S> FuzzingInputGenerator<S> where S: HasRand{
    pub fn new(max_len: NonZeroUsize, code_lower: u32, code_upper: u32, max_intr_num: u32) -> Self {
        Self{
            bytes_generator: RandBytesGenerator::new(max_len.into()),
            code_lower,
            code_upper,
            max_intr_num,
        }
    }
}

// create mechanism to generate inputs from scratch.
// I dont know why
impl<S> Generator<InputWrapper, S> for FuzzingInputGenerator<S> where S: HasRand{
    fn generate(&mut self, state: &mut S) -> Result<InputWrapper, libAFLError>{

        // Generate input bytes, to be used when peripheral read occurs
        let generator = &mut self.bytes_generator;
        let bytes_input = generator.generate(state).unwrap().target_bytes().to_vec();

        // Do generation for interrupt numbers, interrupt addresses on our own here
        let mut rand_obj = state.rand_mut();

        // How many interrupts are going to be raised?
        let num_of_interrupts = rand_obj.below(MAX_NUM_INTERRUPTS as usize);
        let mut intr_addrs_vec = vec![(0_u32, 0_u32); num_of_interrupts];
        // TODO: is it okay to use the same rand object to generate random bytes
        // for unrelated parts of the input?
        for elem in intr_addrs_vec.iter_mut(){
            (*elem).0 = rand_obj.between(self.code_lower as usize, self.code_upper as usize) as u32;
            (*elem).0 = rand_obj.below(self.max_intr_num as usize) as u32;
        }

        Ok(InputWrapper{
            bytes: bytes_input,
            idx: 0_usize,
            intr_addrs: intr_addrs_vec,
        })

    }
}

// How do we mutate our input?
// Can think of couple of mutators:
// 1. Add address to trigger an interrupt with number n
// 2. Change existing address
// 3. Change existing interrupt number
// 4. Remove existing interrupt
// 5. Use existing havoc mutators for the input field

