use core::num::NonZeroUsize;
#[allow(unused_imports)]
use std::{
    borrow::Cow,
    error::Error,
    hash::{DefaultHasher, Hash, Hasher},
};

#[allow(unused_imports)]
use libafl::{
    corpus::CorpusId,
    generators::{Generator, RandBytesGenerator},
    inputs::{BytesInput, HasMutatorBytes, HasTargetBytes, Input, MutVecInput},
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error as libAFLError, SerdeAny,
};
use libafl_bolts::{rands::Rand, Named};

use serde::{Deserialize, Serialize};
use unicorn_engine::UcHookId;

// Crate imports
pub use crate::dynamic_analysis::emu::hooks::common_hooks::CanUpdateMap;
use crate::dynamic_analysis::MAX_NUM_INTERRUPTS;

pub trait InputIterator {
    fn get_next_word(&mut self) -> [u8; 4];
    fn get_next_interrupt(&mut self) -> Result<(u32, u32), i32>;
}

// CombinedInput to hold input for peripheral reads, addresses for interrupts, and interrupt numbers
// This is the object actually created by the fuzzer
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct CombinedInput {
    bytes: Vec<u8>,
    intr_addrs: Vec<(u32, u32)>,
}

impl CombinedInput {
    pub fn new() -> CombinedInput {
        CombinedInput {
            bytes: Vec::<u8>::new(),
            intr_addrs: Vec::<(u32, u32)>::new(),
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn bytes_mut(&mut self) -> MutVecInput<'_> {
        (&mut self.bytes).into()
    }
}

pub struct InputWrapper<'a> {
    bytes: &'a Vec<u8>,
    idx_bytes: usize,
    intr_addrs: &'a Vec<(u32, u32)>,
    idx_intrs: usize,
}

impl<'a> InputWrapper<'a> {
    pub fn new(bytes: &'a Vec<u8>, intr_addrs: &'a Vec<(u32, u32)>) -> Self {
        Self {
            bytes,
            idx_bytes: 0,
            intr_addrs,
            idx_intrs: 0,
        }
    }
}

impl<'a> From<&'a CombinedInput> for InputWrapper<'a> {
    fn from(value: &'a CombinedInput) -> Self {
        InputWrapper::new(&value.bytes, &value.intr_addrs)
    }
}

impl<'a> InputIterator for InputWrapper<'a> {
    fn get_next_word(&mut self) -> [u8; 4] {
        if self.bytes.is_empty() {
            return [0, 0, 0, 0];
        }
        let mut a: [u8; 4] = [0, 0, 0, 0];
        let mut i: usize = 0;
        while self.idx_bytes < self.bytes.len() && i < 4 {
            a[i] = self.bytes[self.idx_bytes];
            self.idx_bytes += 1;
            i += 1;
        }
        a
    }
    fn get_next_interrupt(&mut self) -> Result<(u32, u32), i32> {
        if self.idx_intrs >= self.intr_addrs.len() {
            return Err(-1);
        }
        let retval = self.intr_addrs[self.idx_intrs];
        self.idx_intrs = self.idx_intrs.checked_add(1).expect("You had one job");
        return Ok(retval);
    }
}

impl Input for CombinedInput {
    fn generate_name(&self, _id: Option<CorpusId>) -> String {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }
}

pub struct FuzzingInputGenerator {
    pub bytes_generator: RandBytesGenerator,
    pub code_lower: u32,
    pub code_upper: u32,
    pub max_intr_num: NonZeroUsize,
}

impl FuzzingInputGenerator {
    pub fn new(max_len: NonZeroUsize, code_lower: u32, code_upper: u32, max_intr_num: u32) -> Self {
        Self {
            bytes_generator: RandBytesGenerator::new(max_len.into()),
            code_lower,
            code_upper,
            max_intr_num: NonZeroUsize::new(max_intr_num as usize).unwrap(),
        }
    }
}

// create mechanism to generate inputs from scratch.
// I dont know why
impl<S> Generator<CombinedInput, S> for FuzzingInputGenerator
where
    S: HasRand,
{
    fn generate(&mut self, state: &mut S) -> Result<CombinedInput, libAFLError> {
        // Generate input bytes, to be used when peripheral read occurs
        let generator = &mut self.bytes_generator;
        let bytes_input = generator.generate(state).unwrap().target_bytes().to_vec();

        // Do generation for interrupt numbers, interrupt addresses on our own here
        let rand_obj = state.rand_mut();

        // How many interrupts are going to be raised?
        let num_of_interrupts =
            rand_obj.below(NonZeroUsize::new(MAX_NUM_INTERRUPTS as usize).unwrap()) as u32;
        let mut intr_addrs_vec = vec![(0_u32, 0_u32); num_of_interrupts as usize];
        // TODO: is it okay to use the same rand object to generate random bytes
        // for unrelated parts of the input?
        for elem in intr_addrs_vec.iter_mut() {
            (*elem).0 = rand_obj.between(self.code_lower as usize, self.code_upper as usize) as u32;
            (*elem).0 = rand_obj.below(self.max_intr_num) as u32;
        }

        Ok(CombinedInput {
            bytes: bytes_input,
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
pub struct InterruptAddMutator {
    code_lower: u32,
    code_upper: u32,
    max_intr_num: NonZeroUsize,
}
pub struct InterruptModifyMutator {
    code_lower: u32,
    code_upper: u32,
    max_intr_num: NonZeroUsize,
}
pub struct InterruptRemoveMutator;

impl InterruptAddMutator {
    pub fn new(code_lower: u32, code_upper: u32, max_intr_num: NonZeroUsize) -> Self {
        Self {
            code_lower,
            code_upper,
            max_intr_num,
        }
    }
}

impl InterruptModifyMutator {
    pub fn new(code_lower: u32, code_upper: u32, max_intr_num: NonZeroUsize) -> Self {
        Self {
            code_lower,
            code_upper,
            max_intr_num,
        }
    }
}

impl InterruptRemoveMutator {
    pub fn new() -> Self {
        Self {}
    }
}

impl Named for InterruptAddMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("InterruptAddMutator")
    }
}

impl Named for InterruptModifyMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("InterruptModifyMutator")
    }
}

impl Named for InterruptRemoveMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("InterruptRemoveMutator")
    }
}

impl<S> Mutator<CombinedInput, S> for InterruptAddMutator
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut CombinedInput,
    ) -> Result<MutationResult, libAFLError> {
        // If we have too many interrupt addresses, skip the mutation
        if input.intr_addrs.len() as u32 >= MAX_NUM_INTERRUPTS {
            return Ok(MutationResult::Skipped);
        }
        let rand_obj = state.rand_mut();
        // Get the new thing
        let new_addr = rand_obj.between(self.code_lower as usize, self.code_upper as usize) as u32;
        let new_intr = rand_obj.below(self.max_intr_num) as u32;

        // Get Index to add to
        let intr_addr_size = input.intr_addrs.len();
        let idx = rand_obj.below(NonZeroUsize::new(intr_addr_size + 1).unwrap());
        if idx == intr_addr_size {
            // add to end of the vector
            input.intr_addrs.push((new_addr, new_intr));
        } else {
            // add to idx
            input.intr_addrs.insert(idx, (new_addr, new_intr));
        }
        Ok(MutationResult::Mutated)
    }
}

impl<S> Mutator<CombinedInput, S> for InterruptModifyMutator
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut CombinedInput,
    ) -> Result<MutationResult, libAFLError> {
        // Select an index to mutate
        let idx = match state.rand_mut().choose(&mut input.intr_addrs) {
            Some(val) => val,
            None => return Ok(MutationResult::Skipped),
        };
        let rand_obj = state.rand_mut();
        // Get the new thing
        let new_addr = rand_obj.between(self.code_lower as usize, self.code_upper as usize) as u32;
        let new_intr = rand_obj.below(self.max_intr_num) as u32;

        *idx = (new_addr, new_intr);
        Ok(MutationResult::Mutated)
    }
}

impl<S> Mutator<CombinedInput, S> for InterruptRemoveMutator
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut CombinedInput,
    ) -> Result<MutationResult, libAFLError> {
        let vec = &mut input.intr_addrs;
        if vec.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        // choose index to remove
        let idx = state
            .rand_mut()
            .below(NonZeroUsize::new(vec.len()).unwrap());
        vec.remove(idx);
        Ok(MutationResult::Mutated)
    }
}

#[allow(dead_code)]
pub struct FuzzUserData<'a, CM> {
    input_object: InputWrapper<'a>,
    cov_map: CM,
    cov_size: u64,
    last_intr_addr: Option<UcHookId>,
}

impl<'a> CanUpdateMap for FuzzUserData<'a, &'a mut [u8]> {
    unsafe fn update_map(&mut self, hash: u64) {
        let mut cur = self.cov_map[hash as usize];
        cur = cur.overflowing_add(1).0;
        self.cov_map[hash as usize] = cur;
    }
}

impl<'a, CM> InputIterator for FuzzUserData<'a, CM> {
    fn get_next_word(&mut self) -> [u8; 4] {
        self.input_object.get_next_word()
    }

    fn get_next_interrupt(&mut self) -> Result<(u32, u32), i32> {
        self.input_object.get_next_interrupt()
    }
}

impl<'a, CM> FuzzUserData<'a, CM> {
    pub fn new(input_object: InputWrapper<'a>, cov_map: CM, cov_size: u64) -> FuzzUserData<CM> {
        Self {
            input_object,
            cov_map,
            cov_size,
            last_intr_addr: None,
        }
    }
}
