use crate::FileInfo;
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission, SECOND_SCALE};

use std::error::Error;
pub mod emu;
use emu::input::{InputWrapper, InputIterator, CanLoadData};
use emu::hooks::common_hooks::CanUpdateMap;
use std::{
    env,
    path::PathBuf,
};
use unicorn_engine::Unicorn;
use libafl_targets::{EDGES_MAP_PTR, EDGES_MAP_SIZE_IN_USE};
use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus}, events::SimpleEventManager, executors::{inprocess_fork::InProcessForkExecutor, ExitKind}, feedback_or, feedback_or_fast, feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback}, fuzzer::{Fuzzer, StdFuzzer}, generators::RandBytesGenerator, inputs::BytesInput, monitors::{MultiMonitor, tui::TuiMonitor}, mutators::scheduled::{havoc_mutations, StdScheduledMutator}, observers::{ConstMapObserver, HitcountsMapObserver, TimeObserver}, prelude::CanTrack, schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler}, stages::mutational::StdMutationalStage, state::StdState
};
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    tuples::tuple_list,
    shmem::{unix_shmem, ShMem, ShMemProvider},
    AsSliceMut,
};


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

impl<CM> CanLoadData for FuzzUserData<CM>{
    fn load_bytes(&mut self, input: &BytesInput){
        self.input_object.load_bytes(input);
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
    fn new(input_object: InputWrapper, cov_map:CM, cov_size: u64) -> FuzzUserData<CM>{
        Self{
            input_object,
            cov_map,
            cov_size,
        }
    }
}

pub fn start_fuzz(mut fileinfo: FileInfo) -> Result<(), Box<dyn Error>> where
{
    // Shmem provider
    let mut shmem_provider = unix_shmem::UnixShMemProvider::new().unwrap();
    let mut EDGES_SIZE = libafl_targets::EDGES_MAP_SIZE_IN_USE;
    let mut EDGES = shmem_provider.new_shmem(EDGES_SIZE).unwrap();
    let EDGES_PTR = EDGES.as_slice_mut().as_mut_ptr();
     // Create harness
    let mut harness = |input: &BytesInput|{
        let EDGES_MAP = EDGES.as_slice_mut();
        let ud = InputWrapper::new();
        let fud = FuzzUserData::new(ud, EDGES_MAP, EDGES_SIZE as u64);
        let mut emu = emu::Emulator::new(Arch::ARM, Mode::LITTLE_ENDIAN, fud);
        emu.setup(&mut fileinfo.contents);
        let ud = emu.get_mut_data();
        ud.reset().expect("Error while resetting Input object");
        ud.load_bytes(input);
        let emu_result = emu.start_emu();
        let result = match emu_result {
            Ok(()) => ExitKind::Ok,
            Err(uc_error) => ExitKind::Crash,
        };
        return result;
    };
    let monitor = TuiMonitor::builder().title(String::from("KMN")).build();
    let mut mgr = SimpleEventManager::new(monitor);
    let edges_observer = unsafe {
        HitcountsMapObserver::new(ConstMapObserver::<_, EDGES_MAP_SIZE_IN_USE>::from_mut_ptr(
            "edges",
            EDGES_PTR,
        )).track_indices()
    };
    let time_observer = TimeObserver::new("time");
    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&edges_observer),
        TimeFeedback::new(&time_observer)
    );

    let mut objective = feedback_or_fast!(CrashFeedback::new());

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::new(),
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();
    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());
    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = InProcessForkExecutor::new(
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        core::time::Duration::from_millis(5000),
        shmem_provider,
    )
    .expect("Failed to create the executor");

    // Generator of printable bytearrays of max size 32
    let mut generator = RandBytesGenerator::new(4);

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
    Ok(())
}
pub fn run(fileinfo: FileInfo) -> Result<(), Box<dyn Error>> {
    start_fuzz(fileinfo).expect("Huh what");
    Ok(())
}

