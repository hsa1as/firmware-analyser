use crate::FileInfo;
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission, SECOND_SCALE};

use std::error::Error;
pub mod emu;
use emu::input::{InputWrapper, InputIterator, CanLoadData};
use std::{
    env,
    path::PathBuf,
};
use unicorn_engine::Unicorn;
use libafl_targets::{EDGES_MAP_PTR, EDGES_MAP_SIZE_IN_USE};
use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus}, events::SimpleEventManager, executors::{inprocess::InProcessExecutor, ExitKind}, feedback_or, feedback_or_fast, feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback}, fuzzer::{Fuzzer, StdFuzzer}, generators::RandBytesGenerator, inputs::BytesInput, monitors::MultiMonitor, mutators::scheduled::{havoc_mutations, StdScheduledMutator}, observers::{ConstMapObserver, HitcountsMapObserver, TimeObserver}, prelude::CanTrack, schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler}, stages::mutational::StdMutationalStage, state::StdState
};
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    tuples::tuple_list,
};

pub fn start_fuzz(mut fileinfo: FileInfo) -> Result<(), Box<dyn Error>> where
{
     // Create harness
    let mut harness = |input: &BytesInput|{
        let ud = InputWrapper::new();
        let mut emu = emu::Emulator::new(Arch::ARM, Mode::LITTLE_ENDIAN, ud);
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
/*
    let i1 = BytesInput::new(vec![0, 0x1, 0x2, 0x3, 0x4, 0x5]);
    let i2 = BytesInput::new(vec![0, 0x4, 0x7, 0x13, 0xa, 0xf5]);
    let mut r = harness(&i1);
    let mut r2 = match r {
        ExitKind::Ok => "Okay",
        _ => "crashed",
    };
    println!("{r2}");
    println!("All ok");
    r = harness(&i2);
    r2 = match r{
            ExitKind::Ok => "Okay",
        _ => "crashed",
    };
    println!("{r2}");*/

    let monitor = MultiMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(monitor);
    let edges_observer = unsafe {
        HitcountsMapObserver::new(ConstMapObserver::<_, EDGES_MAP_SIZE_IN_USE>::from_mut_ptr(
            "edges",
            EDGES_MAP_PTR,
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

    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
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

