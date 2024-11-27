use crate::FileInfo;

// Standard imports
use core::num::NonZeroUsize;
use core::ptr::NonNull;
use std::error::Error;
use std::path::PathBuf;

// Unicorn imports
use unicorn_engine::unicorn_const::{Arch, Mode};

// LibAFL imports
#[allow(unused_imports)]
use libafl::{
    corpus::OnDiskCorpus,
    events::SimpleEventManager,
    executors::{inprocess_fork::InProcessForkExecutor, ExitKind},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::BytesInput,
    monitors::tui::TuiMonitor,
    mutators::{havoc_mutations, scheduled::StdScheduledMutator},
    observers::{CanTrack, ConstMapObserver, HitcountsMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    shmem::{unix_shmem, ShMemProvider},
    tuples::tuple_list,
    AsSliceMut,
};
pub use libafl_targets::EDGES_MAP_DEFAULT_SIZE as MAP_SIZE;

// Emulator struct
pub mod emu;
use emu::hooks::common_hooks::CanUpdateMap;
use emu::input::{CombinedInput, FuzzUserData, InputIterator, InputWrapper};

// Tunable constants
pub const MAX_NUM_INTERRUPTS: u32 = 25;

#[allow(non_snake_case, unused_variables, unused_mut)]
pub fn emulate(mut fileinfo: FileInfo) -> Result<(), Box<dyn Error>> {
    println!("Not implemented");
    Ok(())
}

#[allow(non_snake_case, unused_variables, unused_mut)]
pub fn start_fuzz_singlecore(mut fileinfo: FileInfo) -> Result<(), Box<dyn Error>> where
{
    // Shmem provider
    let mut shmem_provider = unix_shmem::UnixShMemProvider::new().unwrap();
    let mut EDGES = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    let EDGES_PTR = EDGES.as_slice_mut();
    let EDGES_PTR_FOR_MAP = NonNull::<[u8; MAP_SIZE]>::new(
        <&mut [u8; MAP_SIZE]>::try_from(EDGES_PTR).expect("Error while converting Map to array"),
    )
    .unwrap();

    // Create harness
    let mut harness = |input: &CombinedInput| {
        let EDGES_MAP = EDGES.as_slice_mut();
        let ud = InputWrapper::from(input);
        let fud = FuzzUserData::new(ud, EDGES_MAP, MAP_SIZE as u64);
        let mut emu = emu::Emulator::new(Arch::ARM, Mode::LITTLE_ENDIAN, fud);
        emu.setup(&mut fileinfo.contents);
        let emu_result = emu.start_emu();
        match emu_result {
            Ok(()) => ExitKind::Ok,
            Err(uc_error) => ExitKind::Crash,
        }
    };

    let monitor = TuiMonitor::builder().title(String::from("Fuzzer")).build();
    let mut mgr = SimpleEventManager::new(monitor);

    let edges_observer = unsafe {
        HitcountsMapObserver::new(ConstMapObserver::<_, MAP_SIZE>::from_mut_ptr(
            "edges",
            EDGES_PTR_FOR_MAP,
        ))
        .track_indices()
    };
    let time_observer = TimeObserver::new("time");

    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&edges_observer),
        TimeFeedback::new(&time_observer)
    );

    let mut objective = feedback_or_fast!(CrashFeedback::new());

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        OnDiskCorpus::new(PathBuf::from("./corpus")).unwrap(),
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
    let mut generator = RandBytesGenerator::new(NonZeroUsize::new(4).unwrap());

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
    println!("It stopped?");
    Ok(())
}

pub fn run(fileinfo: FileInfo, fuzz: bool) -> Result<(), Box<dyn Error>> {
    if fuzz {
        start_fuzz_singlecore(fileinfo).expect("Fuzzing failed");
    } else {
        emulate(fileinfo).expect("Emulation failed");
    }
    Ok(())
}
