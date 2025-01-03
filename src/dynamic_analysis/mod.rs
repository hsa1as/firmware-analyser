use crate::FileInfo;

// Standard imports
use core::num::NonZeroUsize;
use core::ptr::NonNull;
use std::error::Error;
use std::path::PathBuf;

use libafl::mutators::mapped_havoc_mutations;
// Unicorn imports
use unicorn_engine::unicorn_const::{Arch, Mode};

// LibAFL imports
#[allow(unused_imports)]
use libafl::{
    corpus::OnDiskCorpus,
    events::{launcher::Launcher, EventConfig, SimpleEventManager},
    executors::{inprocess::InProcessExecutor, inprocess_fork::InProcessForkExecutor, ExitKind},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::{Generator, RandBytesGenerator},
    inputs::BytesInput,
    monitors::{tui::TuiMonitor, SimpleMonitor},
    mutators::{havoc_mutations, scheduled::StdScheduledMutator},
    observers::{CanTrack, ConstMapObserver, HitcountsMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::mutational::StdMutationalStage,
    state::{HasRand, NopState, StdState},
};
use libafl_bolts::{
    core_affinity::Cores,
    current_nanos,
    rands::StdRand,
    shmem::{unix_shmem, ShMemProvider},
    tuples::{tuple_list, Merge, Prepend},
    AsSliceMut,
};
pub use libafl_targets::EDGES_MAP_DEFAULT_SIZE as MAP_SIZE;

// Emulator struct
pub mod emu;
use emu::{
    input::{
        CombinedInput, FuzzUserData, FuzzingInputGenerator, InputIterator, InputWrapper,
        InterruptAddMutator, InterruptModifyMutator, InterruptRemoveMutator,
    },
    EmuExit,
};

// Tunable constants
pub const MAX_NUM_INTERRUPTS: u32 = 25;

#[allow(non_snake_case, unused_variables, unused_mut)]
pub fn test_emulate(mut fileinfo: FileInfo) -> Result<(), Box<dyn Error>> {
    // Create edge map
    let mut shmem_provider = unix_shmem::UnixShMemProvider::new().unwrap();
    let mut EDGES = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    let EDGES_PTR = EDGES.as_slice_mut();
    let EDGES_PTR_FOR_MAP = NonNull::<[u8; MAP_SIZE]>::new(
        <&mut [u8; MAP_SIZE]>::try_from(EDGES_PTR).expect("Error while converting Map to array"),
    )
    .unwrap();
    let EDGES_MAP = EDGES.as_slice_mut();

    let mut combined_input_gen = FuzzingInputGenerator::new(
        NonZeroUsize::new(0x100).unwrap(),
        2480,
        2490,
        MAX_NUM_INTERRUPTS,
    );
    let mut nop_state = NopState::<CombinedInput>::new();
    let mut combined_input = combined_input_gen.generate(&mut nop_state).unwrap();
    println!("Generated input: {:?}", combined_input);
    let mut ud = InputWrapper::from(&combined_input);
    println!("InputWrapper: {:?}", ud);
    let mut fud = FuzzUserData::new(ud, EDGES_MAP, MAP_SIZE as u64);
    let mut emu = emu::Emulator::new(Arch::ARM, Mode::LITTLE_ENDIAN, fud);
    emu.setup(&mut fileinfo.contents);
    let emu_result = emu.start_emu();
    println!("Emulation result: {:?}", emu_result);
    Ok(())
}

#[allow(non_snake_case, unused)]
pub fn start_fuzz_multicore(mut fileinfo: FileInfo) -> Result<(), Box<dyn Error>> {
    // Shmem provider
    let mut shmem_provider = unix_shmem::UnixShMemProvider::new().unwrap();
    let mut EDGES = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    let EDGES_PTR = EDGES.as_slice_mut();
    let EDGES_PTR_FOR_MAP = NonNull::<[u8; MAP_SIZE]>::new(
        <&mut [u8; MAP_SIZE]>::try_from(EDGES_PTR).expect("Error while converting Map to array"),
    )
    .unwrap();

    // Monitor
    // let monitor = SimpleMonitor::new(|s| println!("{s}"));
    let monitor = TuiMonitor::builder().title(String::from("Fuzzer")).build();

    // Closure for run_client
    let mut run_client = |state: Option<_>, mut restarting_mgr, _core_id| {
        // Create harness
        let mut harness = |input: &CombinedInput| {
            let EDGES_MAP = EDGES.as_slice_mut();
            let ud = InputWrapper::from(input);
            let fud = FuzzUserData::new(ud, EDGES_MAP, MAP_SIZE as u64);
            let mut emu = emu::Emulator::new(Arch::ARM, Mode::LITTLE_ENDIAN, fud);
            emu.setup(&mut fileinfo.contents);
            let emu_result = emu.start_emu();
            match emu_result {
                Ok(EmuExit::Timeout) => ExitKind::Timeout,
                Ok(EmuExit::Ok) => ExitKind::Ok,
                Ok(EmuExit::Crash) => ExitKind::Crash,
                Err(uc_error) => ExitKind::Crash,
            }
        };

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

        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                StdRand::with_seed(current_nanos()),
                OnDiskCorpus::new(PathBuf::from("./corpus")).unwrap(),
                OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
                &mut feedback,
                &mut objective,
            )
            .unwrap()
        });

        let scheduler = QueueScheduler::new(); //IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());
                                               // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut executor = InProcessExecutor::with_timeout(
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut restarting_mgr,
            core::time::Duration::from_millis(5000),
        )
        .expect("Failed to create the executor");

        // Generator of printable bytearrays of max size 32
        let mut generator = FuzzingInputGenerator::new(
            NonZeroUsize::new(0x1000).unwrap(),
            0x1000,
            0x2000,
            MAX_NUM_INTERRUPTS,
        );

        // Generate 8 initial inputs
        if state.must_load_initial_inputs() {
            state
                .generate_initial_inputs(
                    &mut fuzzer,
                    &mut executor,
                    &mut generator,
                    &mut restarting_mgr,
                    8,
                )
                .expect("Failed to generate the initial corpus");
        }

        // Setup a mutational stage with a basic bytes mutator
        let mapped_mutators =
            mapped_havoc_mutations(CombinedInput::bytes_mut, CombinedInput::bytes);
        let mutators = tuple_list!()
            .merge(mapped_mutators)
            .prepend(InterruptAddMutator::new(
                0x0,
                0x20000000,
                NonZeroUsize::new(MAX_NUM_INTERRUPTS as usize).unwrap(),
            ))
            .prepend(InterruptModifyMutator::new(
                0x0,
                0x20000000,
                NonZeroUsize::new(MAX_NUM_INTERRUPTS as usize).unwrap(),
            ))
            .prepend(InterruptRemoveMutator::new());
        let mutator = StdScheduledMutator::new(mutators);
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr)?;
        println!("It stopped?");
        Ok(())
    };

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("Default"))
        .monitor(monitor)
        .run_client(run_client)
        .cores(&Cores::all().unwrap())
        .overcommit(1)
        .broker_port(1337)
        .build()
        .launch()
    {
        Ok(_) => println!("Launcher launched"),
        Err(e) => println!("Error while launching launcher: {:?}", e),
    }

    Ok(())
}

#[allow(non_snake_case, unused)]
pub fn start_fuzz_singlecore(mut fileinfo: FileInfo) -> Result<(), Box<dyn Error>> {
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
            Ok(EmuExit::Timeout) => ExitKind::Timeout,
            Ok(EmuExit::Ok) => ExitKind::Ok,
            Ok(EmuExit::Crash) => ExitKind::Crash,
            Err(uc_error) => ExitKind::Crash,
        }
    };
    // let monitor = SimpleMonitor::new(|s| println!("{s}"));
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
    let scheduler = QueueScheduler::new(); //IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());
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
    let mut generator = FuzzingInputGenerator::new(
        NonZeroUsize::new(0x1000).unwrap(),
        0x1000,
        0x2000,
        MAX_NUM_INTERRUPTS,
    );

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mapped_mutators = mapped_havoc_mutations(CombinedInput::bytes_mut, CombinedInput::bytes);
    let mutators = tuple_list!()
        .merge(mapped_mutators)
        .prepend(InterruptAddMutator::new(
            0x0,
            0x20000000,
            NonZeroUsize::new(MAX_NUM_INTERRUPTS as usize).unwrap(),
        ))
        .prepend(InterruptModifyMutator::new(
            0x0,
            0x20000000,
            NonZeroUsize::new(MAX_NUM_INTERRUPTS as usize).unwrap(),
        ))
        .prepend(InterruptRemoveMutator::new());
    let mutator = StdScheduledMutator::new(mutators);
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
    println!("It stopped?");
    Ok(())
}

pub fn run(fileinfo: FileInfo, fuzz: bool) -> Result<(), Box<dyn Error>> {
    if fuzz {
        //start_fuzz_singlecore(fileinfo).expect("Fuzzing failed");
        start_fuzz_multicore(fileinfo).expect("Fuzzing failed");
    } else {
        test_emulate(fileinfo).expect("Emulation failed");
    }
    Ok(())
}
