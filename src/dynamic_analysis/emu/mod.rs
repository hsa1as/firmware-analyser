#![allow(unused)]
// Input type
pub mod input;
use input::InputIterator;

// Unicorn imports
use unicorn_engine::unicorn_const::{
    uc_error, Arch, HookType, MemType, Mode, Permission, SECOND_SCALE,
};
use unicorn_engine::{ArmCpuModel, Context, RegisterARM, UcHookId, Unicorn};

// Hooks
pub mod hooks;
pub use hooks::common_hooks::{do_interrupt, CanUpdateMap};
pub use hooks::interrupt::{do_exc_entry, do_exc_return, ArmV7Nvic};

// Std
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
enum StopRequested {
    Interrupt,
    Crash,
    None,
}

#[derive(Debug)]
pub enum EmuExit {
    Timeout,
    Crash,
    Ok,
}

#[allow(dead_code)]
pub struct Emulator<'a, T: InputIterator> {
    uc: unicorn_engine::Unicorn<'a, T>,
    arch: Arch,
    mode: Mode,
    entry_point: u64,
    timeout: u64,
    count: u64,
    nvic: Rc<RefCell<ArmV7Nvic>>,
    stop_requested: Rc<RefCell<StopRequested>>,
    last_hook: Option<(UcHookId, u32)>,
}

impl<'a, T> Emulator<'a, T>
where
    T: InputIterator + CanUpdateMap,
{
    pub fn new(arch: Arch, mode: Mode, ud: T) -> Emulator<'a, T> {
        let uc_n = Unicorn::new_with_data(arch, mode, ud).expect("Unable to create uc emulator");
        Emulator {
            uc: uc_n,
            arch,
            mode,
            entry_point: 0,
            timeout: 10000,
            count: 0,
            nvic: Rc::new(RefCell::new(ArmV7Nvic::new())),
            stop_requested: Rc::new(RefCell::new(StopRequested::None)),
            last_hook: None,
        }
    }

    pub fn setup(&mut self, code: &mut Vec<u8>) -> Context {
        match self.arch {
            Arch::ARM => {
                // Setup CPU model through ctl_set_cpu_model
                self.uc
                    .ctl_set_cpu_model(ArmCpuModel::UC_CPU_ARM_CORTEX_M3 as i32)
                    .expect("Unable to set CPU Mode");

                // Setup sp and entry point
                let sp = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
                self.entry_point = u32::from_le_bytes([code[4], code[5], code[6], code[7]]) as u64;
                self.uc
                    .reg_write(RegisterARM::SP, sp as u64)
                    .expect("Failed to write sp");

                // Write code to memory
                self.uc
                    .mem_map(
                        0x0,
                        0x20000000,
                        Permission::READ | Permission::EXEC | Permission::WRITE,
                    )
                    .expect("Failed to map code section");
                self.uc
                    .mem_write(0, code.as_mut_slice())
                    .expect("Unable to write code");

                // Map remaining address space as rw
                self.uc
                    .mem_map(0x20000000, 0xF0000000, Permission::READ | Permission::WRITE)
                    .expect("Failed to map remaining addr space");
            }
            _ => unimplemented!(),
        }
        self.init_basic_hooks();
        self.uc
            .context_init()
            .expect("Unable to save initial unicorn ctx")
    }

    pub fn reset(&mut self, ctx: &Context) {
        self.uc
            .context_restore(ctx)
            .expect("Unable to restore uc to initial state");
    }
    // TODO: It may be possible to remove the Rc in Rc<RefCell<ArmV7Nvic>> and just have a pure RefCell
    // Have to fix lifetime annotations in the impl block for this
    fn init_basic_hooks(&mut self) {
        // Code hook for debug
        //#[cfg(feature = "debug")]
        //self.uc
        //    .add_code_hook(0, 0x1FFFFFFF, hooks::common_hooks::code_hook)
        //    .expect("Unable to add code hook");

        // We capture a lot of Rc clones in some closures for hooks here
        // But this is okay, and won't leak memory as all these hooks are static, and
        // are initialised only once and never removed. This could be a problem for interrupt hooks
        self.uc
            .add_block_hook(0, 0x1FFFFFFF, hooks::common_hooks::block_hook)
            .expect("Unable to add block hook");
        //self.uc.add_code_hook(0, 0x1FFFFFFF, hooks::common_hooks::code_hook)
        //  .expect("Unable to add code hook");
        self.uc
            .add_insn_invalid_hook(hooks::common_hooks::insn_invalid_hook)
            .expect("Unable to add invalid instruction hook");
        match self.arch {
            Arch::ARM => {
                // TOOD: make start_address tunable as memory maps change
                self.uc
                    .add_mem_hook(
                        HookType::MEM_ALL,
                        0x40000000,
                        0x60000000,
                        hooks::armv7_hooks::ARM_CORTEX_M3_PERIPHERAL_HOOK,
                    )
                    .expect("Unable to add peripheral hook for ARM");

                // Hook all invalid accesses till 0xF0000000
                // after 0xF0000000, EXC_RETURN is handled separately
                self.uc
                    .add_mem_hook(
                        HookType::MEM_INVALID,
                        0x20000000,
                        0xEFFFFFFF,
                        hooks::common_hooks::mem_hook,
                    )
                    .expect("Unable to add invalid mem access hook");

                // This is not needed as unicorn engine implements sw intr to intno 8 for exc_return
                self.uc
                    .add_mem_hook(
                        HookType::MEM_READ_PROT | HookType::MEM_WRITE_PROT,
                        0xF0000000,
                        0xFFFFFFFF,
                        hooks::common_hooks::mem_hook,
                    )
                    .expect("Unable to add invalid r/w hook to 0xF0000000+");

                // Add hook to handle writes to Armv7-NVIC registers
                let nvic_rc_nvic = self.nvic.clone(); // Create an RC clone
                                                      // closure
                let handle_nvic_acc = move |uc: &mut Unicorn<'_, T>,
                                            acc_type: MemType,
                                            loc: u64,
                                            sz: usize,
                                            val: i64|
                      -> bool {
                    let mut nvic_borr = (*nvic_rc_nvic).borrow_mut();
                    hooks::armv7_hooks::nvic_hook(uc, acc_type, loc, sz, val, &mut nvic_borr)
                };

                // Add hook to handle r/w to the ARM System control block registers
                let nvic_rc_scb = self.nvic.clone(); // Create an RC Clone
                let handle_scb_acc = move |uc: &mut Unicorn<'_, T>,
                                           acc_type: MemType,
                                           loc: u64,
                                           sz: usize,
                                           val: i64|
                      -> bool {
                    let mut nvic_borr = (*nvic_rc_scb).borrow_mut();
                    hooks::armv7_hooks::scb_hook(uc, acc_type, loc, sz, val, &mut nvic_borr)
                };

                self.uc
                    .add_mem_hook(HookType::MEM_ALL, 0xE000E100, 0xE000ECFC, handle_nvic_acc);

                // Setup EXC_RETURN hook, use intr_hook, interrupt number 8 as documented in unicorn
                // FAQ
                // fetch_prot hook is not required see : https://github.com/unicorn-engine/unicorn/blob/dev/docs/FAQ.md#how-to-emulate-interrupts-or-ticks-with-unicorn
                // Unicorn exposes software exception ( add_intr_hook ) with number 8 for handling exc_return
                // Example in unit tests
                let nvic_exc_ret = self.nvic.clone(); // Create an RC Clone
                let sw_intr_handle = move |uc: &mut unicorn_engine::Unicorn<'_, T>,
                                           intr_num: u32| {
                    #[cfg(feature = "debug")]
                    {
                        println!("Handling interrupt number: {}", intr_num);
                    }

                    if intr_num != 8 {
                        // This is a normal software interrupt, do not do an exc_return
                        return;
                    }

                    let nvic_borr = &mut *(*nvic_exc_ret).borrow_mut();

                    #[cfg(feature = "debug")]
                    {
                        println!("Handling EXC_RETURN");
                        println!("Current state of nvic: {:#?}", *nvic_borr);
                    }

                    // This is an exc_return, we have to handle it.
                    // Since this is an exc_return, we first deal with changes to the nvic structure
                    // remove the current irqn from the active list
                    let current_irqn = nvic_borr.get_current_irqn();
                    match current_irqn {
                        Some(irqn) => {
                            nvic_borr.exc_active(irqn, false);
                            nvic_borr.set_current_irqn(None);
                            // TODO: Change hardcoded MAX_PRIORITY_LEVEL here, it is 256 for 8
                            // priority bits
                            nvic_borr.set_current_prio(256);
                            // Set active count
                            nvic_borr.set_active_count(nvic_borr.get_active_count() - 1);
                            do_exc_return(uc);

                            #[cfg(feature = "debug")]
                            {
                                println!("Finished EXC_RETURN for irqn: {}", irqn);
                                println!("After exc_return: {:#?}", *nvic_borr);
                            }
                        }
                        None => {
                            // If this happens, it could be a bug
                            panic!("No current irqn set for exc_return");
                        }
                    }
                    // We could tail-chain some other pending exceptions
                    nvic_borr.maybe_activate_interrupt(uc);

                    // Add a hook to pend the next interrupt
                };
                self.uc
                    .add_intr_hook(sw_intr_handle)
                    .expect("Unable to add interrupt hook to handle EXC_RETURN for ARM");
            }
            _ => unimplemented!(),
        }
    }

    pub fn start_emu(&mut self) -> Result<EmuExit, uc_error> {
        // Schedule first interrupt to arrive
        self.schedule_next_interrupt();

        // Setup timers
        let mut now = Instant::now();
        let mut rem = self.timeout;

        // First step emulation
        let mut res = self
            .uc
            .emu_start(self.entry_point, 0x1FFFFFFF, rem, self.count as usize);

        let elapsed = now.elapsed().as_micros() as u64;
        rem = match rem.checked_sub(elapsed) {
            Some(v) => v,
            None => return Ok(EmuExit::Timeout),
        };

        // Delete last intr hook if it exists
        match self.last_hook {
            Some(v) => {
                self.uc.remove_hook(v.0);
                self.last_hook = None;
                self.uc.ctl_remove_cache(v.1 as u64, v.1 as u64 + 1);
                self.uc.set_pc(self.uc.pc_read().unwrap());
            }
            None => (),
        }
        let mut temp = self.stop_requested.borrow().clone();
        while let StopRequested::Interrupt = temp {
            // Change stop_requested status
            {
                let mut x = self.stop_requested.borrow_mut();
                *x = StopRequested::None;
            }

            // Check emulation run exit status
            match res {
                Ok(_) => (),
                Err(e) => return Err(e),
            };

            // Delete last intr hook if it exists
            match self.last_hook {
                Some(v) => {
                    self.uc.remove_hook(v.0);
                    self.last_hook = None;
                    self.uc.ctl_remove_cache(v.1 as u64, v.1 as u64 + 1);
                    self.uc.set_pc(self.uc.pc_read().unwrap());
                }
                None => (),
            }

            // Schedule next interrupt
            self.schedule_next_interrupt();

            // Restart emulation
            now = Instant::now();
            res = self
                .uc
                .emu_start(self.entry_point, 0x1FFFFFFF, rem, self.count as usize);
            let elapsed = now.elapsed().as_micros() as u64;
            rem = match rem.checked_sub(elapsed) {
                Some(v) => v,
                None => return Ok(EmuExit::Timeout),
            };

            // Check exit status
            temp = self.stop_requested.borrow().clone();
        }
        match res {
            Ok(_) => (),
            Err(e) => return Err(e),
        };
        match temp {
            StopRequested::Crash => Ok(EmuExit::Crash),
            StopRequested::None => Ok(EmuExit::Ok),
            StopRequested::Interrupt => panic!("Interrupt requested after emulation exit"),
        }
    }

    pub fn get_mut_data(&mut self) -> &mut T {
        self.uc.get_data_mut()
    }

    pub fn schedule_next_interrupt(&mut self) -> bool {
        // We will schedule an interrupt to be pended at addr, with intno: irqn
        // Next, we will check if this interrupt can be activated. If it can, do the
        // steps for activation
        //

        // Get UserData
        let ud = self.get_mut_data();

        // Get the next interrupt
        let (irqn, addr) = match ud.get_next_interrupt() {
            Ok(val) => val,
            Err(_) => return false,
        };

        #[cfg(feature = "debug")]
        {
            println!("Scheduling interrupt: {} at address: {:#08x}", irqn, addr);
        }

        let nvic_intr = self.nvic.clone();
        let stop_request_clone = self.stop_requested.clone();
        // Closure for the hook
        let mut intr_pend_hook = move |uc: &mut Unicorn<'_, T>, addr: u64, sz: u32| {
            #[cfg(feature = "debug")]
            {
                println!("Interrupt hook: Address = {:#08x}, Size = {}", addr, sz);
            }

            let mut nvic_borr = &mut *nvic_intr.borrow_mut();
            let mut stop_request_ref = stop_request_clone.borrow_mut();
            nvic_borr.exc_pend(irqn, true);

            #[cfg(feature = "debug")]
            {
                println!("After pend: {:#?}", *nvic_borr);
            }

            let active = nvic_borr.maybe_activate_interrupt(uc);

            // Stop emulation to schedule the next interrupt
            *stop_request_ref = StopRequested::Interrupt;

            #[cfg(feature = "debug")]
            {
                println!("Stopping emulation to schedule next interrupt");
            }

            uc.emu_stop().unwrap();
        };

        // Get hook ID
        let hook_id = self
            .uc
            .add_code_hook(addr as u64, addr as u64, intr_pend_hook)
            .unwrap();

        // Set hook id in the RefCell
        self.last_hook = Some((hook_id, addr));
        return true;
    }
}
