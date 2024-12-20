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

#[allow(dead_code)]
pub struct Emulator<'a, T: InputIterator> {
    uc: unicorn_engine::Unicorn<'a, T>,
    arch: Arch,
    mode: Mode,
    entry_point: u64,
    timeout: u64,
    count: u64,
    nvic: Rc<RefCell<ArmV7Nvic>>,
    hook_list: Vec<UcHookId>,
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
            timeout: 2,
            count: 0,
            nvic: Rc::new(RefCell::new(ArmV7Nvic::new())),
            hook_list: Vec::new(),
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
                    if intr_num != 8 {
                        // This is a normal software interrupt, do not do an exc_return
                        return;
                    }
                    let nvic_borr = &mut *(*nvic_exc_ret).borrow_mut();
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
                        }
                        None => {
                            // If this happens, it could be a bug
                            panic!("No current irqn set for exc_return");
                        }
                    }
                };
                self.uc
                    .add_intr_hook(sw_intr_handle)
                    .expect("Unable to add interrupt hook to handle EXC_RETURN for ARM");

                // Schedule the first interrupt to arrive
                self.schedule_next_interrupt();
            }
            _ => unimplemented!(),
        }
    }

    pub fn start_emu(&mut self) -> Result<(), uc_error> {
        self.uc.emu_start(
            self.entry_point,
            0x1FFFFFFF,
            self.timeout * SECOND_SCALE,
            self.count as usize,
        )
    }

    pub fn get_mut_data(&mut self) -> &mut T {
        self.uc.get_data_mut()
    }

    pub fn schedule_next_interrupt(&mut self) {}

    pub fn schedule_one_interrupt(&mut self, addr: u32, irqn: u32) {
        // We will schedule an interrupt to be pended at addr, with intno: irqn
        // Next, we will check if this interrupt can be activated. If it can, do the
        // steps for activation
        //
        let nvic_intr = self.nvic.clone();
        let mut intr_harness = move |uc: &mut Unicorn<'_, T>, addr: u64, sz: u32| {
            let mut nvic_borr = &mut *nvic_intr.borrow_mut();
            nvic_borr.exc_pend(irqn, true);
            nvic_borr.maybe_activate_interrupt(uc);
        };
        let hook_id = self
            .uc
            .add_code_hook(addr as u64, addr as u64, intr_harness);
        // Set hook id in the RefCell
    }

    pub fn do_pending_interrupt(&mut self) {
        let mut nvic_borr = &mut *self.nvic.borrow_mut();
        let irqn = nvic_borr.get_vectpending();
        if irqn == 0 {
            return;
        }
        let prio = nvic_borr.get_prio(irqn as usize);
        nvic_borr.exc_active(irqn, true);
        nvic_borr.exc_pend(irqn, false);
        nvic_borr.set_current_irqn(Some(irqn));
        nvic_borr.set_current_prio(prio);
        nvic_borr.set_active_count(nvic_borr.get_active_count() + 1);
        do_exc_entry(&mut self.uc, irqn);
    }
}
