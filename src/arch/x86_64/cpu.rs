//! CPU feature, descriptor, interrupt, timer, and syscall initialization.

use super::{
    global_descriptor_table, interrupt_controller, interrupt_descriptor_table, interval_timer,
};
use x86_64::VirtAddr;

const EXTENDED_FEATURE_ENABLE_REGISTER: u32 = 0xc000_0080;
const SYSTEM_CALL_TARGET_ADDRESS_REGISTER: u32 = 0xc000_0081;
const LONG_SYSTEM_CALL_TARGET_ADDRESS_REGISTER: u32 = 0xc000_0082;
const SYSTEM_CALL_FLAG_MASK_REGISTER: u32 = 0xc000_0084;
const SYSTEM_CALL_ENABLE_BIT: u64 = 1;
const INTERRUPT_FLAG_BIT: u64 = 1 << 9;
const KERNEL_CODE_SELECTOR: u16 = 0x08;

/// Architecture-owned virtual address for the `SYSCALL` entry target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallEntryAddress(VirtAddr);

impl SyscallEntryAddress {
    /// Create a syscall entry address from the kernel's registered entry point.
    ///
    /// # Panics
    ///
    /// Panics if the function address cannot be represented as `u64`.
    pub fn from_function(function: unsafe extern "C" fn()) -> Self {
        let pointer = function as *const ();
        let address = u64::try_from(pointer.addr()).expect("syscall entry address must fit in u64");
        Self(VirtAddr::new(address))
    }

    /// Return the raw virtual address for the final architecture MSR boundary.
    pub fn as_u64(self) -> u64 {
        self.0.as_u64()
    }
}

/// Check if the CPU supports APIC.
#[allow(dead_code)]
pub fn has_apic() -> bool {
    let cpuid = core::arch::x86_64::__cpuid(1);
    (cpuid.edx & (1 << 9)) != 0
}

/// `x86_64` specific initialization.
pub fn init(system_call_handler: SyscallEntryAddress) {
    crate::log_info!("arch", "Initializing GDT...");
    global_descriptor_table::init();
    crate::log_info!("arch", "Initializing IDT...");
    interrupt_descriptor_table::initialize();
    crate::log_info!("arch", "Initializing SYSCALL...");
    init_syscall(system_call_handler);
    crate::log_info!(
        "arch",
        "Preferred interrupt controller: {:?}, IOAPIC routing: {} apic_provider_configured={}",
        interrupt_controller::get_preferred_kind(),
        interrupt_controller::has_ioapic_routing(),
        interrupt_controller::is_apic_routing_provider_configured()
    );
    // SAFETY: The interrupt controllers are initialized while interrupts are
    // disabled during early architecture setup.
    let legacy_pic_status =
        unsafe { interrupt_controller::initialize_interrupt_controller_backend() };
    crate::log_info!(
        "arch",
        "Interrupt controller backend initialized: legacy_pic_initialized={} legacy_fallback_enabled={} legacy_pic_masked_for_apic={} master_mask={:#x} slave_mask={:#x}",
        legacy_pic_status.is_initialized(),
        legacy_pic_status.is_fallback_enabled(),
        legacy_pic_status.is_masked_for_apic_routing(),
        legacy_pic_status.master_mask(),
        legacy_pic_status.slave_mask()
    );

    crate::log_info!(
        "arch",
        "Initializing PIT... preferred timer: {:?}, local APIC timer: {}",
        interval_timer::get_preferred_kind(),
        interval_timer::has_local_apic_timer()
    );
    interval_timer::initialize_programmable_interval_timer(crate::shared::TIMER_TICKS_PER_SECOND);
}

/// Initialize the `x86_64` `SYSCALL`/`SYSRET` model-specific registers.
pub fn init_syscall(handler: SyscallEntryAddress) {
    use x86_64::registers::model_specific::Msr;

    let mut extended_feature_enable_register = Msr::new(EXTENDED_FEATURE_ENABLE_REGISTER);
    let mut system_call_target_address_register = Msr::new(SYSTEM_CALL_TARGET_ADDRESS_REGISTER);
    let mut long_system_call_target_address_register =
        Msr::new(LONG_SYSTEM_CALL_TARGET_ADDRESS_REGISTER);
    let mut system_call_flag_mask_register = Msr::new(SYSTEM_CALL_FLAG_MASK_REGISTER);

    // SAFETY: The EFER MSR exists on x86_64 CPUs and setting SCE enables the
    // architectural SYSCALL/SYSRET path.
    let extended_features = unsafe { extended_feature_enable_register.read() };
    // SAFETY: The written value preserves all existing EFER bits and enables SCE.
    unsafe {
        extended_feature_enable_register.write(extended_features | SYSTEM_CALL_ENABLE_BIT);
    }

    let user_system_return_selector = global_descriptor_table::USER_CODE_SELECTOR.wrapping_sub(16);
    let system_call_segments =
        (u64::from(user_system_return_selector) << 48) | (u64::from(KERNEL_CODE_SELECTOR) << 32);
    // SAFETY: STAR is the architectural segment selector MSR for
    // SYSCALL/SYSRET, and the selectors refer to entries loaded in the GDT.
    unsafe {
        system_call_target_address_register.write(system_call_segments);
    }
    // SAFETY: LSTAR is the architectural 64-bit syscall entry target MSR, and
    // `handler` is provided by the kernel composition root.
    unsafe {
        long_system_call_target_address_register.write(handler.as_u64());
    }
    // SAFETY: SFMASK is the architectural syscall flags mask MSR; masking IF
    // disables interrupts on syscall entry.
    unsafe {
        system_call_flag_mask_register.write(INTERRUPT_FLAG_BIT);
    }
    crate::log_info!(
        "arch",
        "SYSCALL MSR initialized: lstar={:#x} syscall_entry_typed=true",
        handler.as_u64()
    );
}

/// Enable CPU interrupts after architecture and driver initialization.
pub fn enable_interrupts() {
    x86_64::instructions::interrupts::enable();
}

/// Disable CPU interrupts during architecture backend switching.
pub fn disable_interrupts() {
    x86_64::instructions::interrupts::disable();
}

/// Read the current `x86_64` timestamp counter value.
pub fn read_timestamp_counter() -> u64 {
    // SAFETY: RDTSC reads the processor timestamp counter and does not access
    // memory or require additional kernel invariants.
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[allow(dead_code)]
pub fn hlt_loop() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}
