/*
 * LD_PRELOAD shim for the resource-audit toolset: pauses at the
 * krun_vmm_run() boundary so the driver can sample the VMM-built state of
 * launchers we don't control (--wrap mode).
 *
 * Only works for launchers that call krun_vmm_run() through the PLT — i.e.
 * dynamically linked against libkrun, like examples/chroot_vm. Statically
 * linked or non-libkrun launchers never call this symbol, so the shim is
 * silently absent and the driver skips the pre-boot phase. Without
 * KRUN_AUDIT_PHASE_PAUSE set to a positive number of seconds it is a
 * pass-through.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void krun_vmm_run(void *vmm)
{
    static void (*real_run)(void *);
    const char *pause = getenv("KRUN_AUDIT_PHASE_PAUSE");
    int secs = pause ? atoi(pause) : 0;

    if (!real_run)
        real_run = (void (*)(void *))dlsym(RTLD_NEXT, "krun_vmm_run");
    if (secs > 0) {
        fprintf(stderr, "AUDIT_PHASE_VMM_BUILT\n");
        fflush(stderr);
        sleep(secs);
    }
    real_run(vmm);
}
