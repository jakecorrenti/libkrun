/*
 * Experimental LD_PRELOAD shim for the resource-audit toolset: names every
 * anonymous mmap() after its caller, so a kernel with CONFIG_ANON_VMA_NAME
 * shows [anon:krun: <soname>: <symbol>+0x<off>] labels in smaps — the same
 * attribution the QEMU resource-audit article got by patching QEMU, but
 * without touching libkrun.
 *
 * Names must not contain '[' or ']' (the kernel reserves those for its own
 * [heap]/[stack] smaps pseudo-entries and rejects them), hence the unwrapped
 * "krun:" prefix; the kernel adds the [anon:...] display wrapper itself.
 * prctl failing is expected and silently ignored on kernels built without
 * CONFIG_ANON_VMA_NAME, where the shim is a harmless no-op — probe with
 * build/vma-probe to check.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif

static void name_mapping(void *addr, size_t len, void *caller)
{
    Dl_info info;
    char name[80];
    const char *base;
    unsigned long off;

    if (dladdr(caller, &info) != 0 && info.dli_fname != NULL) {
        base = strrchr(info.dli_fname, '/');
        base = base != NULL ? base + 1 : info.dli_fname;
        if (info.dli_sname != NULL) {
            off = (unsigned long)((char *)caller - (char *)info.dli_saddr);
            snprintf(name, sizeof(name), "krun: %s: %s+0x%lx",
                     base, info.dli_sname, off);
        } else {
            off = (unsigned long)((char *)caller - (char *)info.dli_fbase);
            snprintf(name, sizeof(name), "krun: %s+0x%lx", base, off);
        }
    } else {
        snprintf(name, sizeof(name), "krun: mmap caller 0x%lx",
                 (unsigned long)caller);
    }

    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, (unsigned long)addr, len,
          (unsigned long)name);
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
    static void *(*real_mmap)(void *, size_t, int, int, int, off_t);

    if (real_mmap == NULL) {
        real_mmap = dlsym(RTLD_NEXT, "mmap");
    }
    void *ret = real_mmap(addr, len, prot, flags, fd, off);

    /* MAP_ANONYMOUS already implies "not backed by a file" on Linux; shared
     * anonymous mappings are left unnamed. */
    if (ret != MAP_FAILED && (flags & MAP_ANONYMOUS) != 0 && (flags & MAP_SHARED) == 0) {
        name_mapping(ret, len, __builtin_return_address(0));
    }
    return ret;
}
