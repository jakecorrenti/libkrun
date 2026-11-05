/*
 * Experimental LD_PRELOAD shim for the resource-audit toolset: names every
 * anonymous mmap() and every large malloc()/calloc() after its caller, so a
 * kernel with CONFIG_ANON_VMA_NAME shows [anon:krun: ...] labels in smaps —
 * the same attribution the QEMU resource-audit article got by patching QEMU,
 * but without touching libkrun.
 *
 * Names must not contain '[' or ']' (the kernel reserves those for its own
 * [heap]/[stack] smaps pseudo-entries and rejects them), hence the unwrapped
 * "krun:" prefix; the kernel adds the [anon:...] display wrapper itself.
 * prctl failing is expected and silently ignored on kernels built without
 * CONFIG_ANON_VMA_NAME, where the shim is a harmless no-op — probe with
 * build/vma-probe to check.
 *
 * malloc()/calloc() labeling only names allocations whose containing VMA the
 * kernel left unnamed: arena-served and [heap] allocations are skipped (their
 * VMAs carry glibc's names or none), so in practice only mmap-served
 * allocations (>= glibc's mmap threshold) are named. Allocations at or above
 * KRUN_AUDIT_MALLOC_LABEL_KIB KiB (default 128) are labeled. MALLOC_MMAP_THRESHOLD_
 * is deliberately NOT set here: forcing more allocations through mmap (and
 * thus getting more labels) perturbs allocator behavior, so it is left as an
 * opt-in via the audit matrix's extra_env.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif

static void *(*real_mmap)(void *, size_t, int, int, int, off_t);
static void *(*real_malloc)(size_t);
static void *(*real_calloc)(size_t, size_t);
static size_t malloc_threshold = 128 * 1024;

/* dlsym may allocate while it is resolving the real allocators; those early
 * requests are served from this static bump heap (never freed, already
 * zeroed) instead of recursing. */
static char boot_heap[64 * 1024];
static size_t boot_heap_used;
static int in_dlsym;

static void *boot_alloc(size_t len)
{
    len = (len + 15) & ~(size_t)15;
    if (boot_heap_used + len > sizeof(boot_heap)) {
        return NULL;
    }
    void *p = boot_heap + boot_heap_used;
    boot_heap_used += len;
    return p;
}

static void resolve_real_fns(void)
{
    in_dlsym = 1;
    real_mmap = dlsym(RTLD_NEXT, "mmap");
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    in_dlsym = 0;
}

__attribute__((constructor))
static void shim_init(void)
{
    const char *kib = getenv("KRUN_AUDIT_MALLOC_LABEL_KIB");

    if (kib != NULL) {
        malloc_threshold = (size_t)strtoul(kib, NULL, 10) * 1024;
    }
    resolve_real_fns();
}

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

/* Find the unnamed VMA containing ptr. Everything on this path is stack
 * buffers and raw open/read — no stdio and no allocation. Returns 0 and
 * fills the VMA start and size when found and unnamed. */
static int find_unnamed_vma(void *ptr, unsigned long *vstart, size_t *vsize)
{
    char buf[4096];
    char line[512];
    size_t line_len = 0;
    int found = -1;
    int fd = open("/proc/self/maps", O_RDONLY);

    if (fd < 0) {
        return -1;
    }
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) {
            break;
        }
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] != '\n') {
                if (line_len < sizeof(line) - 1) {
                    line[line_len++] = buf[i];
                }
                continue;
            }
            line[line_len] = '\0';
            line_len = 0;

            unsigned long start, end, map_off, inode;
            unsigned int devmaj, devmin;
            char perms[5];
            int consumed = 0;
            if (sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %n",
                       &start, &end, perms, &map_off, &devmaj, &devmin,
                       &inode, &consumed) < 7) {
                continue;
            }
            if (ptr < (void *)start || ptr >= (void *)end) {
                continue;
            }
            const char *rest = line + consumed;
            while (*rest == ' ' || *rest == '\t') {
                rest++;
            }
            if (*rest == '\0') {
                *vstart = start;
                *vsize = end - start;
                found = 0;
            }
            goto out;
        }
    }
out:
    close(fd);
    return found;
}

static void label_allocation(void *ptr, size_t size, void *caller)
{
    unsigned long vstart;
    size_t vsize;
    Dl_info info;
    char name[80];
    const char *base;
    unsigned long off;

    if (find_unnamed_vma(ptr, &vstart, &vsize) != 0) {
        return;
    }
    if (dladdr(caller, &info) != 0 && info.dli_fname != NULL) {
        base = strrchr(info.dli_fname, '/');
        base = base != NULL ? base + 1 : info.dli_fname;
        off = (unsigned long)((char *)caller - (char *)info.dli_fbase);
        snprintf(name, sizeof(name), "krun: malloc %zuKiB from %s+0x%lx",
                 size / 1024, base, off);
    } else {
        snprintf(name, sizeof(name), "krun: malloc %zuKiB", size / 1024);
    }
    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, vstart, vsize,
          (unsigned long)name);
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
    if (real_mmap == NULL) {
        if (in_dlsym) {
            /* mmap from inside dlsym: serve it via the raw syscall, unnamed */
            return (void *)syscall(SYS_mmap, addr, len, prot, flags, fd, off);
        }
        resolve_real_fns();
    }
    void *ret = real_mmap(addr, len, prot, flags, fd, off);

    /* MAP_ANONYMOUS already implies "not backed by a file" on Linux; shared
     * anonymous mappings are left unnamed. */
    if (ret != MAP_FAILED && (flags & MAP_ANONYMOUS) != 0 && (flags & MAP_SHARED) == 0) {
        name_mapping(ret, len, __builtin_return_address(0));
    }
    return ret;
}

void *malloc(size_t size)
{
    if (real_malloc == NULL) {
        if (in_dlsym) {
            return boot_alloc(size);
        }
        resolve_real_fns();
    }
    void *ret = real_malloc(size);

    if (ret != NULL && size >= malloc_threshold) {
        label_allocation(ret, size, __builtin_return_address(0));
    }
    return ret;
}

void *calloc(size_t nmemb, size_t size)
{
    if (real_calloc == NULL) {
        if (in_dlsym) {
            return boot_alloc(nmemb * size);
        }
        resolve_real_fns();
    }
    void *ret = real_calloc(nmemb, size);

    if (ret != NULL && nmemb != 0 && nmemb * size >= malloc_threshold) {
        label_allocation(ret, nmemb * size, __builtin_return_address(0));
    }
    return ret;
}
