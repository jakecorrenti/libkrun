/*
 * Functional probe for CONFIG_ANON_VMA_NAME, used by run-audit.sh's meta.txt:
 * neither /boot/config-$(uname -r) nor /proc/config.gz is guaranteed to exist,
 * so ask the kernel directly. Exit status: 0 supported, 1 prctl refused
 * (kernel built without the option, or the name was rejected), 2 mmap failed.
 *
 * The name must not contain '[' or ']' — the kernel reserves those for its
 * own [heap]/[stack] smaps pseudo-entries.
 */

#include <errno.h>
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

int main(void)
{
    size_t len = 4096;
    void *page = mmap(NULL, len, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (page == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    if (prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, (unsigned long)page,
              len, (unsigned long)"krun-audit-probe") != 0) {
        printf("anonymous map labels NOT supported (prctl: %s)\n",
               strerror(errno));
        return 1;
    }
    printf("anonymous map labels supported\n");
    return 0;
}
