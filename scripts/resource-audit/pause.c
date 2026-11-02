/*
 * Guest workload for the resource-audit runs.
 *
 * Prints a readiness marker on the console, then sleeps forever so the guest
 * stays quiescent while the host samples the harness process. Built static
 * by run-audit.sh so a NullFs guest needs no libraries of its own.
 */

#include <unistd.h>

int main(void)
{
    static const char marker[] = "AUDIT_GUEST_READY\n";

    write(STDOUT_FILENO, marker, sizeof(marker) - 1);
    for (;;) {
        pause();
    }
}
