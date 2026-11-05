/*
 * Guest workload for the realistic-matrix blk test: mounts the ext4 disk
 * with a raw mount(2), writes 32 MiB to it, reports readiness and idles.
 *
 * The podman-exported rootfs this runs in carries foreign uids together
 * with setuid bits, so executing its /sbin/mount (setuid, owned by that
 * foreign uid) flips euid away from root and libmount's fsopen() fails
 * with EPERM even for root. Raw mount(2)/write(2) from this non-setuid
 * helper run as euid 0 and work. A properly-owned rootfs
 * (sudo chown -R 0:0, or any non-podman rootfs) would let /sbin/mount
 * work again.
 *
 * The readiness marker is only written after every step succeeded; a
 * failure prints its status line and idles, so the audit driver reports
 * the test as failed while guest-console.log shows why.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

#define CHUNK (1 << 20)
#define TOTAL (32 << 20)

static char chunk[CHUNK];

static int write_data(void)
{
    int fd = open("/mnt/data", O_WRONLY | O_CREAT | O_TRUNC, 0644);

    if (fd < 0) {
        printf("BLK-WRITE-FAILED: open /mnt/data: %s\n", strerror(errno));
        return -1;
    }
    for (size_t done = 0; done < TOTAL; done += CHUNK) {
        if (write(fd, chunk, CHUNK) != CHUNK) {
            printf("BLK-WRITE-FAILED: write: %s\n", strerror(errno));
            close(fd);
            return -1;
        }
    }
    if (fsync(fd) != 0) {
        printf("BLK-WRITE-FAILED: fsync: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int main(void)
{
    if (mount("/dev/vda", "/mnt", "ext4", 0, NULL) != 0) {
        printf("BLK-MOUNT-FAILED: mount /dev/vda: %s\n", strerror(errno));
    } else {
        printf("BLK-MOUNT-OK\n");
        if (write_data() == 0) {
            printf("BLK-WRITE-OK\n");
            fflush(stdout);
            write(STDOUT_FILENO, "AUDIT_GUEST_READY\n", 19);
        }
    }
    fflush(stdout);
    for (;;) {
        pause();
    }
}
