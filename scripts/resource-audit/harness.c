/*
 * VM launcher for the libkrun resource-audit toolset (scripts/resource-audit).
 *
 * Boots one libkrun microVM with a configurable payload, root filesystem and
 * virtio device set, and runs it until the process is killed. Modeled on
 * examples/chroot_vm.c; run-audit.sh starts it in the background and samples
 * /proc while the guest runs.
 *
 * In nullfs root mode the guest workload is mapped read-only from the host
 * with --embed and exposed through the init overlay, so its pages stay
 * file-backed instead of being copied into the heap.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libkrun.h>
#include <libkrun_init.h>

#if defined(__linux__) && defined(__x86_64__)
#define KRUN_PCI_TRANSPORT_SUPPORTED 1
#else
#define KRUN_PCI_TRANSPORT_SUPPORTED 0
#endif

// Net feature flags mirrored from examples/chroot_vm.c.
#define COMPAT_NET_FEATURES ((1 << 0) | (1 << 1) | (1 << 7) | (1 << 10) | (1 << 11) | (1 << 14))

#define MAX_EMBEDS 64

#if defined(__x86_64__)
#define DEFAULT_KERNEL_FORMAT KRUN_KERNEL_FORMAT_ELF
#else
#define DEFAULT_KERNEL_FORMAT KRUN_KERNEL_FORMAT_RAW
#endif

struct embed_file {
    const char *guest_path;
    void *data;
    size_t len;
};

// Read-only mmaps of --embed files, kept for the whole process lifetime: the
// overlay borrows the pointers until the VM exits.
static struct embed_file embeds[MAX_EMBEDS];
static int embed_count;

enum transport_mode {
    TRANSPORT_MODE_MMIO = 0,
    TRANSPORT_MODE_PCI,
};

enum payload_mode {
    PAYLOAD_KRUNFW = 0,
    PAYLOAD_EXTERNAL,
    PAYLOAD_FIRMWARE,
};

enum root_fs_mode {
    ROOT_NULLFS = 0,
    ROOT_DIR,
};

struct devices {
    bool rng;
    bool balloon;
    bool vsock;
    bool blk;
    bool net;
};

struct cmdline {
    bool show_help;
    uint8_t vcpus;
    uint32_t ram_mib;
    enum transport_mode transport_mode;
    enum payload_mode payload_mode;
    enum root_fs_mode root_fs_mode;
    const char *kernel_path;
    uint32_t kernel_format;
    const char *initrd_path;
    const char *kernel_cmdline;
    const char *firmware_path;
    const char *append_cmdline;
    const char *root_dir;
    const char *workload;
    const char *blk_img;
    uint32_t blk_format;
    const char *net_socket;
    const char *log_path;
    unsigned int pause_before_run;
    struct devices devices;
    char *const *workload_args;
};

static void print_help(char *const name)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS] [-- WORKLOAD_ARGS...]\n"
        "\n"
        "Boots one libkrun microVM and runs it until killed. Arguments after\n"
        "-- are passed as workload arguments; the workload's argv[0] is the\n"
        "--workload path itself.\n"
        "\n"
        "OPTIONS:\n"
        "  -h, --help                      show this help\n"
        "      --vcpus=N                   number of vCPUs (default 1)\n"
        "      --ram-mib=N                 guest RAM in MiB (default 256)\n"
        "      --transport=MMIO|PCI        virtio transport (default MMIO; PCI is\n"
        "                                  x86_64 Linux only and enables ACPI)\n"
        "      --payload=KRUNFW|EXTERNAL|FIRMWARE\n"
        "                                  boot payload (default KRUNFW)\n"
        "      --kernel=PATH               EXTERNAL: kernel image\n"
        "      --kernel-format=ELF|RAW|PE-GZ|IMAGE-BZ2|IMAGE-GZ|IMAGE-ZSTD\n"
        "                                  EXTERNAL: kernel format (default ELF on\n"
        "                                  x86_64, RAW otherwise)\n"
        "      --initrd=PATH               EXTERNAL: initramfs\n"
        "      --cmdline=STR               EXTERNAL/FIRMWARE: full cmdline replacement\n"
        "      --firmware=PATH             FIRMWARE: firmware image\n"
        "      --append-cmdline=STR        extra cmdline appended to any payload\n"
        "      --root-mode=NULLFS|DIR      root filesystem (default NULLFS)\n"
        "      --root-dir=PATH             DIR: host directory shared as root\n"
        "      --workload=PATH             guest path of the init workload\n"
        "                                  (default /pause)\n"
        "      --embed=HOST:GUEST          NULLFS: map HOST read-only into the guest\n"
        "                                  at GUEST (repeatable)\n"
        "      --devices=LIST              comma-separated subset of\n"
        "                                  console,rng,balloon,vsock,blk,net\n"
        "                                  (default console; console is always added)\n"
        "      --blk-img=PATH              BLK: disk image\n"
        "      --blk-format=RAW|QCOW2|VMDK BLK: disk format (default RAW)\n"
        "      --net-socket=PATH           NET: passt unix stream socket path\n"
        "      --log=PATH                  write the libkrun log to PATH\n"
        "      --pause-before-run=SECS     after the VM is built, print\n"
        "                                  AUDIT_PHASE_VMM_BUILT to stderr and\n"
        "                                  sleep SECS before running the guest\n"
        "\n"
        "FIRMWARE payloads boot the firmware itself: no init configuration,\n"
        "root filesystem or workload is set up.\n",
        name);
}

static bool push_to_stderr(void *userdata, KrunStr s)
{
    (void)userdata;
    fwrite(s.data, 1, s.len, stderr);
    return true;
}

// CHECK_INIT macro for init-blob errors (KrunInitError)
static KrunVtableHandle stderr_writer = KRUN_VTABLE_HANDLE(
    KRUN_INIT_PUSH_STR_TYPE_TAG,
    ((KrunInitPushStrVtable){ .drop = NULL, .push = push_to_stderr }),
    NULL);

#define CHECK_INIT(call)                                                       \
    err = NULL;                                                                \
    call;                                                                      \
    if (err) {                                                                 \
        flockfile(stderr);                                                     \
        fprintf(stderr, "%s failed: ", #call);                                 \
        krun_init_error_message(err, &stderr_writer);                          \
        fputc('\n', stderr);                                                   \
        funlockfile(stderr);                                                   \
        krun_init_error_destroy(err);                                          \
        return -1;                                                             \
    }

// CHECK macro for libkrun errors (KrunError)
static KrunVtableHandle krun_stderr_writer = KRUN_VTABLE_HANDLE(
    KRUN_PUSH_STR_TYPE_TAG,
    ((KrunPushStrVtable){ .drop = NULL, .push = push_to_stderr }),
    NULL);

#define CHECK(call)                                                            \
    krun_err = NULL;                                                           \
    call;                                                                      \
    if (krun_err) {                                                            \
        flockfile(stderr);                                                     \
        fprintf(stderr, "%s failed: ", #call);                                 \
        krun_error_message(krun_err, &krun_stderr_writer);                     \
        fputc('\n', stderr);                                                   \
        funlockfile(stderr);                                                   \
        krun_error_destroy(krun_err);                                          \
        return -1;                                                             \
    }

enum {
    OPT_VCPUS = 1000,
    OPT_RAM_MIB,
    OPT_TRANSPORT,
    OPT_PAYLOAD,
    OPT_KERNEL,
    OPT_KERNEL_FORMAT,
    OPT_INITRD,
    OPT_CMDLINE,
    OPT_FIRMWARE,
    OPT_APPEND_CMDLINE,
    OPT_ROOT_MODE,
    OPT_ROOT_DIR,
    OPT_WORKLOAD,
    OPT_EMBED,
    OPT_DEVICES,
    OPT_BLK_IMG,
    OPT_BLK_FORMAT,
    OPT_NET_SOCKET,
    OPT_LOG,
    OPT_PAUSE_BEFORE_RUN,
};

static const struct option long_options[] = {
    { "help", no_argument, NULL, 'h' },
    { "vcpus", required_argument, NULL, OPT_VCPUS },
    { "ram-mib", required_argument, NULL, OPT_RAM_MIB },
    { "transport", required_argument, NULL, OPT_TRANSPORT },
    { "payload", required_argument, NULL, OPT_PAYLOAD },
    { "kernel", required_argument, NULL, OPT_KERNEL },
    { "kernel-format", required_argument, NULL, OPT_KERNEL_FORMAT },
    { "initrd", required_argument, NULL, OPT_INITRD },
    { "cmdline", required_argument, NULL, OPT_CMDLINE },
    { "firmware", required_argument, NULL, OPT_FIRMWARE },
    { "append-cmdline", required_argument, NULL, OPT_APPEND_CMDLINE },
    { "root-mode", required_argument, NULL, OPT_ROOT_MODE },
    { "root-dir", required_argument, NULL, OPT_ROOT_DIR },
    { "workload", required_argument, NULL, OPT_WORKLOAD },
    { "embed", required_argument, NULL, OPT_EMBED },
    { "devices", required_argument, NULL, OPT_DEVICES },
    { "blk-img", required_argument, NULL, OPT_BLK_IMG },
    { "blk-format", required_argument, NULL, OPT_BLK_FORMAT },
    { "net-socket", required_argument, NULL, OPT_NET_SOCKET },
    { "log", required_argument, NULL, OPT_LOG },
    { "pause-before-run", required_argument, NULL, OPT_PAUSE_BEFORE_RUN },
    { NULL, 0, NULL, 0 }
};

static bool parse_num(const char *s, unsigned long max, unsigned long *out)
{
    char *end;
    unsigned long value;

    if (s == NULL || *s == '\0') {
        return false;
    }
    errno = 0;
    value = strtoul(s, &end, 10);
    if (errno != 0 || *end != '\0' || value > max) {
        return false;
    }
    *out = value;
    return true;
}

static bool parse_transport(const char *s, enum transport_mode *out)
{
    if (strcasecmp(s, "mmio") == 0) {
        *out = TRANSPORT_MODE_MMIO;
        return true;
    }
    if (strcasecmp(s, "pci") == 0) {
#if KRUN_PCI_TRANSPORT_SUPPORTED
        *out = TRANSPORT_MODE_PCI;
        return true;
#else
        fprintf(stderr, "PCI transport is only supported on x86_64 Linux\n");
        return false;
#endif
    }
    return false;
}

static bool parse_payload_mode(const char *s, enum payload_mode *out)
{
    if (strcasecmp(s, "krunfw") == 0) {
        *out = PAYLOAD_KRUNFW;
    } else if (strcasecmp(s, "external") == 0) {
        *out = PAYLOAD_EXTERNAL;
    } else if (strcasecmp(s, "firmware") == 0) {
        *out = PAYLOAD_FIRMWARE;
    } else {
        return false;
    }
    return true;
}

static bool parse_root_fs_mode(const char *s, enum root_fs_mode *out)
{
    if (strcasecmp(s, "nullfs") == 0) {
        *out = ROOT_NULLFS;
    } else if (strcasecmp(s, "dir") == 0) {
        *out = ROOT_DIR;
    } else {
        return false;
    }
    return true;
}

static bool parse_kernel_format(const char *s, uint32_t *out)
{
    if (strcasecmp(s, "elf") == 0) {
        *out = KRUN_KERNEL_FORMAT_ELF;
    } else if (strcasecmp(s, "raw") == 0) {
        *out = KRUN_KERNEL_FORMAT_RAW;
    } else if (strcasecmp(s, "pe-gz") == 0) {
        *out = KRUN_KERNEL_FORMAT_PE_GZ;
    } else if (strcasecmp(s, "image-bz2") == 0) {
        *out = KRUN_KERNEL_FORMAT_IMAGE_BZ2;
    } else if (strcasecmp(s, "image-gz") == 0) {
        *out = KRUN_KERNEL_FORMAT_IMAGE_GZ;
    } else if (strcasecmp(s, "image-zstd") == 0) {
        *out = KRUN_KERNEL_FORMAT_IMAGE_ZSTD;
    } else {
        return false;
    }
    return true;
}

static bool parse_blk_format(const char *s, uint32_t *out)
{
    if (strcasecmp(s, "raw") == 0) {
        *out = KRUN_DISK_FORMAT_RAW;
    } else if (strcasecmp(s, "qcow2") == 0) {
        *out = KRUN_DISK_FORMAT_QCOW2;
    } else if (strcasecmp(s, "vmdk") == 0) {
        *out = KRUN_DISK_FORMAT_VMDK;
    } else {
        return false;
    }
    return true;
}

static bool parse_devices(const char *list, struct cmdline *cmdline)
{
    char *copy = strdup(list);
    char *saveptr = NULL;
    char *token;

    if (copy == NULL) {
        perror("strdup");
        return false;
    }
    for (token = strtok_r(copy, ",", &saveptr); token != NULL;
         token = strtok_r(NULL, ",", &saveptr)) {
        // The console is always configured; accept the token as a no-op.
        if (strcmp(token, "console") == 0) {
            continue;
        } else if (strcmp(token, "rng") == 0) {
            cmdline->devices.rng = true;
        } else if (strcmp(token, "balloon") == 0) {
            cmdline->devices.balloon = true;
        } else if (strcmp(token, "vsock") == 0) {
            cmdline->devices.vsock = true;
        } else if (strcmp(token, "blk") == 0) {
            cmdline->devices.blk = true;
        } else if (strcmp(token, "net") == 0) {
            cmdline->devices.net = true;
        } else {
            fprintf(stderr, "Unknown device '%s'\n", token);
            free(copy);
            return false;
        }
    }
    free(copy);
    return true;
}

static bool add_embed(const char *spec)
{
    const char *colon = strchr(spec, ':');
    const char *guest_path;
    struct embed_file *embed;
    struct stat st;
    char *host_path;
    size_t host_len;
    int fd;

    if (colon == NULL || colon == spec || colon[1] == '\0') {
        fprintf(stderr, "--embed expects HOST_PATH:GUEST_PATH, got '%s'\n", spec);
        return false;
    }
    if (embed_count >= MAX_EMBEDS) {
        fprintf(stderr, "Too many --embed arguments (max %d)\n", MAX_EMBEDS);
        return false;
    }

    host_len = (size_t)(colon - spec);
    host_path = strndup(spec, host_len);
    if (host_path == NULL) {
        perror("strndup");
        return false;
    }
    guest_path = colon + 1;

    fd = open(host_path, O_RDONLY);
    if (fd < 0) {
        perror(host_path);
        free(host_path);
        return false;
    }
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        free(host_path);
        return false;
    }
    if (!S_ISREG(st.st_mode) || st.st_size == 0) {
        fprintf(stderr, "%s: not a non-empty regular file\n", host_path);
        close(fd);
        free(host_path);
        return false;
    }

    embed = &embeds[embed_count];
    // PROT_READ | MAP_PRIVATE keeps the pages file-backed (shareable page
    // cache, no heap copy). Intentionally never unmapped: the overlay
    // borrows the pointer for the lifetime of the process.
    embed->data = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (embed->data == MAP_FAILED) {
        perror("mmap");
        close(fd);
        free(host_path);
        return false;
    }
    embed->len = (size_t)st.st_size;
    embed->guest_path = guest_path;
    embed_count++;

    close(fd);
    free(host_path);
    return true;
}

bool parse_cmdline(int argc, char *const argv[], struct cmdline *cmdline)
{
    unsigned long num;
    int option_index = 0;
    int c;

    // set the defaults
    *cmdline = (struct cmdline){
        .show_help = false,
        .vcpus = 1,
        .ram_mib = 256,
        .transport_mode = TRANSPORT_MODE_MMIO,
        .payload_mode = PAYLOAD_KRUNFW,
        .root_fs_mode = ROOT_NULLFS,
        .kernel_path = NULL,
        .kernel_format = DEFAULT_KERNEL_FORMAT,
        .initrd_path = NULL,
        .kernel_cmdline = NULL,
        .firmware_path = NULL,
        .append_cmdline = NULL,
        .root_dir = NULL,
        .workload = "/pause",
        .blk_img = NULL,
        .blk_format = KRUN_DISK_FORMAT_RAW,
        .net_socket = NULL,
        .log_path = NULL,
        .pause_before_run = 0,
        .devices = { 0 },
        .workload_args = NULL,
    };

    // the '+' in optstring is a GNU extension that disables permutating argv
    while ((c = getopt_long(argc, argv, "+h", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmdline->show_help = true;
            return true;
        case OPT_VCPUS:
            if (!parse_num(optarg, 255, &num)) {
                fprintf(stderr, "Invalid --vcpus value '%s'\n", optarg);
                return false;
            }
            cmdline->vcpus = (uint8_t)num;
            break;
        case OPT_RAM_MIB:
            if (!parse_num(optarg, UINT32_MAX, &num)) {
                fprintf(stderr, "Invalid --ram-mib value '%s'\n", optarg);
                return false;
            }
            cmdline->ram_mib = (uint32_t)num;
            break;
        case OPT_TRANSPORT:
            if (!parse_transport(optarg, &cmdline->transport_mode)) {
                fprintf(stderr, "Unknown transport mode '%s'\n", optarg);
                return false;
            }
            break;
        case OPT_PAYLOAD:
            if (!parse_payload_mode(optarg, &cmdline->payload_mode)) {
                fprintf(stderr, "Unknown payload '%s'\n", optarg);
                return false;
            }
            break;
        case OPT_KERNEL:
            cmdline->kernel_path = optarg;
            break;
        case OPT_KERNEL_FORMAT:
            if (!parse_kernel_format(optarg, &cmdline->kernel_format)) {
                fprintf(stderr, "Unknown kernel format '%s'\n", optarg);
                return false;
            }
            break;
        case OPT_INITRD:
            cmdline->initrd_path = optarg;
            break;
        case OPT_CMDLINE:
            cmdline->kernel_cmdline = optarg;
            break;
        case OPT_FIRMWARE:
            cmdline->firmware_path = optarg;
            break;
        case OPT_APPEND_CMDLINE:
            cmdline->append_cmdline = optarg;
            break;
        case OPT_ROOT_MODE:
            if (!parse_root_fs_mode(optarg, &cmdline->root_fs_mode)) {
                fprintf(stderr, "Unknown root mode '%s'\n", optarg);
                return false;
            }
            break;
        case OPT_ROOT_DIR:
            cmdline->root_dir = optarg;
            break;
        case OPT_WORKLOAD:
            cmdline->workload = optarg;
            break;
        case OPT_EMBED:
            if (!add_embed(optarg)) {
                return false;
            }
            break;
        case OPT_DEVICES:
            if (!parse_devices(optarg, cmdline)) {
                return false;
            }
            break;
        case OPT_BLK_IMG:
            cmdline->blk_img = optarg;
            break;
        case OPT_BLK_FORMAT:
            if (!parse_blk_format(optarg, &cmdline->blk_format)) {
                fprintf(stderr, "Unknown blk format '%s'\n", optarg);
                return false;
            }
            break;
        case OPT_NET_SOCKET:
            cmdline->net_socket = optarg;
            break;
        case OPT_LOG:
            cmdline->log_path = optarg;
            break;
        case OPT_PAUSE_BEFORE_RUN:
            if (!parse_num(optarg, 65535, &num)) {
                fprintf(stderr, "Invalid --pause-before-run value '%s'\n", optarg);
                return false;
            }
            cmdline->pause_before_run = (unsigned int)num;
            break;
        case '?':
            return false;
        default:
            fprintf(stderr, "internal argument parsing error (returned character code 0x%x)\n", c);
            return false;
        }
    }

    cmdline->workload_args = &argv[optind];

    if (cmdline->payload_mode == PAYLOAD_EXTERNAL && cmdline->kernel_path == NULL) {
        fprintf(stderr, "--payload=external requires --kernel\n");
        return false;
    }
    if (cmdline->payload_mode == PAYLOAD_FIRMWARE && cmdline->firmware_path == NULL) {
        fprintf(stderr, "--payload=firmware requires --firmware\n");
        return false;
    }
    if (cmdline->payload_mode == PAYLOAD_FIRMWARE && cmdline->workload_args[0] != NULL) {
        fprintf(stderr, "workload arguments are not supported with --payload=firmware\n");
        return false;
    }
    if (cmdline->root_fs_mode == ROOT_DIR && cmdline->root_dir == NULL) {
        fprintf(stderr, "--root-mode=dir requires --root-dir\n");
        return false;
    }
    if (cmdline->root_fs_mode == ROOT_NULLFS && cmdline->root_dir != NULL) {
        fprintf(stderr, "--root-dir is only valid with --root-mode=dir\n");
        return false;
    }
    if (embed_count > 0 && cmdline->payload_mode == PAYLOAD_FIRMWARE) {
        fprintf(stderr, "--embed is not supported with --payload=firmware\n");
        return false;
    }
    if (embed_count > 0 && cmdline->root_fs_mode != ROOT_NULLFS) {
        fprintf(stderr, "--embed requires --root-mode=nullfs\n");
        return false;
    }
    if (cmdline->devices.blk && cmdline->blk_img == NULL) {
        fprintf(stderr, "device blk requires --blk-img\n");
        return false;
    }
    if (cmdline->devices.net && cmdline->net_socket == NULL) {
        fprintf(stderr, "device net requires --net-socket\n");
        return false;
    }

    return true;
}

static KrunDeviceManager virtio_devices_new(enum transport_mode transport_mode)
{
#if KRUN_PCI_TRANSPORT_SUPPORTED
    if (transport_mode == TRANSPORT_MODE_PCI) {
        return krun_pci_device_manager_new();
    }
#else
    (void)transport_mode;
#endif
    return krun_mmio_device_manager_new();
}

int main(int argc, char *const argv[])
{
    KrunError krun_err;
    KrunInitError err;
    struct rlimit rlim;
    struct cmdline cmdline;
    KrunPayload payload;
    KrunFsOverlay overlay;
    // Kept alive (never destroyed): the overlay and payload borrow from the
    // init config until the VM exits — see include/libkrun_init.h.
    KrunInitConfig init_config = NULL;
    KrunDeviceManager devices;
    KrunVmmBuilder builder;
    int log_target = -1;
    int i;

    if (!parse_cmdline(argc, argv, &cmdline)) {
        putchar('\n');
        print_help(argv[0]);
        return -1;
    }

    if (cmdline.show_help) {
        print_help(argv[0]);
        return 0;
    }

    if (cmdline.log_path != NULL) {
        log_target = open(cmdline.log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (log_target < 0) {
            perror(cmdline.log_path);
            return -1;
        }
    }

    // Set the log level to "warn".
    CHECK(krun_init_log(log_target, KRUN_LOG_LEVEL_WARN, KRUN_LOG_STYLE_AUTO, 0, &krun_err));

    // Load the boot payload.
    switch (cmdline.payload_mode) {
    case PAYLOAD_EXTERNAL:
        payload = krun_payload_load_external(KRUN_STR(cmdline.kernel_path),
                                             cmdline.kernel_format,
                                             KRUN_STR(cmdline.initrd_path),
                                             KRUN_STR(cmdline.kernel_cmdline ? cmdline.kernel_cmdline : ""),
                                             &krun_err);
        break;
    case PAYLOAD_FIRMWARE:
        payload = krun_payload_load_firmware(KRUN_STR(cmdline.firmware_path),
                                             KRUN_STR(cmdline.kernel_cmdline ? cmdline.kernel_cmdline : ""),
                                             &krun_err);
        break;
    default:
        payload = krun_payload_load_krunfw(&krun_err);
        break;
    }
    if (payload == NULL) {
        fprintf(stderr, "Error loading payload\n");
        if (krun_err != NULL) {
            krun_error_message(krun_err, &krun_stderr_writer);
            fputc('\n', stderr);
            krun_error_destroy(krun_err);
        }
        return -1;
    }

    // Create the filesystem overlay for init-blob and workload injection.
    overlay = krun_fs_overlay_new();

    // Build the init configuration (executable, args, workdir) and apply it
    // to the overlay and the payload.
    if (cmdline.payload_mode != PAYLOAD_FIRMWARE) {
        KrunInitBuilder init_builder = krun_init_config_builder();

        krun_init_builder_arg(&init_builder, KRUN_STR(cmdline.workload));
        for (i = 0; cmdline.workload_args[i]; i++)
            krun_init_builder_arg(&init_builder, KRUN_STR(cmdline.workload_args[i]));
        krun_init_builder_workdir(&init_builder, KRUN_STR("/"));

        init_config = krun_init_builder_build(&init_builder);
        CHECK_INIT(krun_init_config_apply(init_config, overlay, payload, &err));

        // A NullFs root starts empty; the guest init needs these mount points.
        if (cmdline.root_fs_mode == ROOT_NULLFS) {
            CHECK(krun_fs_overlay_add_dir(overlay, KRUN_STR("dev"), 0755, &krun_err));
            CHECK(krun_fs_overlay_add_dir(overlay, KRUN_STR("proc"), 0755, &krun_err));
            CHECK(krun_fs_overlay_add_dir(overlay, KRUN_STR("sys"), 0755, &krun_err));
        }

        for (i = 0; i < embed_count; i++) {
            KrunBytes bytes = { .data = embeds[i].data, .len = embeds[i].len };
            CHECK(krun_fs_overlay_add_file(overlay, KRUN_STR(embeds[i].guest_path),
                                           bytes, 0755, false, &krun_err));
        }
    }

    if (cmdline.append_cmdline != NULL) {
        krun_payload_append_cmdline(payload, KRUN_STR(cmdline.append_cmdline));
    }

    // Create the device manager.
    devices = virtio_devices_new(cmdline.transport_mode);

    // Configure the console (always present; harness stdio is the console).
    {
        KrunConsoleBuilder cb = krun_console_device_builder();
        CHECK(krun_console_builder_add_default_console(cb, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, &krun_err));
        KrunConsoleDevice console = krun_console_builder_build(cb, &krun_err);
        krun_device_manager_add(devices, console);
    }

    if (cmdline.payload_mode != PAYLOAD_FIRMWARE) {
        // Raise RLIMIT_NOFILE to the maximum allowed to create some room for virtio-fs
        getrlimit(RLIMIT_NOFILE, &rlim);
        rlim.rlim_cur = rlim.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rlim);

        // Configure the root filesystem via virtiofs.
        if (cmdline.root_fs_mode == ROOT_DIR) {
            CHECK(KrunFsDevice rootfs = krun_fs_device_new(KRUN_STR("/dev/root"), KRUN_STR(cmdline.root_dir), &krun_err));
            krun_fs_device_set_overlay(rootfs, overlay);
            krun_device_manager_add(devices, rootfs);
        } else {
            CHECK(KrunFsDevice rootfs = krun_fs_device_new_null(KRUN_STR("/dev/root"), &krun_err));
            krun_fs_device_set_overlay(rootfs, overlay);
            krun_device_manager_add(devices, rootfs);
        }
    }

    if (cmdline.devices.blk) {
        CHECK(KrunBlockDevice blk = krun_block_device_new(KRUN_STR("blk0"),
            KRUN_STR(cmdline.blk_img), cmdline.blk_format, &krun_err));
        krun_device_manager_add(devices, blk);
    }

    if (cmdline.devices.net) {
        uint8_t mac[] = {0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee};
        CHECK(KrunNetDevice net = krun_net_device_new_unixstream_path(KRUN_STR("net0"),
            KRUN_STR(cmdline.net_socket), KRUN_BYTES(mac), COMPAT_NET_FEATURES, 0, &krun_err));
        krun_device_manager_add(devices, net);
    }

    if (cmdline.devices.vsock) {
        CHECK(KrunVsockDevice vsock = krun_vsock_device_new(3, KRUN_TSI_FLAGS_HIJACK_INET | KRUN_TSI_FLAGS_HIJACK_UNIX, &krun_err));
        krun_device_manager_add(devices, vsock);
    }

    if (cmdline.devices.rng) {
        CHECK(KrunRngDevice rng = krun_rng_device_new(&krun_err));
        krun_device_manager_add(devices, rng);
    }

    if (cmdline.devices.balloon) {
        CHECK(KrunBalloonDevice balloon = krun_balloon_device_new(&krun_err));
        krun_device_manager_add(devices, balloon);
    }

    // Build the VM.
    builder = krun_vmm_builder_new();
    CHECK(krun_vmm_builder_vcpus(&builder, cmdline.vcpus, &krun_err));
    CHECK(krun_vmm_builder_ram_mib(&builder, cmdline.ram_mib, &krun_err));
    krun_vmm_builder_payload(&builder, payload);
    krun_vmm_builder_devices(&builder, devices);
    CHECK(krun_vmm_builder_split_irqchip(&builder, false, &krun_err));
#if defined(__x86_64__)
    CHECK(krun_vmm_builder_acpi(&builder,
        cmdline.transport_mode == TRANSPORT_MODE_PCI, &krun_err));
#endif

    CHECK(KrunVmm vmm = krun_vmm_builder_build(&builder, &krun_err));

    if (cmdline.pause_before_run > 0) {
        // Phase marker for the audit driver: everything above is built (KVM
        // VM, devices, guest RAM, kernel inserted), the guest has not
        // executed yet.
        fprintf(stderr, "AUDIT_PHASE_VMM_BUILT\n");
        fflush(stderr);
        sleep(cmdline.pause_before_run);
    }
    krun_vmm_run(vmm); // never returns

    // Not reached.
    return 0;
}
