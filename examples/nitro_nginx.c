/*
 * AWS Nitro enclave example: Fedora rootfs with nginx serving HTTPS "hello world".
 * The guest virtio-net TAP is assigned 172.31.10.83/24 (see aws-nitro init).
 * From the host (with passt): curl -k https://172.31.10.83/
 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <libkrun.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void print_help(char *const name)
{
    fprintf(
        stderr,
        "Usage: %s NEWROOT NVCPUS RAM_MIB\n"
        "OPTIONS:\n"
        "        -h, --help     Show help\n"
        "        -n, --net      Enable networking with passt (default: on)\n"
        "        -N, --no-net   Disable networking\n"
        "        -d, --debug    Kernel and initramfs debug output\n"
        "\n"
        "Build rootfs:  make -C examples rootfs-nginx-https\n"
        "Host test:     curl -k https://172.31.10.83/\n",
        name);
}

static const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"net", no_argument, NULL, 'n'},
    {"no-net", no_argument, NULL, 'N'},
    {"debug", no_argument, NULL, 'd'},
    {NULL, 0, NULL, 0},
};

struct cmdline {
    bool show_help;
    const char *new_root;
    unsigned int nvcpus;
    unsigned int ram_mib;
    bool net;
    bool debug;
};

static bool parse_cmdline(int argc, char *const argv[], struct cmdline *cmdline)
{
    int c, option_index = 0;

    assert(cmdline != NULL);

    *cmdline = (struct cmdline){
        .show_help = false,
        .net = true,
        .debug = false,
    };

    while ((c = getopt_long(argc, argv, "+hnNd", long_options, &option_index)) !=
           -1) {
        switch (c) {
        case 'h':
            cmdline->show_help = true;
            return true;
        case 'n':
            cmdline->net = true;
            break;
        case 'N':
            cmdline->net = false;
            break;
        case 'd':
            cmdline->debug = true;
            break;
        case '?':
            return false;
        default:
            fprintf(stderr,
                    "internal argument parsing error (returned character "
                    "0x%x)\n",
                    c);
            return false;
        }
    }

    if (optind < argc - 2) {
        cmdline->new_root = argv[optind];
        cmdline->nvcpus = strtoul(argv[optind + 1], NULL, 10);
        cmdline->ram_mib = strtoul(argv[optind + 2], NULL, 10);
        return true;
    }

    if (optind >= argc - 2)
        fprintf(stderr, "Missing RAM_MIB argument\n");
    if (optind >= argc - 1)
        fprintf(stderr, "Missing VCPUS argument\n");
    if (optind == argc)
        fprintf(stderr, "Missing NEWROOT argument\n");

    return false;
}

static const char *const nginx_argv[] = {"nginx", "-g", "daemon off;", NULL};

#define DEFAULT_PATH_ENV "PATH=/sbin:/usr/sbin:/bin:/usr/bin"
static const char *const default_envp[] = {
    DEFAULT_PATH_ENV,
    NULL,
};

static int start_passt(void)
{
    int socket_fds[2];
    const int PARENT = 0;
    const int CHILD = 1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socket_fds) < 0) {
        perror("Failed to create passt socket fd");
        return -1;
    }

    int pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        if (close(socket_fds[PARENT]) < 0)
            perror("close PARENT");

        char fd_as_str[16];
        snprintf(fd_as_str, sizeof(fd_as_str), "%d", socket_fds[CHILD]);

        if (execlp("passt", "passt", "-t", "all", "-f", "--fd", fd_as_str, NULL) <
            0) {
            perror("execlp");
            _exit(1);
        }
        _exit(1);
    }

    if (close(socket_fds[CHILD]) < 0)
        perror("close CHILD");

    return socket_fds[PARENT];
}

int main(int argc, char *const argv[])
{
    int cid, ctx_id, err, passt_fd, log_level;
    struct cmdline cmdline;

    if (!parse_cmdline(argc, argv, &cmdline)) {
        putchar('\n');
        print_help(argv[0]);
        return -1;
    }

    if (cmdline.show_help) {
        print_help(argv[0]);
        return 0;
    }

    log_level =
        (cmdline.debug) ? KRUN_LOG_LEVEL_DEBUG : KRUN_LOG_LEVEL_ERROR;
    err = krun_set_log_level(log_level);
    if (err) {
        errno = -err;
        perror("Error configuring log level");
        return -1;
    }

    ctx_id = krun_create_ctx();
    if (ctx_id < 0) {
        errno = -ctx_id;
        perror("Error creating configuration context");
        return -1;
    }

    if ((err = krun_set_vm_config(ctx_id, cmdline.nvcpus, cmdline.ram_mib))) {
        errno = -err;
        perror(
            "Error configuring the number of vCPUs and/or the amount of RAM");
        return -1;
    }

    if ((err = krun_set_console_output(ctx_id, "/dev/stdout"))) {
        errno = -err;
        perror("Error configuring the console output");
        return -1;
    }

    if ((err = krun_set_root(ctx_id, cmdline.new_root))) {
        errno = -err;
        perror("Error configuring enclave rootfs");
        return -1;
    }

    if ((err = krun_set_exec(ctx_id, nginx_argv[0], nginx_argv, default_envp))) {
        errno = -err;
        perror("Error configuring enclave execution path");
        return -1;
    }

    if (cmdline.net) {
        uint8_t mac[] = {0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee};

        passt_fd = start_passt();
        if (passt_fd < 0) {
            fprintf(stderr, "unable to start passt socket pair\n");
            return -1;
        }

        if ((err = krun_add_net_unixstream(ctx_id, NULL, passt_fd, &mac[0],
                                           COMPAT_NET_FEATURES, 0))) {
            errno = -err;
            perror("Error configuring net mode");
            return -1;
        }
    }

    cid = krun_start_enter(ctx_id);
    if (cid < 0) {
        errno = -cid;
        perror("Error creating the microVM");
        return -1;
    }

    return 0;
}
