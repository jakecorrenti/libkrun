#!/usr/bin/env bash
#
# Runtime resource-usage audit for libkrun guests.
#
# For every test in the matrix (tests.conf) this script boots a real microVM
# through the installed libkrun/libkrunfw/libkrun_init, waits for the guest
# workload to report readiness, samples /proc/<harness-pid> for a while, and
# writes per-test summaries plus a run-level comparison table.
#
# Methodology modeled on QEMU's "resource audit" article (section
# "Analyzing Runtime Resource Usage"):
# https://jsnow.gitlab.io/qemu/devel/qemu-resource-audit.html
# See README.md for metric definitions and limitations.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CC="${KRUN_AUDIT_CC:-cc}"
PREFIX="${KRUN_AUDIT_PREFIX:-/usr/local}"
LIBDIR="$PREFIX/lib64"
INCLUDEDIR="$PREFIX/include"

HARNESS="$SCRIPT_DIR/build/krun-harness"
PAUSE="$SCRIPT_DIR/build/pause"
BLK_SETUP="$SCRIPT_DIR/build/blk-setup"
LABEL_SHIM="$SCRIPT_DIR/build/mmap-label.so"
VMA_PROBE="$SCRIPT_DIR/build/vma-probe"
CLK_TCK=$(getconf CLK_TCK)

CONFIG_FILE="$SCRIPT_DIR/tests.conf"
RESULTS_DIR=""
SETTLE=10
DURATION=10
INTERVAL=1
LIST=0
DRY_RUN=0
REBUILD=0
KEEP_GOING=0
SELECTED=()

DEFAULT_APPEND_CMDLINE=""
PAUSE_BUILD_CMD=""
HARNESS_BUILD_CMD=""
BLK_SETUP_BUILD_CMD=""
LABEL_SHIM_BUILD_CMD=""
VMA_PROBE_BUILD_CMD=""
STRACE_K_OK=0
STRACE_KILL_OK=0
CURRENT_PID=""
CURRENT_PG=""
COMPLETED=()

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] [TEST ...]

Runs the libkrun resource-audit test matrix (default: all tests in it).

Options:
  --config FILE     test matrix to use (default: tests.conf next to this script)
  --results DIR     output directory (default: results/<timestamp> next to it)
  --settle SECS     max wait for guest readiness (default: 10)
  --duration SECS   sampling duration per test (default: 10)
  --interval SECS   sampling interval in seconds (default: 1)
  --list            list the tests defined in the matrix and exit
  --dry-run         print the harness command line of each test without
                    running it (per-test artifacts are still assembled)
  --rebuild         rebuild the harness and workload even if up to date
  --keep-going      continue after failed tests (default: abort)
  -h, --help        show this help

Environment:
  KRUN_AUDIT_CC             C compiler (default: cc)
  KRUN_AUDIT_PREFIX         installation prefix of libkrun (default: /usr/local,
                            libraries are expected in \$PREFIX/lib64)
  KRUN_AUDIT_EXTRA_LD_PATH  extra LD_LIBRARY_PATH entries placed in front of
                            the prefix libdir — put a directory holding an
                            alternative libkrunfw.so.5 here to audit a
                            different guest kernel build
EOF
}

die() {
    echo "run-audit.sh: $*" >&2
    exit 1
}

cleanup() {
    if [[ -n "$CURRENT_PID" ]] && kill -0 "$CURRENT_PID" 2>/dev/null; then
        kill -TERM "$CURRENT_PID" 2>/dev/null || true
        if [[ -n "$CURRENT_PG" ]]; then
            kill -TERM -- "-$CURRENT_PG" 2>/dev/null || true
        fi
        sleep 0.5
        kill -KILL "$CURRENT_PID" 2>/dev/null || true
        if [[ -n "$CURRENT_PG" ]]; then
            kill -KILL -- "-$CURRENT_PG" 2>/dev/null || true
        fi
    fi
}

on_signal() {
    cleanup
    trap - EXIT
    exit 130
}

trap cleanup EXIT
trap on_signal INT TERM

elapsed_between() { # elapsed_between START -> seconds since START, one decimal
    awk -v a="$1" -v b="$EPOCHREALTIME" 'BEGIN { printf "%.1f", b - a }'
}

time_up() { # time_up START SECONDS — true once SECONDS have elapsed since START
    awk -v a="$1" -v b="$EPOCHREALTIME" -v s="$2" 'BEGIN { exit !(b - a >= s) }'
}

proc_alive() {
    local pid=$1
    kill -0 "$pid" 2>/dev/null || return 1
    # A zombie still answers kill -0 but has no memory left to sample.
    local state
    state=$(awk '{ sub(/^.*\)/, ""); print $1 }' "/proc/$pid/stat" 2>/dev/null) || return 1
    [[ -n "$state" && "$state" != "Z" ]]
}

proc_field() { # proc_field FILE "Key:" — value from a "Key: value kB" proc file
    awk -v k="$2" '$1 == k { print $2; exit }' "$1" 2>/dev/null || true
}

build_binaries() {
    mkdir -p "$SCRIPT_DIR/build"

    if [[ ! -f "$PAUSE" || "$SCRIPT_DIR/pause.c" -nt "$PAUSE" || $REBUILD -eq 1 ]]; then
        # Static, so the nullfs guest needs no libraries of its own.
        if "$CC" -O2 -static -o "$PAUSE" "$SCRIPT_DIR/pause.c" 2>/dev/null; then
            PAUSE_BUILD_CMD="$CC -O2 -static pause.c -o build/pause"
        elif "$CC" -O2 -static-pie -o "$PAUSE" "$SCRIPT_DIR/pause.c" 2>/dev/null; then
            PAUSE_BUILD_CMD="$CC -O2 -static-pie pause.c -o build/pause (static-pie fallback)"
        else
            "$CC" -O2 -o "$PAUSE" "$SCRIPT_DIR/pause.c"
            PAUSE_BUILD_CMD="$CC -O2 pause.c -o build/pause (dynamic fallback — guest would need libc)"
        fi
    fi

    if [[ ! -f "$HARNESS" || "$SCRIPT_DIR/harness.c" -nt "$HARNESS" || $REBUILD -eq 1 ]]; then
        # -Wl,-rpath covers the libraries linked here; libkrunfw.so.5 is
        # dlopened by soname at payload-load time, so LD_LIBRARY_PATH (set at
        # launch) is what resolves it.
        "$CC" -O2 -I"$INCLUDEDIR" "$SCRIPT_DIR/harness.c" -o "$HARNESS" \
            -L"$LIBDIR" -lkrun -lkrun_init -Wl,-rpath,"$LIBDIR"
        HARNESS_BUILD_CMD="$CC -O2 -I$INCLUDEDIR harness.c -o build/krun-harness -L$LIBDIR -lkrun -lkrun_init -Wl,-rpath,$LIBDIR"
    fi

    if [[ ! -f "$BLK_SETUP" || "$SCRIPT_DIR/blk-setup.c" -nt "$BLK_SETUP" || $REBUILD -eq 1 ]]; then
        # Static, like pause: the realistic-matrix rootfs it runs in is the
        # only thing the guest needs.
        "$CC" -O2 -static -o "$BLK_SETUP" "$SCRIPT_DIR/blk-setup.c"
        BLK_SETUP_BUILD_CMD="$CC -O2 -static blk-setup.c -o build/blk-setup"
    fi

    if [[ ! -f "$LABEL_SHIM" || "$SCRIPT_DIR/mmap-label.c" -nt "$LABEL_SHIM" || $REBUILD -eq 1 ]]; then
        "$CC" -O2 -shared -fPIC -o "$LABEL_SHIM" "$SCRIPT_DIR/mmap-label.c" -ldl
        LABEL_SHIM_BUILD_CMD="$CC -O2 -shared -fPIC -o build/mmap-label.so mmap-label.c -ldl"
    fi

    if [[ ! -f "$VMA_PROBE" || "$SCRIPT_DIR/vma-probe.c" -nt "$VMA_PROBE" || $REBUILD -eq 1 ]]; then
        "$CC" -O2 -o "$VMA_PROBE" "$SCRIPT_DIR/vma-probe.c"
        VMA_PROBE_BUILD_CMD="$CC -O2 -o build/vma-probe vma-probe.c"
    fi

    # Not every strace build knows -k (syscall callstacks) or
    # --kill-on-exit; probe once.
    if command -v strace >/dev/null 2>&1; then
        if strace -k -e trace=none true >/dev/null 2>&1; then
            STRACE_K_OK=1
        fi
        if strace --kill-on-exit -e trace=none true >/dev/null 2>&1; then
            STRACE_KILL_OK=1
        fi
    fi
}

sample_once() { # sample_once PID CSV_FILE SAMPLING_START — append one CSV row
    local pid=$1 out=$2 start=$3
    local elapsed fds row

    proc_alive "$pid" || return 1

    # find tolerates fds appearing or disappearing mid-scan
    fds=$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 -printf '.' 2>/dev/null | wc -c) || fds=0
    elapsed=$(elapsed_between "$start")

    # /proc/PID/stat: utime, stime and guest_time are fields 14, 15 and 43;
    # comm may contain spaces, so parse after the closing parenthesis, which
    # shifts the remaining fields down by two.
    row=$(awk -v elapsed="$elapsed" -v tck="$CLK_TCK" -v fds="$fds" '
        FNR == 1 { file++ }
        file == 1 {
            if ($1 == "VmRSS:") vmrss = $2
            else if ($1 == "RssAnon:") rssanon = $2
            else if ($1 == "RssFile:") rssfile = $2
            else if ($1 == "VmPTE:") pte = $2
            else if ($1 == "Threads:") threads = $2
        }
        file == 2 {
            if ($1 == "Pss:") pss = $2
            else if ($1 == "Private_Clean:") pc = $2
            else if ($1 == "Private_Dirty:") pd = $2
            else if ($1 == "Anonymous:") anon = $2
        }
        file == 3 {
            sub(/^.*\)/, "")
            user = $12 / tck
            sys = $13 / tck
            guest = $41 / tck
        }
        END {
            if (vmrss == "") exit 1
            printf "%.1f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.2f,%.2f,%.2f\n", \
                elapsed, vmrss, rssanon, rssfile, pss, pc + pd, anon, pte, threads, fds, user, sys, guest
        }
    ' "/proc/$pid/status" "/proc/$pid/smaps_rollup" "/proc/$pid/stat") || return 1

    echo "$row" >> "$out"
}

take_final_snapshot() { # take_final_snapshot PID TEST_DIR
    local pid=$1 dir=$2
    local fd target t lib

    cp "/proc/$pid/status" "$dir/final-status.txt" 2>/dev/null || true
    cp "/proc/$pid/smaps" "$dir/final-smaps.txt" 2>/dev/null || true
    cp "/proc/$pid/smaps_rollup" "$dir/final-smaps_rollup.txt" 2>/dev/null || true
    cp "/proc/$pid/maps" "$dir/final-maps.txt" 2>/dev/null || true
    cp "/proc/$pid/io" "$dir/final-io.txt" 2>/dev/null || true

    : > "$dir/fds.txt"
    for fd in /proc/$pid/fd/*; do
        [[ -L "$fd" ]] || continue
        target=$(readlink "$fd" 2>/dev/null) || target="(unreadable)"
        printf '%s %s\n' "${fd##*/}" "$target" >> "$dir/fds.txt"
    done

    : > "$dir/threads.txt"
    for t in /proc/$pid/task/*; do
        [[ -d "$t" ]] || continue
        printf '%s %s\n' "${t##*/}" "$(cat "$t/comm" 2>/dev/null)" >> "$dir/threads.txt"
    done

    # One "tid comm sp" line per task. The sp is the user stack pointer from
    # the thread's blocked syscall (/proc/.../syscall, field 8): stat's
    # startstack is mm-wide (the same main-stack value for every thread) and
    # cannot attribute per-thread stacks. Threads not in a syscall report 0.
    : > "$dir/task-stats.txt"
    local tid sp
    for t in /proc/$pid/task/*; do
        [[ -d "$t" ]] || continue
        tid=${t##*/}
        sp=$(awk '{ print $8 }' "$t/syscall" 2>/dev/null) || sp=""
        printf '%s %s %s\n' "$tid" "$(cat "$t/comm" 2>/dev/null)" "${sp:-0}" >> "$dir/task-stats.txt"
    done

    {
        ldd "$HARNESS" 2>/dev/null || true
        echo
        echo "krun libraries actually mapped by the harness (from final-maps.txt):"
        awk '{ for (i = 6; i <= NF; i++) if ($i ~ /\/libkrun[^/]*\.so/) print $i }' "$dir/final-maps.txt" 2>/dev/null \
            | sort -u | while read -r lib; do
            printf '  %s -> %s\n' "$lib" "$(readlink -f "$lib")"
        done
    } > "$dir/libs.txt"
}

classify_fds() { # classify_fds FDS_FILE — "total=N, class=cnt, ..." summary
    awk '
        function cls(t) {
            if (t == "/dev/kvm") return "/dev/kvm"
            if (t ~ /^anon_inode:kvm/) return "anon_inode:kvm-*"
            if (t ~ /^\/memfd:/) return "memfd"
            if (t ~ /^pipe:/) return "pipe"
            if (t ~ /^socket:/) return "socket"
            if (t ~ /^anon_inode:/) {
                sub(/^anon_inode:/, "", t)
                gsub(/[\[\]]/, "", t)
                return "anon_inode:" t
            }
            if (t ~ /^\//) return "file"
            return "other"
        }
        { c[cls($2)]++; n++ }
        END { print "total", n; for (k in c) print k, c[k] }' "$1" 2>/dev/null \
        | sort | awk '{ printf "%s%s=%s", sep, $1, $2; sep = ", " } END { if (NR > 0) printf "\n" }'
}

write_summary() { # write_summary TEST_DIR NAME VCPUS RAM_MIB TRANSPORT PAYLOAD ROOT DEVICES RESULT REASON READY_AFTER DURATION INTERVAL
    local test_dir=$1 name=$2 vcpus=$3 ram_mib=$4 transport=$5 payload=$6
    local root_mode=$7 devices=$8 result=$9 reason=${10} ready_after=${11}
    local duration=${12} interval=${13}

    local status="$test_dir/final-status.txt"
    local rollup="$test_dir/final-smaps_rollup.txt"
    local io="$test_dir/final-io.txt"
    local parsed="$test_dir/parsed-smaps.tsv"

    # Pre-boot phase (harness --pause-before-run): end-of-phase counters come
    # from the last samples-preboot.csv row.
    local have_preboot=0
    local pb_vmrss=0 pb_rssan=0 pb_rssfile=0 pb_pss=0 pb_uss=0 pb_anon=0
    local pb_pte=0 pb_threads=0 pb_fds=0 pb_samples=0 pb_span=0
    if [[ -f "$test_dir/preboot-smaps.txt" ]]; then
        have_preboot=1
        local pb_body pb_last
        pb_body=$(tail -n +2 "$test_dir/samples-preboot.csv" 2>/dev/null || true)
        if [[ -n "$pb_body" ]]; then
            pb_last=$(printf '%s\n' "$pb_body" | tail -1)
            IFS=, read -r _ pb_vmrss pb_rssan pb_rssfile pb_pss pb_uss pb_anon pb_pte pb_threads pb_fds _ _ _ <<< "$pb_last"
            pb_samples=$(printf '%s\n' "$pb_body" | wc -l)
            pb_span=$(cut -d, -f1 <<< "$pb_last")
        fi
    fi

    if [[ -f "$test_dir/final-smaps.txt" ]]; then
        awk -v ram_kib=$((ram_mib * 1024)) -v harness="krun-harness" \
            -f "$SCRIPT_DIR/parse-smaps.awk" "$test_dir/final-smaps.txt" > "$parsed"
    else
        : > "$parsed"
    fi

    local gr_method="none" gr_n=0 gr_rss=0 gr_anon=0
    local t_rss=0 t_anon=0 t_pss=0 t_uss=0 t_shared=0
    if [[ -s "$parsed" ]]; then
        local gr_line tl_line
        gr_line=$(grep $'^GUESTRAM\t' "$parsed" || true)
        tl_line=$(grep $'^TOTAL\t' "$parsed" || true)
        if [[ -n "$gr_line" ]]; then
            IFS=$'\t' read -r _ gr_method gr_n gr_rss gr_anon <<< "$gr_line"
        fi
        if [[ -n "$tl_line" ]]; then
            IFS=$'\t' read -r _ t_rss t_anon t_pss t_uss t_shared <<< "$tl_line"
        fi
    fi
    local vmm_private_anon=$(( t_anon - gr_anon ))

    local vmrss rss_anon rss_file vmpte threads
    vmrss=$(proc_field "$status" "VmRSS:")
    rss_anon=$(proc_field "$status" "RssAnon:")
    rss_file=$(proc_field "$status" "RssFile:")
    vmpte=$(proc_field "$status" "VmPTE:")
    threads=$(proc_field "$status" "Threads:")
    local pss pc pd anon_r sc sd swap_pss
    pss=$(proc_field "$rollup" "Pss:")
    pc=$(proc_field "$rollup" "Private_Clean:")
    pd=$(proc_field "$rollup" "Private_Dirty:")
    anon_r=$(proc_field "$rollup" "Anonymous:")
    sc=$(proc_field "$rollup" "Shared_Clean:")
    sd=$(proc_field "$rollup" "Shared_Dirty:")
    swap_pss=$(proc_field "$rollup" "SwapPss:")
    local uss=$(( ${pc:-0} + ${pd:-0} ))

    local nsamples=0 span_s=0 u1=0 s1=0 g1=0 u2=0 s2=0 g2=0
    if [[ -f "$test_dir/samples.csv" ]]; then
        local csv_body first last
        csv_body=$(tail -n +2 "$test_dir/samples.csv" || true)
        if [[ -n "$csv_body" ]]; then
            nsamples=$(printf '%s\n' "$csv_body" | wc -l)
            first=$(printf '%s\n' "$csv_body" | head -1)
            last=$(printf '%s\n' "$csv_body" | tail -1)
            IFS=, read -r _ _ _ _ _ _ _ _ _ _ u1 s1 g1 <<< "$first"
            IFS=, read -r _ _ _ _ _ _ _ _ _ _ u2 s2 g2 <<< "$last"
            span_s=$(cut -d, -f1 <<< "$last")
        fi
    fi
    local du=0 ds=0 dg=0
    if (( nsamples > 1 )); then
        read -r du ds dg < <(awk -v u1="$u1" -v u2="$u2" -v s1="$s1" -v s2="$s2" \
            -v g1="$g1" -v g2="$g2" -v n=$((nsamples - 1)) \
            'BEGIN { printf "%.3f %.3f %.3f", (u2 - u1) / n, (s2 - s1) / n, (g2 - g1) / n }')
    fi

    {
        echo "Test: $name"
        echo "Config: vcpus=$vcpus ram_mib=$ram_mib transport=$transport payload=$payload root=$root_mode devices=$devices"
        if [[ "$result" == "OK" ]]; then
            if [[ "$ready_after" == "n/a" ]]; then
                echo "Result: OK (no readiness marker for this payload; settle wait completed)"
            else
                echo "Result: OK (guest ready after ${ready_after}s)"
            fi
        else
            echo "Result: FAILED ($reason)"
        fi
        echo "Samples: $nsamples over ${span_s:-0}s (interval ${interval}s, duration ${duration}s)"
        echo

        if [[ $have_preboot -eq 1 ]]; then
            echo "[Phase: VMM built, before guest start]"
            echo "VmRSS: ${pb_vmrss:-0} KiB  RssAnon: ${pb_rssan:-0} KiB  RssFile: ${pb_rssfile:-0} KiB  PSS: ${pb_pss:-0} KiB  USS: ${pb_uss:-0} KiB"
            echo "VmPTE: ${pb_pte:-0} KiB  Threads: ${pb_threads:-0}  fds: ${pb_fds:-0}   (at end of pre-boot sampling)"
            echo "(samples: ${pb_samples:-0} over ${pb_span:-0}s, annotated map: preboot-maps-annotated.txt)"
            echo
        fi

        echo "[Process counters /proc/PID/status]"
        local key v
        for key in VmPeak VmSize VmHWM VmRSS RssAnon RssFile RssShmem VmPTE VmSwap; do
            v=$(proc_field "$status" "$key:")
            echo "$key: ${v:--} KiB"
        done
        v=$(proc_field "$status" "Threads:")
        echo "Threads: ${v:--}"
        v=$(proc_field "$status" "voluntary_ctxt_switches:")
        echo "voluntary_ctxt_switches: ${v:--}"
        v=$(proc_field "$status" "nonvoluntary_ctxt_switches:")
        echo "nonvoluntary_ctxt_switches: ${v:--}"
        echo

        echo "[Memory breakdown /proc/PID/smaps_rollup]"
        v=$(proc_field "$rollup" "Rss:")
        echo "Rss: ${v:--} KiB"
        echo "Pss: ${pss:--} KiB"
        if [[ -n "$pss" ]]; then
            echo "USS (Private_Clean+Private_Dirty): $uss KiB"
        else
            echo "USS (Private_Clean+Private_Dirty): -"
        fi
        echo "Anonymous: ${anon_r:--} KiB"
        if [[ -n "$pss" ]]; then
            echo "Shared (Shared_Clean+Shared_Dirty): $(( ${sc:-0} + ${sd:-0} )) KiB"
        else
            echo "Shared (Shared_Clean+Shared_Dirty): -"
        fi
        echo "SwapPss: ${swap_pss:--} KiB"
        echo

        echo "[Derived]"
        if [[ $have_preboot -eq 1 && -n "$vmrss" && -n "$anon_r" ]]; then
            echo "boot cost: VmRSS +$(( vmrss - pb_vmrss )) KiB, Anonymous +$(( anon_r - pb_anon )) KiB (guest RAM + kernel COW)"
        fi
        echo "guest_ram_rss: $gr_rss KiB (method: $gr_method, $gr_n region(s))"
        echo "vmm_private_anon: $vmm_private_anon KiB   (= Anonymous $t_anon - guest-RAM anon $gr_anon; the headline libkrun overhead)"
        echo "file_backed_rss: ${rss_file:--} KiB (shareable across instances)"
        echo

        echo "[CPU]"
        echo "user: ${u2}s sys: ${s2}s guest: ${g2}s (final sample)"
        echo "avg per sample: user ${du}s sys ${ds}s guest ${dg}s"
        echo

        echo "[Threads]"
        if [[ -s "$test_dir/threads.txt" ]]; then
            awk '{ printf "  "; print }' "$test_dir/threads.txt"
        else
            echo "  (not captured)"
        fi
        echo

        echo "[FDs]"
        if [[ -s "$test_dir/fds.txt" ]]; then
            echo "  $(classify_fds "$test_dir/fds.txt")"
        else
            echo "  (not captured)"
        fi
        echo

        echo "[I/O /proc/PID/io]"
        v=$(proc_field "$io" "rchar:")
        echo "rchar: ${v:--}"
        v=$(proc_field "$io" "wchar:")
        echo "wchar: ${v:--}"
        v=$(proc_field "$io" "read_bytes:")
        echo "read_bytes: ${v:--}"
        v=$(proc_field "$io" "write_bytes:")
        echo "write_bytes: ${v:--}"
        echo

        echo "[Top mappings by RSS]  size_kib rss_kib anon_kib perms label"
        if [[ -s "$parsed" ]]; then
            grep $'^MAP\t' "$parsed" | sort -t$'\t' -k3,3nr \
                | awk -F'\t' 'NR <= 15 { printf "  %10d %10d %10d  %-5s  %s\n", $2, $3, $4, $7, $8 }'
        fi
        echo

        echo "[Top mappings by Anonymous]  size_kib rss_kib anon_kib perms label"
        if [[ -s "$parsed" ]]; then
            grep $'^MAP\t' "$parsed" | sort -t$'\t' -k4,4nr \
                | awk -F'\t' 'NR <= 15 { printf "  %10d %10d %10d  %-5s  %s\n", $2, $3, $4, $7, $8 }'
        fi
        echo

        echo "[Category rollup]  rss_kib anon_kib"
        if [[ -s "$parsed" ]]; then
            grep $'^ROLLUP\t' "$parsed" | awk -F'\t' '{ printf "  %-14s %10d %10d\n", $2, $3, $4 }'
        fi
    } > "$test_dir/summary.txt"

    {
        echo "vcpus=$vcpus"
        echo "ram_mib=$ram_mib"
        echo "transport=$transport"
        echo "payload=$payload"
        echo "root=$root_mode"
        echo "devices=$devices"
        echo "result=$result"
        echo "vmrss_kib=${vmrss:--}"
        echo "rss_anon_kib=${rss_anon:--}"
        if [[ -n "$pss" ]]; then
            echo "uss_kib=$uss"
        else
            echo "uss_kib=-"
        fi
        echo "pss_kib=${pss:--}"
        echo "guest_ram_rss_kib=$gr_rss"
        echo "vmm_private_anon_kib=$vmm_private_anon"
        echo "vmpte_kib=${vmpte:--}"
        echo "threads=${threads:--}"
        if [[ -s "$test_dir/fds.txt" ]]; then
            echo "fds=$(awk 'END { print NR }' "$test_dir/fds.txt")"
        else
            echo "fds=-"
        fi
        echo "cpu_user_s=$u2"
        echo "cpu_sys_s=$s2"
        echo "cpu_guest_s=$g2"
    } > "$test_dir/metrics.txt"

    # Verbose annotated memory map, category data and charts.
    if [[ -f "$test_dir/final-smaps.txt" ]]; then
        if command -v python3 >/dev/null 2>&1; then
            local totals=""
            if totals=$(python3 "$SCRIPT_DIR/annotate-maps.py" "$test_dir" \
                    --name "$name" --ram-mib "$ram_mib" 2>/dev/null); then
                {
                    echo
                    echo "[Total memory breakdown]"
                    echo "$totals"
                    echo
                    echo "Annotated memory map: $test_dir/maps-annotated.txt"
                    echo "Category data:        $test_dir/categories.csv"
                    echo "Charts:               $test_dir/charts/"
                } >> "$test_dir/summary.txt"
            else
                echo "(annotate-maps.py failed; run it by hand for the error)" >> "$test_dir/summary.txt"
            fi
            if [[ $have_preboot -eq 1 ]]; then
                # second pass over the pre-boot snapshot; its stdout totals
                # are already reflected in the phase section above
                python3 "$SCRIPT_DIR/annotate-maps.py" "$test_dir" \
                    --name "$name-preboot" --ram-mib "$ram_mib" \
                    --input-prefix preboot- --output-prefix preboot- >/dev/null 2>&1 \
                    || echo "(preboot annotate-maps.py failed; run it by hand for the error)" >> "$test_dir/summary.txt"
            fi
        else
            echo "(python3 not found — annotated memory map and charts skipped)" >> "$test_dir/summary.txt"
        fi
    fi
}

write_run_summary() {
    local out="$RESULTS_DIR/summary.md"
    {
        echo "# libkrun resource audit — $(basename "$RESULTS_DIR")"
        echo
        echo "Memory values in KiB, CPU in seconds. Per-test details in <test>/summary.txt,"
        echo "run metadata in meta.txt, raw samples in <test>/samples.csv."
        echo
        echo "| test | vcpus | ram | transport | payload | root | devices | RSS | RssAnon | USS | PSS | guest_ram_rss | vmm_private_anon | VmPTE | threads | fds | cpu_user_s | cpu_sys_s | cpu_guest_s | result |"
        echo "|------|-------|-----|-----------|---------|------|---------|-----|---------|-----|-----|---------------|------------------|-------|---------|-----|------------|------------|--------------|--------|"
        local name m
        for name in "${COMPLETED[@]}"; do
            m="$RESULTS_DIR/$name/metrics.txt"
            if [[ -f "$m" ]]; then
                awk -F= -v t="$name" '
                    /^(vcpus|ram_mib|transport|payload|root|devices|vmrss_kib|rss_anon_kib|uss_kib|pss_kib|guest_ram_rss_kib|vmm_private_anon_kib|vmpte_kib|threads|fds|cpu_user_s|cpu_sys_s|cpu_guest_s|result)=/ {
                        v[$1] = $2
                    }
                    function val(k) {
                        if (k in v && v[k] != "") return v[k]
                        return "-"
                    }
                    END {
                        printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", \
                            t, val("vcpus"), val("ram_mib"), val("transport"), val("payload"), val("root"), val("devices"), \
                            val("vmrss_kib"), val("rss_anon_kib"), val("uss_kib"), val("pss_kib"), val("guest_ram_rss_kib"), \
                            val("vmm_private_anon_kib"), val("vmpte_kib"), val("threads"), val("fds"), \
                            val("cpu_user_s"), val("cpu_sys_s"), val("cpu_guest_s"), val("result")
                    }' "$m"
            else
                echo "| $name | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | not run |"
            fi
        done
    } > "$out"
    echo "run summary: $out"
}

write_meta() {
    # Functional probe first: neither /boot/config-$(uname -r) nor
    # /proc/config.gz is guaranteed to exist (custom kernels).
    local anon_labels="unknown" anon_source="config file"
    if [[ -x "$VMA_PROBE" ]]; then
        anon_source="functional probe"
        if "$VMA_PROBE" >/dev/null 2>&1; then
            anon_labels="yes"
        else
            anon_labels="no"
        fi
    else
        local kconfig="/boot/config-$(uname -r)"
        if [[ -r "$kconfig" ]]; then
            if grep -q '^CONFIG_ANON_VMA_NAME=y' "$kconfig"; then
                anon_labels="yes"
            else
                anon_labels="no"
            fi
        elif [[ -r /proc/config.gz ]]; then
            if gzip -cd /proc/config.gz 2>/dev/null | grep '^CONFIG_ANON_VMA_NAME=y' >/dev/null; then
                anon_labels="yes"
            else
                anon_labels="no"
            fi
        fi
    fi

    {
        echo "date: $(date -Is)"
        echo "host: $(uname -sr) ($(uname -m))"
        echo "MemTotal: $(awk '/^MemTotal:/ { print $2, $3 }' /proc/meminfo)"
        echo "CLK_TCK: $CLK_TCK"
        echo "libkrun: $(readlink -f "$LIBDIR/libkrun.so.2")"
        echo "libkrun_init: $(readlink -f "$LIBDIR/libkrun_init.so.0")"
        echo "libkrunfw (dlopened by soname libkrunfw.so.5): $(readlink -f "$LIBDIR/libkrunfw.so.5")"
        echo "libkrunfw resolution: LD_LIBRARY_PATH lists KRUN_AUDIT_EXTRA_LD_PATH entries"
        echo "  first, then $LIBDIR — an alternative libkrunfw.so.5 build placed earlier wins."
        echo "harness build: ${HARNESS_BUILD_CMD:-cached from previous run}"
        echo "pause build: ${PAUSE_BUILD_CMD:-cached from previous run}"
        echo "blk-setup build: ${BLK_SETUP_BUILD_CMD:-cached from previous run}"
        echo "mmap-label shim: ${LABEL_SHIM_BUILD_CMD:-cached from previous run}"
        if command -v strace >/dev/null 2>&1; then
            echo "strace: $(command -v strace) (callstacks: $([[ $STRACE_K_OK -eq 1 ]] && echo yes || echo no))"
        else
            echo "strace: not installed"
        fi
        echo "settle=${SETTLE}s duration=${DURATION}s interval=${INTERVAL}s"
        echo "CONFIG_ANON_VMA_NAME: $anon_labels ($anon_source) — glibc's"
        echo "  GLIBC_TUNABLES=glibc.mem.decorate_maps=1 labels and the label_mmap shim both"
        echo "  depend on it; without it anonymous mappings carry no [anon:...] labels in smaps"
        echo "  and guest RAM is identified by size only (see parse-smaps.awk)."
        echo "vma probe build: ${VMA_PROBE_BUILD_CMD:-cached from previous run}"
    } > "$RESULTS_DIR/meta.txt"
}

run_test() { # run_test NAME — returns nonzero if the test failed
    local name=$1
    local func="test_$name"
    local test_dir="$RESULTS_DIR/$name"

    # Matrix defaults; the test function overrides what it needs.
    local vcpus=1 ram_mib=256 transport=mmio payload=krunfw
    local kernel="" kernel_format="" initrd="" cmdline="" firmware_path=""
    local append_cmdline="$DEFAULT_APPEND_CMDLINE"
    local root_mode=nullfs root_dir=""
    local workload="/pause"
    local workload_args=()
    local embeds=()
    local devices="console"
    local blk_img="" blk_format="raw" net_socket=""
    local log_path=""
    local ready_marker="AUDIT_GUEST_READY"
    local settle=$SETTLE duration=$DURATION interval=$INTERVAL
    local strace=0 label_mmap=0 pause_before_run=0
    local -a extra_env=()

    mkdir -p "$test_dir"
    local TEST_DIR="$test_dir"
    "$func"

    if [[ ${KRUN_AUDIT_LABEL_MMAP:-0} == 1 ]]; then
        label_mmap=1
    fi

    [[ "$vcpus" =~ ^[0-9]+$ ]] || die "test $name: vcpus='$vcpus' is not a number"
    [[ "$ram_mib" =~ ^[0-9]+$ ]] || die "test $name: ram_mib='$ram_mib' is not a number"
    [[ "$pause_before_run" =~ ^[0-9]+$ ]] || die "test $name: pause_before_run='$pause_before_run' is not a number"

    # In nullfs mode the audit workload is mapped in from the host, read-only,
    # unless the test embeds its own binary at the workload path.
    if [[ "$payload" != "firmware" && "$root_mode" == "nullfs" ]]; then
        local covered=0 e
        for e in "${embeds[@]}"; do
            if [[ "${e##*:}" == "$workload" ]]; then
                covered=1
            fi
        done
        if [[ $covered -eq 0 ]]; then
            embeds+=("$PAUSE:$workload")
        fi
    fi

    local -a args=(
        --vcpus="$vcpus"
        --ram-mib="$ram_mib"
        --transport="$transport"
        --payload="$payload"
        --root-mode="$root_mode"
        --devices="$devices"
        --workload="$workload"
    )
    if [[ -n "$kernel" ]]; then args+=(--kernel="$kernel"); fi
    if [[ -n "$kernel_format" ]]; then args+=(--kernel-format="$kernel_format"); fi
    if [[ -n "$initrd" ]]; then args+=(--initrd="$initrd"); fi
    if [[ -n "$cmdline" ]]; then args+=(--cmdline="$cmdline"); fi
    if [[ -n "$firmware_path" ]]; then args+=(--firmware="$firmware_path"); fi
    if [[ -n "$append_cmdline" ]]; then args+=(--append-cmdline="$append_cmdline"); fi
    if [[ -n "$root_dir" ]]; then args+=(--root-dir="$root_dir"); fi
    if [[ -n "$blk_img" ]]; then
        args+=(--blk-img="$blk_img")
        args+=(--blk-format="$blk_format")
    fi
    if [[ -n "$net_socket" ]]; then args+=(--net-socket="$net_socket"); fi
    if [[ -n "$log_path" ]]; then args+=(--log="$log_path"); fi
    if [[ "$pause_before_run" -gt 0 ]]; then args+=(--pause-before-run="$pause_before_run"); fi
    local e
    for e in "${embeds[@]}"; do
        args+=(--embed="$e")
    done
    if [[ ${#workload_args[@]} -gt 0 ]]; then
        args+=(-- "${workload_args[@]}")
    fi

    # Fail fast on obviously broken configurations.
    if [[ -n "$kernel" && ! -f "$kernel" ]]; then die "test $name: kernel not found: $kernel"; fi
    if [[ -n "$firmware_path" && ! -f "$firmware_path" ]]; then die "test $name: firmware not found: $firmware_path"; fi
    if [[ -n "$initrd" && ! -f "$initrd" ]]; then die "test $name: initrd not found: $initrd"; fi
    if [[ "$root_mode" == "dir" && ! -d "$root_dir" ]]; then die "test $name: root dir not found: $root_dir"; fi
    if [[ -n "$blk_img" && ! -f "$blk_img" ]]; then die "test $name: blk image not found: $blk_img"; fi
    if [[ $DRY_RUN -eq 0 && "$payload" != "firmware" && "$root_mode" == "nullfs" && ! -f "$PAUSE" ]]; then
        die "test $name: workload binary $PAUSE missing (build skipped?)"
    fi

    if [[ $DRY_RUN -eq 1 ]]; then
        printf '%s: would run: ' "$name"
        printf '%q ' "$HARNESS" "${args[@]}"
        echo
        return 0
    fi

    local console_log="$test_dir/guest-console.log"
    # KRUN_AUDIT_EXTRA_LD_PATH entries come first so an alternative
    # libkrunfw.so.5 build wins over the installed one.
    local ld_path="${KRUN_AUDIT_EXTRA_LD_PATH:+$KRUN_AUDIT_EXTRA_LD_PATH:}$LIBDIR"

    local kv
    {
        echo "# environment"
        echo "LD_LIBRARY_PATH=$ld_path"
        echo "GLIBC_TUNABLES=glibc.mem.decorate_maps=1"
        if [[ $label_mmap -eq 1 ]]; then
            echo "LD_PRELOAD=$LABEL_SHIM"
        fi
        for kv in "${extra_env[@]}"; do echo "$kv"; done
        echo "# knobs"
        echo "strace=$strace"
        echo "label_mmap=$label_mmap"
        echo "# launched with cwd $test_dir"
        printf 'cmdline:'
        printf ' %q' "$HARNESS" "${args[@]}"
        echo
    } > "$test_dir/cmd.txt"

    local -a env_cmd=(env LD_LIBRARY_PATH="$ld_path" GLIBC_TUNABLES=glibc.mem.decorate_maps=1)
    if [[ $label_mmap -eq 1 ]]; then
        env_cmd+=("LD_PRELOAD=$LABEL_SHIM")
    fi
    env_cmd+=("${extra_env[@]}")
    env_cmd+=("$HARNESS" "${args[@]}")

    # strace runs as the direct parent, so ptrace_scope is not an issue.
    # strace merely detaches on SIGTERM, so either ask it to kill its tracees
    # (--kill-on-exit) or put the whole tree in its own process group.
    local -a launch_cmd=("${env_cmd[@]}")
    local launcher_pg=""
    if [[ $strace -eq 1 ]]; then
        if ! command -v strace >/dev/null 2>&1; then
            die "test $name: strace=1 but strace is not installed"
        fi
        launch_cmd=(strace -f)
        if [[ $STRACE_K_OK -eq 1 ]]; then
            launch_cmd+=(-k)
        else
            echo "  note: this strace does not support -k; mmap callstacks disabled"
        fi
        launch_cmd+=(-e trace=mmap,mprotect,munmap,open,openat,openat2,prctl -o "$test_dir/strace.log")
        if [[ $STRACE_KILL_OK -eq 1 ]]; then
            launch_cmd+=(--kill-on-exit)
        else
            launch_cmd=(setsid "${launch_cmd[@]}")
            launcher_pg=1
        fi
        launch_cmd+=("${env_cmd[@]}")
    fi

    (
        cd "$test_dir"
        exec "${launch_cmd[@]}" </dev/null >"$console_log" 2>&1
    ) &
    local pid=$!
    CURRENT_PID=$pid
    CURRENT_PG=""
    if [[ -n "$launcher_pg" ]]; then
        CURRENT_PG=$pid
    fi

    # Under strace, $pid is the tracer; sampling must target the VM process.
    # strace's only child is env, which execs the harness without forking, so
    # the first child pid is the harness's own.
    local vm_pid=$pid
    if [[ $strace -eq 1 ]]; then
        local tries=0 child=""
        while (( tries < 20 )) && [[ -z "$child" ]]; do
            child=$(awk '{ print $1 }' "/proc/$pid/task/$pid/children" 2>/dev/null) || child=""
            if [[ -z "$child" ]]; then
                sleep 0.1
                tries=$((tries + 1))
            fi
        done
        vm_pid=${child:-$pid}
    fi

    local launch_time=$EPOCHREALTIME
    local result="OK" reason="" ready_after=""
    local ready_from=$launch_time
    local csv_header="elapsed_s,vmrss_kib,rss_anon_kib,rss_file_kib,pss_kib,uss_kib,anon_kib,pte_kib,threads,fds,cpu_user_s,cpu_sys_s,cpu_guest_s"

    if [[ "$pause_before_run" -gt 0 ]]; then
        # Phase 1: VMM built (KVM VM, devices, guest RAM, kernel inserted),
        # guest not executing yet. The harness sleeps pause_before_run seconds
        # from the marker; keep a 1s safety margin because marker detection
        # lags and the guest reaches readiness within ~0.2s of the sleep
        # ending — sampling into the guest phase would corrupt the split.
        local phase_seen=0
        while :; do
            if grep -aFq "AUDIT_PHASE_VMM_BUILT" "$console_log" 2>/dev/null; then
                phase_seen=1
                break
            fi
            if ! proc_alive "$vm_pid" || ! proc_alive "$pid"; then
                result="FAILED"
                reason="harness exited before the VMM-built marker (see guest-console.log)"
                break
            fi
            if time_up "$launch_time" "$settle"; then
                result="FAILED"
                reason="VMM-built marker not found within ${settle}s (see guest-console.log)"
                break
            fi
            sleep 0.2
        done
        if [[ $phase_seen -eq 1 && "$result" == "OK" ]]; then
            local preboot_csv="$test_dir/samples-preboot.csv"
            echo "$csv_header" > "$preboot_csv"
            local preboot_start=$EPOCHREALTIME
            local preboot_n=$(( (pause_before_run - 1) / interval ))
            if (( preboot_n < 1 )); then preboot_n=1; fi
            local pi
            for ((pi = 0; pi < preboot_n; pi++)); do
                if ! sample_once "$vm_pid" "$preboot_csv" "$preboot_start"; then
                    result="FAILED"
                    reason="harness exited during pre-boot sampling"
                    break
                fi
                if (( pi < preboot_n - 1 )); then
                    sleep "$interval"
                fi
            done
            if [[ "$result" == "OK" ]] && proc_alive "$vm_pid"; then
                cat "/proc/$vm_pid/status" > "$test_dir/preboot-status.txt" 2>/dev/null || true
                cat "/proc/$vm_pid/smaps" > "$test_dir/preboot-smaps.txt" 2>/dev/null || true
                cat "/proc/$vm_pid/maps" > "$test_dir/preboot-maps.txt" 2>/dev/null || true
                cat "/proc/$vm_pid/io" > "$test_dir/preboot-io.txt" 2>/dev/null || true
            fi
            # the guest only starts executing when the pause window closes
            ready_from=$EPOCHREALTIME
        fi
    fi

    if [[ -n "$ready_marker" ]]; then
        while :; do
            if grep -aFq "$ready_marker" "$console_log" 2>/dev/null; then
                ready_after=$(elapsed_between "$launch_time")
                break
            fi
            if ! proc_alive "$vm_pid" || ! proc_alive "$pid"; then
                result="FAILED"
                reason="harness exited before the readiness marker (see guest-console.log)"
                break
            fi
            if time_up "$ready_from" "$settle"; then
                result="FAILED"
                reason="readiness marker not found within ${settle}s (see guest-console.log)"
                break
            fi
            sleep 0.2
        done
    else
        # Firmware payloads boot themselves; there is no marker to wait for.
        sleep "$settle"
        if proc_alive "$vm_pid"; then
            ready_after="n/a"
        else
            result="FAILED"
            reason="harness exited during the settle period (see guest-console.log)"
        fi
    fi

    local samples="$test_dir/samples.csv"
    echo "$csv_header" > "$samples"

    if [[ "$result" == "OK" ]]; then
        local sample_start=$EPOCHREALTIME
        local n=$(( duration / interval ))
        if (( n < 1 )); then n=1; fi
        local i
        for ((i = 0; i < n; i++)); do
            if ! sample_once "$vm_pid" "$samples" "$sample_start"; then
                result="FAILED"
                reason="harness exited during sampling"
                break
            fi
            if (( i < n - 1 )); then
                sleep "$interval"
            fi
        done
    fi

    if proc_alive "$vm_pid"; then
        take_final_snapshot "$vm_pid" "$test_dir"
    fi

    if proc_alive "$pid" || proc_alive "$vm_pid"; then
        kill -TERM "$pid" "$vm_pid" 2>/dev/null || true
        if [[ -n "$launcher_pg" ]]; then
            kill -TERM -- "-$pid" 2>/dev/null || true
        fi
        local waited=0
        while (proc_alive "$pid" || proc_alive "$vm_pid") && (( waited < 100 )); do
            sleep 0.1
            waited=$((waited + 1))
        done
        if proc_alive "$pid" || proc_alive "$vm_pid"; then
            kill -KILL "$pid" "$vm_pid" 2>/dev/null || true
            if [[ -n "$launcher_pg" ]]; then
                kill -KILL -- "-$pid" 2>/dev/null || true
            fi
        fi
    fi
    wait "$pid" 2>/dev/null || true
    CURRENT_PID=""
    CURRENT_PG=""

    write_summary "$test_dir" "$name" "$vcpus" "$ram_mib" "$transport" "$payload" \
        "$root_mode" "$devices" "$result" "$reason" "$ready_after" "$duration" "$interval"

    if [[ "$result" == "OK" ]]; then
        echo "  OK (guest ready after ${ready_after}s): $test_dir/summary.txt"
        return 0
    fi
    echo "  FAILED: $reason"
    return 1
}

main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --config) CONFIG_FILE=$2; shift 2 ;;
            --config=*) CONFIG_FILE=${1#*=}; shift ;;
            --results) RESULTS_DIR=$2; shift 2 ;;
            --results=*) RESULTS_DIR=${1#*=}; shift ;;
            --settle) SETTLE=$2; shift 2 ;;
            --settle=*) SETTLE=${1#*=}; shift ;;
            --duration) DURATION=$2; shift 2 ;;
            --duration=*) DURATION=${1#*=}; shift ;;
            --interval) INTERVAL=$2; shift 2 ;;
            --interval=*) INTERVAL=${1#*=}; shift ;;
            --list) LIST=1; shift ;;
            --dry-run) DRY_RUN=1; shift ;;
            --rebuild) REBUILD=1; shift ;;
            --keep-going) KEEP_GOING=1; shift ;;
            -h|--help) usage; return 0 ;;
            --) shift; SELECTED+=("$@"); break ;;
            -*) echo "unknown option: $1" >&2; usage >&2; return 1 ;;
            *) SELECTED+=("$1"); shift ;;
        esac
    done

    [[ "$SETTLE" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "--settle must be a number of seconds"
    [[ "$DURATION" =~ ^[0-9]+$ ]] || die "--duration must be an integer number of seconds"
    [[ "$INTERVAL" =~ ^[0-9]+$ ]] || die "--interval must be an integer number of seconds"
    [[ "$INTERVAL" -ge 1 ]] || die "--interval must be at least 1 second"

    [[ -f "$CONFIG_FILE" ]] || die "config file not found: $CONFIG_FILE"
    # shellcheck source=tests.conf
    source "$CONFIG_FILE"
    DEFAULT_APPEND_CMDLINE="${COMMON_APPEND_CMDLINE:-}"

    local all_tests
    all_tests=$(declare -F | awk '$3 ~ /^test_/ { sub(/^test_/, "", $3); print $3 }')
    [[ -n "$all_tests" ]] || die "no test_* functions found in $CONFIG_FILE"

    if [[ $LIST -eq 1 ]]; then
        printf '%s\n' "$all_tests"
        return 0
    fi

    local -a selected=()
    if [[ ${#SELECTED[@]} -eq 0 ]]; then
        mapfile -t selected <<< "$all_tests"
    else
        local t
        for t in "${SELECTED[@]}"; do
            if ! printf '%s\n' "$all_tests" | grep -qx -- "$t"; then
                die "unknown test '$t' (use --list)"
            fi
            selected+=("$t")
        done
    fi

    if [[ -z "$RESULTS_DIR" ]]; then
        RESULTS_DIR="$SCRIPT_DIR/results/$(date +%Y%m%d-%H%M%S)"
    fi
    if [[ $DRY_RUN -eq 0 && -e "$RESULTS_DIR" && -n "$(ls -A "$RESULTS_DIR" 2>/dev/null)" ]]; then
        die "results directory $RESULTS_DIR exists and is not empty (use --results DIR)"
    fi
    mkdir -p "$RESULTS_DIR"

    # The build is mtime-cached and cheap; doing it in dry-run too keeps the
    # per-test artifact assembly (e.g. cp of the workload) working.
    build_binaries
    if [[ $DRY_RUN -eq 0 ]]; then
        write_meta
    fi

    local failed=0 name
    for name in "${selected[@]}"; do
        echo "=== test: $name ==="
        COMPLETED+=("$name")
        if ! run_test "$name"; then
            failed=1
            if [[ $KEEP_GOING -eq 0 ]]; then
                echo "test $name failed; stopping (use --keep-going to continue)" >&2
                break
            fi
        fi
    done

    write_run_summary

    if [[ $failed -ne 0 ]]; then
        return 1
    fi
    echo "all tests passed"
}

main "$@"
