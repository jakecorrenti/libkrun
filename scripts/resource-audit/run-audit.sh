#!/usr/bin/env bash
#
# Runtime resource-usage audit for libkrun guests.
#
# Runs any VM launcher (the COMMAND and its arguments) under the full
# measurement pipeline: console captured, /proc/<pid> sampled from outside,
# and the article-style reports (summary, annotated memory map, categories,
# charts) written to the results directory.
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

LABEL_SHIM="$SCRIPT_DIR/build/mmap-label.so"
PHASE_HOOK="$SCRIPT_DIR/build/phase-hook.so"
VMA_PROBE="$SCRIPT_DIR/build/vma-probe"
CLK_TCK=$(getconf CLK_TCK)
CSV_HEADER="elapsed_s,vmrss_kib,rss_anon_kib,rss_file_kib,pss_kib,uss_kib,anon_kib,pte_kib,threads,fds,cpu_user_s,cpu_sys_s,cpu_guest_s"

RESULTS_DIR=""
SETTLE=10
DURATION=10
INTERVAL=1
REBUILD=0
WRAP_NAME=""
WRAP_RAM_MIB=0
WRAP_PHASE_PAUSE=10
WRAP_LABELS=1
WRAP_CMD=()

# Measurement state; the helpers below communicate through these.
MEAS_LAUNCH_TIME=""
RESULT=""
REASON=""
READY_AFTER=""
READY_FROM=""
PHASE_SEEN=0

LABEL_SHIM_BUILD_CMD=""
PHASE_HOOK_BUILD_CMD=""
VMA_PROBE_BUILD_CMD=""
CURRENT_PID=""
CURRENT_PG=""
COMPLETED=()

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] COMMAND [ARGS...]

Measures COMMAND (a VM launcher or any process) from outside: console
captured, /proc/<pid> sampled, article-style reports written to the
results directory.

Options:
  --name NAME        test name for outputs (default: COMMAND basename)
  --ram-mib N        guest RAM in MiB for exact guest-RAM matching (optional;
                     without it the multi-region method applies)
  --phase-pause S    seconds the phase hook holds libkrun launchers at
                     krun_vmm_run() (default 10)
  --settle S         max wait for the readiness marker (default 10)
  --duration S       sampling duration once ready (default 10)
  --interval S       sampling interval in seconds (default 1)
  --results DIR      output directory (default results/<timestamp>)
  --no-labels        don't preload the mmap/malloc label shim
  --rebuild          rebuild the shims even if up to date
  -h, --help         show this help

The first non-option argument starts COMMAND; everything after it belongs
to the command and is passed through untouched (so sh -c '...' and other
dash-args work). A literal -- immediately before COMMAND is also accepted
and skipped, as is a leading --wrap (both for compatibility with earlier
invocations). A command that itself starts with a dash needs the -- form.

Environment:
  KRUN_AUDIT_CC             C compiler (default: cc)
  KRUN_AUDIT_PREFIX         installation prefix of libkrun (default: /usr/local,
                            libraries are expected in \$PREFIX/lib64)
  KRUN_AUDIT_EXTRA_LD_PATH  extra LD_LIBRARY_PATH entries placed in front of
                            the prefix libdir — put a directory holding an
                            alternative libkrunfw.so.5 here to audit a
                            different guest kernel build
  KRUN_AUDIT_MALLOC_LABEL_KIB
                            malloc-labeling threshold in KiB (default 128),
                            read by the shim itself
EOF
}

die() {
    echo "run-audit.sh: $*" >&2
    exit 1
}

cleanup() {
    if [[ -n "$CURRENT_PID" ]] && kill -0 "$CURRENT_PID" 2>/dev/null; then
        kill -CONT "$CURRENT_PID" 2>/dev/null || true
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

status_field() { # status_field FILE "Key:" — value from a "Key: N kB" status line
    # Pure bash: the wrap fast-poll reads this twice per iteration, where an
    # awk spawn per read would dominate the capture cost.
    local line key=$2
    while IFS= read -r line; do
        if [[ $line == "$key"* ]]; then
            line=${line#"$key"}
            line=${line//[[:space:]]/}
            printf '%s' "${line%kB}"
            return 0
        fi
    done < "$1"
    return 1
}

signed_kib() { # signed_kib DELTA — "+N" or "-N", never the "+-N" a bare prefix renders
    local d=$1
    if (( d < 0 )); then
        echo "$d"
    else
        echo "+$d"
    fi
}

build_binaries() {
    mkdir -p "$SCRIPT_DIR/build"

    if [[ ! -f "$LABEL_SHIM" || "$SCRIPT_DIR/mmap-label.c" -nt "$LABEL_SHIM" || $REBUILD -eq 1 ]]; then
        "$CC" -O2 -shared -fPIC -o "$LABEL_SHIM" "$SCRIPT_DIR/mmap-label.c" -ldl
        LABEL_SHIM_BUILD_CMD="$CC -O2 -shared -fPIC -o build/mmap-label.so mmap-label.c -ldl"
    fi

    if [[ ! -f "$PHASE_HOOK" || "$SCRIPT_DIR/phase-hook.c" -nt "$PHASE_HOOK" || $REBUILD -eq 1 ]]; then
        "$CC" -O2 -shared -fPIC -o "$PHASE_HOOK" "$SCRIPT_DIR/phase-hook.c" -ldl
        PHASE_HOOK_BUILD_CMD="$CC -O2 -shared -fPIC -o build/phase-hook.so phase-hook.c -ldl"
    fi

    if [[ ! -f "$VMA_PROBE" || "$SCRIPT_DIR/vma-probe.c" -nt "$VMA_PROBE" || $REBUILD -eq 1 ]]; then
        "$CC" -O2 -o "$VMA_PROBE" "$SCRIPT_DIR/vma-probe.c"
        VMA_PROBE_BUILD_CMD="$CC -O2 -o build/vma-probe vma-probe.c"
    fi
}

sample_once() { # sample_once PID CSV_FILE SAMPLING_START — append one CSV row
    local pid=$1 out=$2 start=$3
    local elapsed fds row

    proc_alive "$pid" || return 1

    # find tolerates fds appearing or disappearing mid-scan
    fds=$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 -printf '.' 2>/dev/null | wc -c) || fds=0
    # exported for the wrap loop's change-triggered listing refresh and the
    # rise-chase trigger
    SAMPLE_FDS=$fds
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
    # the wrap rise-chase compares against this: a rise can start in the
    # ~15ms between the checkpoint capture and this read
    SAMPLE_RSS=$(cut -d, -f2 <<< "$row")
}

capture_proc_listings() { # capture_proc_listings PID DIR [PREFIX]
    # Writes ${PREFIX}fds.txt, ${PREFIX}threads.txt and ${PREFIX}task-stats.txt.
    # Shared by the live final snapshot and the wrap insurance checkpoint so
    # both paths produce identical listings.
    local pid=$1 dir=$2 prefix=${3:-}
    local fd target t tid sp

    : > "$dir/${prefix}fds.txt"
    for fd in /proc/$pid/fd/*; do
        [[ -L "$fd" ]] || continue
        target=$(readlink "$fd" 2>/dev/null) || target="(unreadable)"
        printf '%s %s\n' "${fd##*/}" "$target" >> "$dir/${prefix}fds.txt"
    done

    : > "$dir/${prefix}threads.txt"
    for t in /proc/$pid/task/*; do
        [[ -d "$t" ]] || continue
        printf '%s %s\n' "${t##*/}" "$(cat "$t/comm" 2>/dev/null)" >> "$dir/${prefix}threads.txt"
    done

    # One "tid comm sp" line per task. The sp is the user stack pointer from
    # the thread's blocked syscall (/proc/.../syscall, field 8): stat's
    # startstack is mm-wide (the same main-stack value for every thread) and
    # cannot attribute per-thread stacks. Threads not in a syscall report 0.
    : > "$dir/${prefix}task-stats.txt"
    for t in /proc/$pid/task/*; do
        [[ -d "$t" ]] || continue
        tid=${t##*/}
        sp=$(awk '{ print $8 }' "$t/syscall" 2>/dev/null) || sp=""
        printf '%s %s %s\n' "$tid" "$(cat "$t/comm" 2>/dev/null)" "${sp:-0}" >> "$dir/${prefix}task-stats.txt"
    done
}

write_libs_txt() { # write_libs_txt BINARY MAPS_FILE SUBJECT DIR [LD_PATH]
    local binary=$1 maps=$2 subject=$3 dir=$4 lib

    # ldd resolves the way the launcher itself did — wrapped commands have
    # no rpath, so without the library path their libs report "not found".
    {
        LD_LIBRARY_PATH="${5:-$LIBDIR}" ldd "$binary" 2>/dev/null || true
        echo
        echo "krun libraries actually mapped by $subject (from $(basename "$maps")):"
        awk '{ for (i = 6; i <= NF; i++) if ($i ~ /\/libkrun[^/]*\.so/) print $i }' "$maps" 2>/dev/null \
            | sort -u | while read -r lib; do
            printf '  %s -> %s\n' "$lib" "$(readlink -f "$lib")"
        done
    } > "$dir/libs.txt"
}

take_final_snapshot() { # take_final_snapshot PID TEST_DIR BINARY LD_PATH
    local pid=$1 dir=$2 binary=$3 ld_path=$4

    cp "/proc/$pid/status" "$dir/final-status.txt" 2>/dev/null || true
    cp "/proc/$pid/smaps" "$dir/final-smaps.txt" 2>/dev/null || true
    cp "/proc/$pid/smaps_rollup" "$dir/final-smaps_rollup.txt" 2>/dev/null || true
    cp "/proc/$pid/maps" "$dir/final-maps.txt" 2>/dev/null || true
    cp "/proc/$pid/io" "$dir/final-io.txt" 2>/dev/null || true

    capture_proc_listings "$pid" "$dir"

    write_libs_txt "$binary" "$dir/final-maps.txt" "the wrapped launcher" "$dir" "$ld_path"
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

write_summary() { # write_summary TEST_DIR NAME CONFIG_LABEL RAM_MIB RESULT_LINE DURATION INTERVAL [METRICS_LINES...]
    local test_dir=$1 name=$2 config_label=$3 ram_mib=$4 result_line=$5
    local duration=$6 interval=$7
    shift 7
    local result_word="${result_line%% (*}"

    local status="$test_dir/final-status.txt"
    local rollup="$test_dir/final-smaps_rollup.txt"
    local io="$test_dir/final-io.txt"
    local parsed="$test_dir/parsed-smaps.tsv"

    # Pre-boot phase (the phase-hook shim holding krun_vmm_run()):
    # end-of-phase counters come from the last samples-preboot.csv row.
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
        awk -v ram_kib=$((ram_mib * 1024)) -v launcher="$(basename "${WRAP_CMD[0]}")" \
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
        echo "Config: $config_label"
        echo "Result: $result_line"
        if [[ -f "$test_dir/final-snapshot-note.txt" ]]; then
            cat "$test_dir/final-snapshot-note.txt"
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
            echo "boot cost: VmRSS $(signed_kib $(( vmrss - pb_vmrss ))) KiB, Anonymous $(signed_kib $(( anon_r - pb_anon ))) KiB (guest RAM + kernel COW)"
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
        local ml
        for ml in "$@"; do
            echo "$ml"
        done
        echo "result=$result_word"
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
        echo "| test | ram | RSS | RssAnon | USS | PSS | guest_ram_rss | vmm_private_anon | VmPTE | threads | fds | cpu_user_s | cpu_sys_s | cpu_guest_s | result |"
        echo "|------|-----|-----|---------|-----|-----|---------------|------------------|-------|---------|-----|------------|------------|--------------|--------|"
        local name m
        for name in "${COMPLETED[@]}"; do
            m="$RESULTS_DIR/$name/metrics.txt"
            if [[ -f "$m" ]]; then
                awk -F= -v t="$name" '
                    /^(ram_mib|vmrss_kib|rss_anon_kib|uss_kib|pss_kib|guest_ram_rss_kib|vmm_private_anon_kib|vmpte_kib|threads|fds|cpu_user_s|cpu_sys_s|cpu_guest_s|result)=/ {
                        v[$1] = $2
                    }
                    function val(k) {
                        if (k in v && v[k] != "") return v[k]
                        return "-"
                    }
                    END {
                        printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", \
                            t, val("ram_mib"), \
                            val("vmrss_kib"), val("rss_anon_kib"), val("uss_kib"), val("pss_kib"), val("guest_ram_rss_kib"), \
                            val("vmm_private_anon_kib"), val("vmpte_kib"), val("threads"), val("fds"), \
                            val("cpu_user_s"), val("cpu_sys_s"), val("cpu_guest_s"), val("result")
                    }' "$m"
            else
                echo "| $name | - | - | - | - | - | - | - | - | - | - | - | - | - | not run |"
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
        echo "mmap-label shim: ${LABEL_SHIM_BUILD_CMD:-cached from previous run}"
        echo "phase-hook shim: ${PHASE_HOOK_BUILD_CMD:-cached from previous run}"
        echo "settle=${SETTLE}s duration=${DURATION}s interval=${INTERVAL}s"
        echo "CONFIG_ANON_VMA_NAME: $anon_labels ($anon_source) — glibc's"
        echo "  GLIBC_TUNABLES=glibc.mem.decorate_maps=1 labels and the label_mmap shim both"
        echo "  depend on it; without it anonymous mappings carry no [anon:...] labels in smaps"
        echo "  and guest RAM is identified by size only (see parse-smaps.awk)."
        echo "vma probe build: ${VMA_PROBE_BUILD_CMD:-cached from previous run}"
    } > "$RESULTS_DIR/meta.txt"
}

# ----- measurement core -----

sample_window() { # sample_window VM_PID CSV START COUNT INTERVAL DEATH_REASON
    local vm_pid=$1 csv=$2 start=$3 n=$4 interval=$5 death=$6 i

    if (( n < 1 )); then n=1; fi
    for ((i = 0; i < n; i++)); do
        if ! sample_once "$vm_pid" "$csv" "$start"; then
            RESULT="FAILED"
            REASON="$death"
            return 1
        fi
        if (( i < n - 1 )); then
            sleep "$interval"
        fi
    done
}

teardown_launcher() { # teardown_launcher PID VM_PID PG — TERM, then KILL, then reap
    local pid=$1 vm_pid=$2 pg=$3

    # undo a chase freeze: a stopped process pockets TERM until continued
    kill -CONT "$pid" "$vm_pid" 2>/dev/null || true
    if proc_alive "$pid" || proc_alive "$vm_pid"; then
        kill -TERM "$pid" "$vm_pid" 2>/dev/null || true
        if [[ -n "$pg" ]]; then
            kill -TERM -- "-$pg" 2>/dev/null || true
        fi
        local waited=0
        while (proc_alive "$pid" || proc_alive "$vm_pid") && (( waited < 100 )); do
            sleep 0.1
            waited=$((waited + 1))
        done
        if proc_alive "$pid" || proc_alive "$vm_pid"; then
            kill -KILL "$pid" "$vm_pid" 2>/dev/null || true
            if [[ -n "$pg" ]]; then
                kill -KILL -- "-$pg" 2>/dev/null || true
            fi
        fi
    fi
    wait "$pid" 2>/dev/null || true
    CURRENT_PID=""
    CURRENT_PG=""
}

wrap_capture_step() { # one insurance capture; runs in run_wrap's scope
    # (bash dynamic scoping): reads vm_pid/test_dir/MEAS_LAUNCH_TIME and the
    # listing-trigger state, updates cp_rss/cp_threads and the best-*
    # checkpoint. Shared by the 0.1s fast-poll loop and the rise-chase below.
    local snapf

    # status is written LAST on purpose: the peak iteration is often also
    # the death iteration, and a mid-loop death truncates the files after it
    # (the shell opens the redirect before cat runs). A non-empty cp-status
    # therefore proves the whole set was read from a living process; an
    # empty one makes cp_rss empty and the set is never promoted, leaving
    # the previous complete checkpoint in best-*.
    for snapf in smaps smaps_rollup maps io status; do
        cat "/proc/$vm_pid/$snapf" > "$test_dir/cp-$snapf.txt" 2>/dev/null || true
    done
    cp_rss=$(status_field "$test_dir/cp-status.txt" "VmRSS:")
    cp_threads=$(status_field "$test_dir/cp-status.txt" "Threads:")

    # The fd/thread listings cost ~15ms (a readlink per fd), so refresh
    # them only when something plausibly changed: first iteration, a
    # thread- or fd-count change, or a strict RSS increase. A post-
    # teardown collapse changes the counts too, but its low RSS can never
    # reach the best-* promotion below, so the collapsed listings are
    # simply overwritten scratch.
    if [[ ! -f "$test_dir/cp-fds.txt" ]] \
            || [[ "$cp_threads" != "$list_threads" ]] \
            || [[ "${SAMPLE_FDS:-}" != "$list_fds" ]] \
            || { [[ -n "$cp_rss" ]] && (( cp_rss > best_rss )); }; then
        capture_proc_listings "$vm_pid" "$test_dir" "cp-"
        list_threads=$cp_threads
        list_fds=${SAMPLE_FDS:-}
        # A process can die mid-capture (the peak iteration is often the
        # last), leaving truncated listings; the status read that armed
        # this refresh happened before the death. Only a capture of a
        # still-living process may reach best-*, so the previous good
        # listing survives as the near-peak one.
        if ! proc_alive "$vm_pid"; then
            rm -f "$test_dir/cp-fds.txt" "$test_dir/cp-threads.txt" \
                "$test_dir/cp-task-stats.txt"
        fi
    fi

    if [[ -n "$cp_rss" ]] && (( cp_rss >= best_rss )); then
        best_rss=$cp_rss
        best_at=$(elapsed_between "$MEAS_LAUNCH_TIME")
        # -s: never let a truncated read through, even though the
        # status-last ordering already gates the set on completeness
        for snapf in status smaps smaps_rollup maps io fds threads task-stats; do
            [[ -s "$test_dir/cp-$snapf.txt" ]] || continue
            cat "$test_dir/cp-$snapf.txt" > "$test_dir/best-$snapf.txt" 2>/dev/null || true
        done
    fi
}

run_wrap() { # run_wrap — measure the wrapped launcher; returns nonzero on failure
    local name=$WRAP_NAME
    local test_dir="$RESULTS_DIR/$name"
    mkdir -p "$test_dir"

    local console_log="$test_dir/guest-console.log"
    local ld_path="${KRUN_AUDIT_EXTRA_LD_PATH:+$KRUN_AUDIT_EXTRA_LD_PATH:}$LIBDIR"
    # The phase hook is always preloaded: without KRUN_AUDIT_PHASE_PAUSE it is
    # a pass-through, and launchers that never call krun_vmm_run() skip it.
    local preload="$PHASE_HOOK"
    if [[ $WRAP_LABELS -eq 1 ]]; then
        preload="$preload:$LABEL_SHIM"
    fi

    {
        echo "# environment"
        echo "LD_LIBRARY_PATH=$ld_path"
        echo "GLIBC_TUNABLES=glibc.mem.decorate_maps=1"
        echo "LD_PRELOAD=$preload"
        echo "KRUN_AUDIT_PHASE_PAUSE=$WRAP_PHASE_PAUSE"
        echo "# knobs"
        echo "label_mmap=$WRAP_LABELS"
        echo "phase_pause=$WRAP_PHASE_PAUSE"
        echo "ram_mib=$WRAP_RAM_MIB"
        echo "# launched from the caller's cwd"
        printf 'cmdline:'
        printf ' %q' "${WRAP_CMD[@]}"
        echo
    } > "$test_dir/cmd.txt"

    local -a env_cmd=(env LD_LIBRARY_PATH="$ld_path" GLIBC_TUNABLES=glibc.mem.decorate_maps=1
                      "LD_PRELOAD=$preload" "KRUN_AUDIT_PHASE_PAUSE=$WRAP_PHASE_PAUSE"
                      "${WRAP_CMD[@]}")

    # No cd: the wrapped command's relative paths resolve from the caller's
    # cwd, like a manual invocation.
    ( exec "${env_cmd[@]}" </dev/null >"$console_log" 2>&1 ) &
    local pid=$!
    CURRENT_PID=$pid
    CURRENT_PG=""
    local vm_pid=$pid

    MEAS_LAUNCH_TIME=$EPOCHREALTIME
    RESULT="OK"
    REASON=""
    READY_AFTER=""
    READY_FROM=$MEAS_LAUNCH_TIME

    # One fast-poll loop covers the whole run: it samples into samples.csv
    # and captures an insurance snapshot set from launch until the readiness
    # marker or process exit. When the VMM-built marker appears (launcher
    # calls krun_vmm_run() through the PLT), sampling switches to
    # samples-preboot.csv for the pause window and comes back afterwards —
    # so launchers that never emit it, or die before emitting it, still get
    # a fully sampled run.
    #
    # The insurance set is captured as a whole on every iteration: the
    # interesting window can be sub-second (the event loop spinning up after
    # a phase pause), and a split cadence once produced mixed-state pairs —
    # status from the post-teardown collapse, smaps from mid-run. The
    # captures use shell redirects, not cp: procfs files are mode 444, and a
    # cp-created copy inherits that, making every later cp onto it fail
    # silently — which froze the old last-* files at their first capture.
    # cp-* is the per-iteration scratch set; best-* is the peak-RSS
    # checkpoint (>=, so a flat-at-peak run keeps it fresh) promoted to
    # final-* when the process exits before a live snapshot can be taken.
    local samples="$test_dir/samples.csv"
    echo "$CSV_HEADER" > "$samples"
    local run_start=$EPOCHREALTIME
    local budget_start=$run_start
    local budget
    budget=$(awk -v a="$SETTLE" -v b="$DURATION" 'BEGIN { print a + b }')
    local ready_seen=0 exited=0 exit_code=0 phase_done=0
    local best_rss=0 best_at=0 cp_rss="" prev_rss=0
    local cp_threads="" list_threads="" list_fds=""
    # After the pre-boot phase returns (~1s before the pause ends), poll at
    # tight cadence: the post-pause transition (event loop spin-up, workload
    # peak, teardown, exit) is often a ~30-100ms window that a 0.1s grid can
    # step over entirely. Covers the margin plus the transition itself.
    local poll_sleep=0.1 tight_from=0
    while :; do
        if ! proc_alive "$vm_pid"; then
            exited=1
            break
        fi
        if [[ $WRAP_PHASE_PAUSE -gt 0 && $phase_done -eq 0 ]] \
                && grep -aFq "AUDIT_PHASE_VMM_BUILT" "$console_log" 2>/dev/null; then
            phase_done=1
            local preboot_csv="$test_dir/samples-preboot.csv"
            echo "$CSV_HEADER" > "$preboot_csv"
            local preboot_start=$EPOCHREALTIME
            local preboot_n=$(( (WRAP_PHASE_PAUSE - 1) / INTERVAL ))
            if (( preboot_n < 1 )); then preboot_n=1; fi
            local pi ok=1
            for ((pi = 0; pi < preboot_n; pi++)); do
                if ! sample_once "$vm_pid" "$preboot_csv" "$preboot_start"; then
                    exited=1
                    ok=0
                    break
                fi
                if (( pi < preboot_n - 1 )); then
                    sleep "$INTERVAL"
                fi
            done
            if [[ $ok -eq 1 ]] && proc_alive "$vm_pid"; then
                cat "/proc/$vm_pid/status" > "$test_dir/preboot-status.txt" 2>/dev/null || true
                cat "/proc/$vm_pid/smaps" > "$test_dir/preboot-smaps.txt" 2>/dev/null || true
                cat "/proc/$vm_pid/maps" > "$test_dir/preboot-maps.txt" 2>/dev/null || true
                cat "/proc/$vm_pid/io" > "$test_dir/preboot-io.txt" 2>/dev/null || true
            fi
            if [[ $exited -eq 1 ]]; then
                break
            fi
            # the guest only starts executing when the pause window closes
            budget_start=$EPOCHREALTIME
            poll_sleep=0.01
            tight_from=$EPOCHREALTIME
            continue
        fi
        if grep -aFq "AUDIT_GUEST_READY" "$console_log" 2>/dev/null; then
            ready_seen=1
            READY_AFTER=$(elapsed_between "$MEAS_LAUNCH_TIME")
            break
        fi
        # Capture before sample_once: its /proc walks take ~15ms, and the
        # peak window sits at the very end of short runs — sampling first
        # would risk losing the capture to a mid-sample death.
        wrap_capture_step
        sample_once "$vm_pid" "$samples" "$run_start" || true

        # Chase a rising RSS at tight cadence: transitions (the event loop
        # spinning up after the phase pause, a workload's peak) are shorter
        # than the 0.1s grid and often end in the process exiting, which
        # would leave the peak uncaptured. Follow the rise until it settles,
        # drops (teardown) or the process dies. Blocked only while the
        # pre-boot phase is still pending (the marker stays in the log
        # forever, so testing for it alone would disable the chase for the
        # whole post-marker run). The step cap bounds a long ramp; the
        # plateau never triggers a chase.
        local chase_steps=0
        while proc_alive "$vm_pid" && [[ -n "$cp_rss" ]] \
                && (( cp_rss > prev_rss || SAMPLE_RSS > prev_rss )) \
                && (( chase_steps < 100 )) \
                && ! { [[ $phase_done -eq 0 ]] \
                        && grep -aFq "AUDIT_PHASE_VMM_BUILT" "$console_log" 2>/dev/null; }; do
            prev_rss=$cp_rss
            chase_steps=$((chase_steps + 1))
            # Freeze for the capture: a rising-RSS transition often ends in
            # the process exiting within tens of milliseconds, and even a
            # living process advances between the five file reads (several
            # MB/s of skew during the spin-up). A frozen process can do
            # neither — the checkpoint and its sample row are an exact
            # point-in-time pair. The ~20ms stall is invisible to the
            # metrics (nothing advances while stopped).
            kill -STOP "$vm_pid" 2>/dev/null || break
            wrap_capture_step
            sample_once "$vm_pid" "$samples" "$run_start" || true
            kill -CONT "$vm_pid" 2>/dev/null || true
            if ! proc_alive "$vm_pid"; then
                break
            fi
            sleep 0.01
        done
        prev_rss=$cp_rss
        if time_up "$budget_start" "$budget"; then
            break
        fi
        if [[ $poll_sleep != 0.1 ]] && time_up "$tight_from" 2.5; then
            poll_sleep=0.1
        fi
        sleep "$poll_sleep"
    done

    local result_line
    if [[ $exited -eq 1 ]]; then
        # COMPLETE: the launcher ran to completion; report its exit code.
        wait "$pid" 2>/dev/null
        exit_code=$?
        CURRENT_PID=""
        local f
        if [[ ! -f "$test_dir/final-status.txt" && -f "$test_dir/best-status.txt" ]]; then
            # The process is gone; final-* becomes the peak-RSS checkpoint.
            # write_summary picks up the note so the provenance is visible.
            for f in status smaps smaps_rollup maps io; do
                cp "$test_dir/best-$f.txt" "$test_dir/final-$f.txt"
            done
            # The listings keep their unprefixed names: write_summary and
            # annotate-maps.py read fds.txt/threads.txt/task-stats.txt.
            for f in fds threads task-stats; do
                if [[ -f "$test_dir/best-$f.txt" ]]; then
                    cp "$test_dir/best-$f.txt" "$test_dir/$f.txt"
                fi
            done
            # ldd needs only the binary and the promoted map, so the
            # library report survives the process.
            [[ -f "$test_dir/final-maps.txt" ]] && \
                write_libs_txt "${WRAP_CMD[0]}" "$test_dir/final-maps.txt" \
                    "the wrapped launcher" "$test_dir" "$ld_path"
            {
                printf 'Note: final snapshot is the peak-RSS checkpoint during the run'
                printf ' (VmRSS %s KiB at ~%ss, thread/fd listings captured near the peak)' \
                    "$best_rss" "$best_at"
                printf ' — the process exited before a live snapshot.\n'
            } > "$test_dir/final-snapshot-note.txt"
        fi
        local ran
        ran=$(elapsed_between "$MEAS_LAUNCH_TIME")
        if [[ $exit_code -eq 0 ]]; then
            result_line="OK (run-to-completion, exit code 0, ran ${ran}s)"
        else
            result_line="FAILED (exit code $exit_code)"
        fi
    elif [[ $ready_seen -eq 1 ]]; then
        # STEADY: marker-gated sampling for the configured duration.
        sample_window "$vm_pid" "$samples" "$run_start" \
            $(( DURATION / INTERVAL )) "$INTERVAL" "launcher exited during sampling"
        if proc_alive "$vm_pid"; then
            take_final_snapshot "$vm_pid" "$test_dir" "${WRAP_CMD[0]}" "$ld_path"
        else
            RESULT="FAILED"
            REASON="launcher exited during sampling"
        fi
        teardown_launcher "$pid" "$vm_pid" ""
        if [[ "$RESULT" == "OK" ]]; then
            result_line="OK (guest ready after ${READY_AFTER}s)"
        else
            result_line="FAILED ($REASON)"
        fi
    else
        # Neither marker nor exit within the budget: treat like a marker-less
        # payload — the RUN loop already sampled the whole window.
        if proc_alive "$vm_pid"; then
            take_final_snapshot "$vm_pid" "$test_dir" "${WRAP_CMD[0]}" "$ld_path"
        fi
        teardown_launcher "$pid" "$vm_pid" ""
        result_line="OK (no readiness marker; settle wait completed)"
    fi

    rm -f "$test_dir"/cp-*.txt "$test_dir"/best-*.txt

    local config_label
    config_label="${WRAP_CMD[*]}"
    if [[ $WRAP_RAM_MIB -gt 0 ]]; then
        config_label="$config_label (ram_mib=$WRAP_RAM_MIB)"
    fi
    write_summary "$test_dir" "$name" "$config_label" "$WRAP_RAM_MIB" \
        "$result_line" "$DURATION" "$INTERVAL" "ram_mib=$WRAP_RAM_MIB"

    if [[ "${result_line%% (*}" == "OK" ]]; then
        echo "  $result_line: $test_dir/summary.txt"
        return 0
    fi
    echo "  FAILED: $(awk -v s="$result_line" 'BEGIN { sub(/^FAILED \(/, "", s); sub(/\)$/, "", s); print s }')"
    return 1
}

main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name) WRAP_NAME=$2; shift 2 ;;
            --name=*) WRAP_NAME=${1#*=}; shift ;;
            --ram-mib) WRAP_RAM_MIB=$2; shift 2 ;;
            --ram-mib=*) WRAP_RAM_MIB=${1#*=}; shift ;;
            --phase-pause) WRAP_PHASE_PAUSE=$2; shift 2 ;;
            --phase-pause=*) WRAP_PHASE_PAUSE=${1#*=}; shift ;;
            --settle) SETTLE=$2; shift 2 ;;
            --settle=*) SETTLE=${1#*=}; shift ;;
            --duration) DURATION=$2; shift 2 ;;
            --duration=*) DURATION=${1#*=}; shift ;;
            --interval) INTERVAL=$2; shift 2 ;;
            --interval=*) INTERVAL=${1#*=}; shift ;;
            --results) RESULTS_DIR=$2; shift 2 ;;
            --results=*) RESULTS_DIR=${1#*=}; shift ;;
            --no-labels) WRAP_LABELS=0; shift ;;
            --rebuild) REBUILD=1; shift ;;
            # compatibility with earlier invocations
            --wrap) shift ;;
            -h|--help) usage; return 0 ;;
            --)
                # the command follows; everything after belongs to it
                shift
                WRAP_CMD=("$@")
                break ;;
            -*)
                echo "unknown option: $1 (a command starting with a dash needs an explicit -- before it)" >&2
                usage >&2
                return 1 ;;
            *)
                # the first non-option argument starts the command; the rest
                # of the line is passed through untouched
                WRAP_CMD=("$@")
                break ;;
        esac
    done

    [[ "$SETTLE" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "--settle must be a number of seconds"
    [[ "$DURATION" =~ ^[0-9]+$ ]] || die "--duration must be an integer number of seconds"
    [[ "$INTERVAL" =~ ^[0-9]+$ ]] || die "--interval must be an integer number of seconds"
    [[ "$INTERVAL" -ge 1 ]] || die "--interval must be at least 1 second"

    [[ ${#WRAP_CMD[@]} -gt 0 ]] || die "no command given (pass it after the options)"
    [[ "$WRAP_RAM_MIB" =~ ^[0-9]+$ ]] || die "--ram-mib must be a number"
    [[ "$WRAP_PHASE_PAUSE" =~ ^[0-9]+$ ]] || die "--phase-pause must be a number of seconds"
    if [[ -z "$WRAP_NAME" ]]; then
        WRAP_NAME=$(basename "${WRAP_CMD[0]}")
    fi
    [[ "$WRAP_NAME" != */* && "$WRAP_NAME" != *..* ]] || die "invalid --name '$WRAP_NAME'"

    if [[ -z "$RESULTS_DIR" ]]; then
        RESULTS_DIR="$SCRIPT_DIR/results/$(date +%Y%m%d-%H%M%S)"
    fi
    if [[ -e "$RESULTS_DIR" && -n "$(ls -A "$RESULTS_DIR" 2>/dev/null)" ]]; then
        die "results directory $RESULTS_DIR exists and is not empty (use --results DIR)"
    fi
    mkdir -p "$RESULTS_DIR"
    build_binaries
    write_meta

    echo "=== measuring: $WRAP_NAME ==="
    COMPLETED+=("$WRAP_NAME")
    local failed=0
    if ! run_wrap; then
        failed=1
    fi
    write_run_summary

    if [[ $failed -ne 0 ]]; then
        return 1
    fi
    echo "all tests passed"
}

main "$@"
