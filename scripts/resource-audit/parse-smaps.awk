# parse-smaps.awk — turn a /proc/PID/smaps snapshot into resource-audit rows.
#
# Usage: awk -v ram_kib=N -v harness=FRAGMENT [-f parse-smaps.awk] FILE
#
# Emits tab-separated records (OFS is set to TAB):
#   MAP      <size> <rss> <anon> <pss> <uss> <perms> <label>   (per mapping)
#   TOTAL    <rss> <anon> <pss> <uss> <shared>
#   GUESTRAM <method> <nregions> <rss> <anon>
#   ROLLUP   <category> <rss> <anon>
#
# Guest-RAM identification: libkrun mmaps guest RAM as anonymous rw regions.
# With typical sizes the main region matches the requested RAM exactly, so
# anonymous rw mappings of exactly ram_kib are summed ("exact-size match");
# without a match the single largest anonymous mapping is used instead
# ("largest-anon fallback"). The small low-memory region below the kernel
# load address is not separable from other anonymous mappings and is counted
# under "other-anon" (its RSS is typically far below 1 MiB).
#
# Categories: guest-RAM, kvm (anon_inode:kvm-*), libkrun.so (includes
# libkrun_init.so, the embedded guest init), libkrunfw.so, system-libs
# (libc/ld and other .so files), harness, heap, stack, other-anon,
# other-file.

function unlabeled_anon(p) {
    return p == "" || p ~ /^\[anon/
}

function anon_like(p) {
    return p == "" || p ~ /^\[/
}

function flush() {
    if (!have) {
        return
    }
    n++
    m_size[n] = size
    m_rss[n] = rss
    m_anon[n] = anon
    m_pss[n] = pss
    m_uss[n] = pc + pd
    m_shared[n] = sc + sd
    m_perms[n] = perms
    m_path[n] = path
}

function category(i,    p) {
    p = m_path[i]
    if (gram_idx[i]) {
        return "guest-RAM"
    }
    if (p == "[heap]") {
        return "heap"
    }
    if (p == "[stack]" || p ~ /^\[stack:/) {
        return "stack"
    }
    if (p ~ /anon_inode:kvm/) {
        return "kvm"
    }
    if (p ~ /libkrunfw\.so/) {
        return "libkrunfw.so"
    }
    if (p ~ /libkrun\.so/ || p ~ /libkrun_init\.so/) {
        return "libkrun.so"
    }
    if (harness != "" && index(p, harness) > 0) {
        return "harness"
    }
    if (p ~ /\.so(\.[0-9]+)*$/ || p ~ /\/ld-linux/) {
        return "system-libs"
    }
    if (anon_like(p)) {
        return "other-anon"
    }
    return "other-file"
}

BEGIN { OFS = "\t" }

# Mapping header: "addr-addr perms offset dev inode [pathname...]".
$1 ~ /^[0-9a-f]+-[0-9a-f]+$/ && $2 ~ /^[r-][w-][x-][ps]$/ {
    flush()
    perms = $2
    path = ""
    for (i = 6; i <= NF; i++) {
        path = path (path == "" ? "" : " ") $i
    }
    size = rss = pss = anon = pc = pd = sc = sd = 0
    have = 1
    next
}

/^Size:/ { size = $2; next }
/^Rss:/ { rss = $2; next }
/^Pss:/ { pss = $2; next }
/^Private_Clean:/ { pc = $2; next }
/^Private_Dirty:/ { pd = $2; next }
/^Shared_Clean:/ { sc = $2; next }
/^Shared_Dirty:/ { sd = $2; next }
/^Anonymous:/ { anon = $2; next }

END {
    flush()

    gram_n = 0
    gram_rss = 0
    gram_anon = 0
    gram_merged = 0
    lg = 0
    lg_size = 0
    for (i = 1; i <= n; i++) {
        # ram exactly, or ram + the 16 MiB low-memory region when the host
        # kernel merged the two anonymous RAM mmaps into one VMA
        if (ram_kib > 0 && unlabeled_anon(m_path[i]) && m_perms[i] ~ /^rw/ \
            && (m_size[i] == ram_kib || m_size[i] == ram_kib + 16384)) {
            gram_n++
            gram_rss += m_rss[i]
            gram_anon += m_anon[i]
            gram_idx[i] = 1
            if (m_size[i] == ram_kib + 16384) {
                gram_merged = 1
            }
        }
        if (unlabeled_anon(m_path[i]) && m_size[i] > lg_size) {
            lg = i
            lg_size = m_size[i]
        }
    }
    if (gram_n > 0) {
        method = gram_merged ? "merged-size match" : "exact-size match"
    } else if (lg > 0) {
        method = "largest-anon fallback"
        gram_n = 1
        gram_rss = m_rss[lg]
        gram_anon = m_anon[lg]
        gram_idx[lg] = 1
    } else {
        method = "none"
    }

    for (i = 1; i <= n; i++) {
        label = m_path[i]
        if (label == "") {
            label = sprintf("[%s:%dk]", (gram_idx[i] ? "guest-RAM" : "anon"), m_size[i])
        }
        print "MAP", m_size[i], m_rss[i], m_anon[i], m_pss[i], m_uss[i], m_perms[i], label

        cat = category(i)
        c_rss[cat] += m_rss[i]
        c_anon[cat] += m_anon[i]
        t_rss += m_rss[i]
        t_anon += m_anon[i]
        t_pss += m_pss[i]
        t_uss += m_uss[i]
        t_shared += m_shared[i]
    }

    print "TOTAL", t_rss + 0, t_anon + 0, t_pss + 0, t_uss + 0, t_shared + 0
    print "GUESTRAM", method, gram_n + 0, gram_rss + 0, gram_anon + 0

    split("guest-RAM kvm libkrun.so libkrunfw.so system-libs harness heap stack other-anon other-file", order, " ")
    for (j = 1; j <= 10; j++) {
        if (order[j] in c_rss || order[j] in c_anon) {
            print "ROLLUP", order[j], c_rss[order[j]] + 0, c_anon[order[j]] + 0
        }
    }
}
