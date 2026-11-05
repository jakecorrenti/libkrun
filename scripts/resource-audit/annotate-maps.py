#!/usr/bin/env python3
"""Annotate the memory map of a libkrun resource-audit test snapshot.

Reads {input-prefix}smaps.txt (the source of truth: its block headers carry
the full maps line), {input-prefix}status.txt, task-stats.txt and metrics.txt
from TEST_DIR and writes into TEST_DIR:

  {output-prefix}maps-annotated.txt   multi-section annotated map (pymap-style):
                                      full map, segments excluding empty
                                      reservations, by RSS, by anonymous,
                                      each with its own totals, plus a
                                      category charge table
  {output-prefix}categories.csv       reservation (RO/RW/none) / RSS / anon
                                      rollup per category
  charts/                              reservation and RSS pies, RO/RW bars

--input-prefix/--output-prefix select the phase: the default (final-) is the
end-of-run snapshot; preboot- addresses the VMM-built-before-guest snapshot
taken for --pause-before-run tests. task-stats.txt and metrics.txt are shared
between phases unless a prefixed copy exists.

Annotations are inferred from what the kernel exposes: ELF sections for
file-backed mappings, thread stacks from per-task user stack pointers,
glibc arena pairs by their 64 MiB pattern, and guest RAM by size. When the
kernel itself labels anonymous mappings (CONFIG_ANON_VMA_NAME — glibc's
decorate_maps names, the label_mmap shim's "krun:" names), the kernel label
is the base: it is passed through verbatim, augmented where noted (thread
stacks get their comm, guest RAM keeps its identification), and the
inference passes only run on unlabeled mappings. stdout carries only the
totals block; run-audit.sh appends it to summary.txt.
"""

import argparse
import math
import os
import re
import struct
import sys

KiB = 1024
ARENA_TOTAL_KIB = 64 * KiB  # glibc HEAP_MAX_SIZE
GUEST_RAM_LOW_KIB = 16 * KiB  # x86_64 kernel load address below main RAM

SMAPS_HEADER = re.compile(r"^([0-9a-f]+)-([0-9a-f]+) (\S{4}) (\S+) (\S+) (\d+) *(\S*.*)$")
KB_LINE = re.compile(r"^(\w+):\s+(\d+) kB$")
# Named anonymous mappings show up as [anon:<name>]; glibc's names carry a
# leading space ("[anon: glibc: malloc]"), so tolerate one when unwrapping.
KERNEL_ANON_RE = re.compile(r"^\[anon:\s*(.*?)\s*\]$")

PALETTE = ["#4e79a7", "#f28e2b", "#e15759", "#76b7b2", "#59a14f",
           "#edc948", "#b07aa1", "#ff9da7", "#9c755f", "#bab0ac"]
COLOR_RO = "#4e79a7"
COLOR_RW = "#f28e2b"
COLOR_NONE = "#bab0ac"

COUNTERS = ("size", "rss", "pss", "shared_clean", "shared_dirty",
            "private_clean", "private_dirty", "anon")

PSEUDO_PASSTHROUGH = ("[heap]", "[stack]", "[vdso]", "[vvar]",
                      "[vvar_vclock]", "[vsyscall]")


class Vma:
    __slots__ = ("start", "end", "perms", "offset", "dev", "inode", "path",
                 "size", "rss", "pss", "shared_clean", "shared_dirty",
                 "private_clean", "private_dirty", "anon", "label", "segments")

    def __init__(self, start, end, perms, offset, dev, inode, path):
        self.start = start
        self.end = end
        self.perms = perms
        self.offset = offset
        self.dev = dev
        self.inode = inode
        self.path = path
        self.size = 0
        self.rss = 0
        self.pss = 0
        self.shared_clean = 0
        self.shared_dirty = 0
        self.private_clean = 0
        self.private_dirty = 0
        self.anon = 0
        self.label = ""
        self.segments = ""

    @property
    def dirty(self):
        return self.shared_dirty + self.private_dirty

    @property
    def uss(self):
        return self.private_clean + self.private_dirty


def parse_smaps(path):
    vmas = []
    cur = None
    with open(path, "r", errors="replace") as f:
        for line in f:
            m = SMAPS_HEADER.match(line)
            if m:
                cur = Vma(int(m.group(1), 16), int(m.group(2), 16), m.group(3),
                          int(m.group(4), 16), m.group(5), m.group(6),
                          m.group(7).strip())
                vmas.append(cur)
                continue
            m = KB_LINE.match(line)
            if m and cur is not None:
                key = m.group(1).lower()
                if key == "anonymous":
                    key = "anon"
                if key in COUNTERS:
                    setattr(cur, key, int(m.group(2)))
    vmas.sort(key=lambda v: v.start)
    return vmas


def parse_task_stats(path):
    """task-stats.txt lines are "tid comm sp" (comm may contain spaces).

    The third field is the thread's user stack pointer as seen by its
    blocked syscall (/proc/PID/task/TID/syscall, field 8) — /proc's
    startstack is mm-wide and identical for every thread, so it cannot
    attribute stacks. Threads not in a syscall report 0.
    """
    tasks = []
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                sp = parts[-1]
                try:
                    sp = int(sp, 16) if sp.startswith("0x") else int(sp)
                except ValueError:
                    continue
                tasks.append((parts[0], " ".join(parts[1:-1]), sp))
    except OSError:
        pass
    return tasks


def parse_status(path):
    status = {}
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                value = value.split()
                if value and value[-1] == "kB":
                    status[key] = int(value[0])
    except OSError:
        pass
    return status


def parse_metrics(path):
    metrics = {}
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                if "=" in line:
                    key, value = line.split("=", 1)
                    metrics[key] = value.strip()
    except OSError:
        pass
    return metrics


# ----- ELF parsing (best-effort; any failure means "no annotation") -----

def _parse_elf(path):
    with open(path, "rb") as f:
        ident = f.read(16)
        if len(ident) < 16 or ident[:4] != b"\x7fELF" or ident[5] != 1:
            return None  # not a little-endian ELF
        is64 = ident[4] == 2
        if not is64 and ident[4] != 1:
            return None
        if is64:
            hdr = struct.unpack("<HHIQQQIHHHHHH", f.read(48))
        else:
            hdr = struct.unpack("<HHIIIIIHHHHHH", f.read(36))
        (_type, _machine, _version, _entry, e_phoff, e_shoff, _flags,
         _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = hdr

        loads = []
        f.seek(e_phoff)
        for _ in range(e_phnum):
            raw = f.read(e_phentsize)
            if is64:
                (p_type, p_flags, p_offset, _vaddr, _paddr, p_filesz,
                 p_memsz, _align) = struct.unpack("<IIQQQQQQ", raw[:56])
            else:
                (p_type, p_offset, _vaddr, _paddr, p_filesz, p_memsz,
                 p_flags, _align) = struct.unpack("<IIIIIIII", raw[:32])
            if p_type == 1:  # PT_LOAD
                loads.append((p_offset, p_filesz, p_memsz, p_flags))

        sections = []
        if e_shoff and e_shnum and e_shentsize and e_shstrndx < e_shnum:
            f.seek(e_shoff)
            shdrs = [f.read(e_shentsize) for _ in range(e_shnum)]
            str_hdr = shdrs[e_shstrndx]
            if is64:
                str_off, str_size = struct.unpack("<IIQQQQIIQQ", str_hdr[:64])[4:6]
            else:
                str_off, str_size = struct.unpack("<IIIIIIIIII", str_hdr[:40])[4:6]
            f.seek(str_off)
            strtab = f.read(str_size)
            for sh in shdrs:
                if is64:
                    vals = struct.unpack("<IIQQQQIIQQ", sh[:64])
                else:
                    vals = struct.unpack("<IIIIIIIIII", sh[:40])
                sh_name, sh_type, sh_offset, sh_size = vals[0], vals[1], vals[4], vals[5]
                if sh_type == 8 or sh_size == 0:  # SHT_NOBITS has no file range
                    continue
                end = strtab.find(b"\0", sh_name)
                if end < 0:
                    end = len(strtab)
                name = strtab[sh_name:end].decode("ascii", "replace")
                if name:
                    sections.append((sh_offset, sh_size, name))
        return loads, sections


def elf_info(path, cache):
    if path in cache:
        return cache[path]
    try:
        info = _parse_elf(path)
    except (OSError, struct.error, ValueError, IndexError):
        info = None
    cache[path] = info
    return info


# ----- annotation passes -----

def kernel_name(v):
    """The name the kernel carries for this mapping, or None.

    Mappings named through prctl(PR_SET_VMA_ANON_NAME) — glibc's
    decorate_maps names or the label_mmap shim's "krun:" names — display as
    [anon:<name>]. A kernel label is the base for display and categorization;
    the size/SP/pattern inference only runs on unlabeled mappings.
    """
    m = KERNEL_ANON_RE.match(v.path)
    return m.group(1) if m else None


def is_anon(v):
    return v.path == "" or kernel_name(v) is not None


def is_thread_stack(v):
    return (v.label.startswith("[thread stack")
            or (kernel_name(v) or "").startswith("glibc: pthread stack"))


def mark_guest_ram(vmas, ram_kib):
    anon_rw = [v for v in vmas if is_anon(v) and v.perms.startswith("rw")]
    targets = []
    method = "largest-anon fallback"
    for want, m in ((ram_kib, "exact-size match"),
                    (ram_kib + GUEST_RAM_LOW_KIB, "merged-size match")):
        targets = [v for v in anon_rw if v.size == want]
        if targets:
            method = m
            break
    if not targets and anon_rw:
        targets = [max(anon_rw, key=lambda v: v.size)]
    # The low-memory region below the kernel load address is guest RAM too;
    # with per-mapping kernel labels the two RAM mmaps no longer merge.
    if ram_kib != GUEST_RAM_LOW_KIB:
        targets += [v for v in anon_rw
                    if v.size == GUEST_RAM_LOW_KIB and v not in targets]
    for v in targets:
        kn = kernel_name(v)
        v.label = "[guest RAM (%s)%s]" % (method, "; " + kn if kn else "")
    return sum(v.rss for v in targets), method, len(targets)


def enrich_glibc_stacks(vmas, tasks):
    """glibc names thread stacks "glibc: pthread stack: <tid>" — attach the
    comm from task-stats.txt so the map shows who owns each stack."""
    comms = {tid: comm for tid, comm, _sp in tasks}
    for v in vmas:
        kn = kernel_name(v)
        if kn is None:
            continue
        m = re.match(r"^glibc: pthread stack: (\d+)$", kn)
        if m and m.group(1) in comms:
            v.label = "[thread stack: %s (tid %s)]" % (comms[m.group(1)], m.group(1))


def mark_thread_stacks(vmas, tasks):
    """Label the anon rw mappings containing each thread's user sp.

    Rust/glibc thread stacks are allocated back to back and the host kernel
    merges them into a single VMA, so a mapping holding several sps is split
    at page-aligned midpoints between them (counters are distributed
    proportionally; the telescoping sums keep the totals exact).
    """
    sps = [(comm, sp) for _tid, comm, sp in tasks if sp]
    out = []
    for v in vmas:
        inside = [t for t in sps if v.start <= t[1] < v.end]
        if not (v.path == "" and not v.label and v.perms.startswith("rw") and inside):
            out.append(v)
            continue
        inside.sort(key=lambda t: t[1])
        cuts = [v.start]
        for i in range(1, len(inside)):
            cut = (inside[i - 1][1] + inside[i][1]) // 2 & ~0xFFF
            if cut > cuts[-1]:
                cuts.append(cut)
        cuts.append(v.end)
        total = v.end - v.start
        for j in range(len(cuts) - 1):
            s = Vma(cuts[j], cuts[j + 1], v.perms, v.offset, v.dev, v.inode, "")
            s.label = "[thread stack: %s]" % inside[j][0]
            c0, c1 = s.start - v.start, s.end - v.start
            for k in COUNTERS:
                val = getattr(v, k)
                setattr(s, k, val * c1 // total - val * c0 // total)
            out.append(s)
    return out


def mark_guards(vmas):
    for i, v in enumerate(vmas):
        if not is_thread_stack(v):
            continue
        prev = vmas[i - 1] if i > 0 else None
        if (prev is not None and prev.path == "" and not prev.label
                and prev.perms.startswith("---") and prev.end == v.start):
            prev.label = "[guard page]"


def mark_arenas(vmas):
    for i in range(len(vmas) - 1):
        head, tail = vmas[i], vmas[i + 1]
        if tail.start != head.end:
            continue
        if not is_anon(tail) or tail.label or not tail.perms.startswith("---"):
            continue
        if not is_anon(head) or head.label or not head.perms.startswith("rw"):
            continue
        if head.size + tail.size != ARENA_TOTAL_KIB:
            continue
        # glibc names the arena head itself; when only the shim named the
        # initial reservation, claim both parts here.
        kn = kernel_name(head)
        if head.path == "":
            head.label = "[glibc: malloc arena]"
        elif kn and not kn.startswith("glibc: malloc arena"):
            head.label = "[glibc: malloc arena; " + kn + "]"
        tkn = kernel_name(tail)
        tail.label = "[glibc: arena reservation%s]" % ("; " + tkn if tkn else "")


def mark_bss(vmas, cache):
    for i in range(len(vmas) - 1):
        v, follower = vmas[i], vmas[i + 1]
        if not v.path.startswith("/"):
            continue
        if follower.path != "" or follower.label or not follower.perms.startswith("rw"):
            continue
        if follower.start != v.end:
            continue
        info = elf_info(v.path, cache)
        if not info:
            continue
        map_len = v.end - v.start
        map_start, map_end = v.offset, v.offset + map_len
        for p_offset, p_filesz, p_memsz, _flags in info[0]:
            if (p_offset < map_end and p_offset + p_filesz > map_start
                    and p_memsz > p_filesz):
                follower.label = "[.bss: %s]" % os.path.basename(v.path)
                break


def annotate_elf(vmas, cache):
    for v in vmas:
        if not v.path.startswith("/") or v.path.startswith("/dev/"):
            continue
        info = elf_info(v.path, cache)
        if not info:
            continue
        loads, sections = info
        map_len = v.end - v.start
        map_start, map_end = v.offset, v.offset + map_len
        inside = sorted(s for s in sections
                        if s[0] >= map_start and s[0] + s[1] <= map_end)
        if inside:
            names = [s[2] for s in inside]
            if len(names) > 8:
                names = names[:7] + ["..."]
            v.segments = "<" + " ".join(names) + ">"
        else:
            for p_offset, p_filesz, _memsz, p_flags in loads:
                if p_offset < map_end and p_offset + p_filesz > map_start:
                    kind = "text" if p_flags & 1 else ("data" if p_flags & 2 else "rodata")
                    v.segments = "<%s>" % kind
                    break


# ----- categories -----

def _path_category(p):
    if p.startswith("anon_inode:kvm") or p == "/dev/kvm":
        return "kvm"
    if p.startswith("memfd:") or p.startswith("/memfd:"):
        return "memfd"
    if p in ("[vdso]", "[vvar]", "[vvar_vclock]", "[vsyscall]"):
        return "vdso"
    if "libkrunfw.so" in p:
        return "libkrunfw.so"
    if "libkrun_init.so" in p:
        return "libkrun_init.so"
    if "libkrun.so" in p:
        return "libkrun.so"
    if "krun-harness" in p:
        return "harness"
    if p.endswith(".so") or ".so." in p or "ld-linux" in p:
        return "system-libs"
    return "other-file"


def _kernel_label_category(kn):
    if kn.startswith("glibc: malloc arena"):
        return "glibc-arena"
    if kn.startswith(("glibc: pthread stack", "glibc: unused stack")):
        return "thread-stacks"
    if kn.startswith("glibc: .bss "):
        return _path_category(kn[len("glibc: .bss "):])
    if kn.startswith("krun: "):
        rest = kn[len("krun: "):]
        if rest.startswith("mmap caller"):
            return "other-anon"
        # attribute the allocation to the library that made it
        return _path_category(rest.split(":")[0].split("+")[0])
    if kn.startswith("glibc:"):
        return "system-libs"
    return None


def categorize(v):
    if v.label.startswith("[guest RAM"):
        return "guest-RAM"
    if v.path == "[heap]":
        return "heap"
    if v.path == "[stack]":
        return "stack"
    if is_thread_stack(v):
        return "thread-stacks"
    if v.label == "[guard page]":
        return "guard"
    if v.label.startswith("[glibc"):
        return "glibc-arena"
    if v.label.startswith("[.bss"):
        return _path_category(v.label[len("[.bss: "):-1])
    kn = kernel_name(v)
    if kn is not None:
        cat = _kernel_label_category(kn)
        return cat if cat is not None else "other-anon"
    if v.path:
        return _path_category(v.path)
    return "other-anon"


# ----- outputs -----

def perm_class(v):
    if "w" in v.perms:
        return "rw"
    if v.perms.startswith("---"):
        return "none"
    return "ro"


def render_table(vmas, separate_groups=True):
    """Header + rows for one report section, in the caller's order.

    Address-ordered sections keep the article-style blank line between
    groups; sorted sections do not, because their groups interleave.
    """
    displays = [v.label if v.label else (v.path + " " + v.segments).strip()
                for v in vmas]
    # A fixed pathname width would let overflowing paths push the trailing
    # counters out of alignment, so the column is sized to its longest entry.
    width = max(len(d) for d in displays + ["pathname/[label]"])
    header_fmt = "%9s %-33s %-4s %8s %5s %10s %-*s %9s %9s %9s %9s %9s"
    row_fmt = "%9d %-33s %-4s %8x %5s %10s %-*s %9d %9d %9d %9d %9d"
    lines = [header_fmt % ("size(KB)", "address_range", "perm", "offset",
                           "dev", "inode", width, "pathname/[label]",
                           "rss(KB)", "dirty(KB)", "anon(KB)", "pss(KB)",
                           "uss(KB)")]
    prev_group = None
    for v, display in zip(vmas, displays):
        if separate_groups:
            group = (v.label if v.label else v.path).split(" (empty reservation)")[0]
            if prev_group is not None and group != prev_group:
                lines.append("")
            prev_group = group
        lines.append(row_fmt % (
            v.size, "%x-%x" % (v.start, v.end), v.perms, v.offset, v.dev,
            v.inode, width, display, v.rss, v.dirty, v.anon, v.pss, v.uss))
    return lines


def gram_for(vmas, method):
    ram = [v for v in vmas if v.label.startswith("[guest RAM")]
    return sum(v.rss for v in ram), method, len(ram)


def category_table(rows):
    lines = ["%-18s %12s %10s %10s %10s %10s %10s" % (
        "category", "reservation", "RO", "RW", "none", "rss", "anon")]
    for name, res, rss, anon, ro, rw, none in rows:
        lines.append("%-18s %12d %10d %10d %10d %10d %10d"
                     % (name, res, ro, rw, none, rss, anon))
    return lines


def write_report(vmas, path, status, gram_method, cat_rows):
    out = list(render_table(vmas))
    out += ["", totals_block(vmas, status, gram_for(vmas, gram_method))]

    resident = [v for v in vmas if v.rss > 0]
    out += ["", "Segments (excluding empty reservations)"]
    out += render_table(resident)
    out += ["", totals_block(resident, {}, gram_for(resident, gram_method))]

    by_rss = sorted(resident, key=lambda v: -v.rss)
    out += ["", "Segments with RSS usage"]
    out += render_table(by_rss, separate_groups=False)
    out += ["", totals_block(by_rss, {}, gram_for(by_rss, gram_method))]

    by_anon = sorted((v for v in vmas if v.anon > 0), key=lambda v: -v.anon)
    out += ["", "Segments with Anonymous memory"]
    out += render_table(by_anon, separate_groups=False)
    out += ["", totals_block(by_anon, {}, gram_for(by_anon, gram_method))]

    out += ["", "Category breakdown"]
    out += category_table(cat_rows)
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")


def totals_block(vmas, status, gram):
    total_size = sum(v.size for v in vmas)
    empty = sum(v.size for v in vmas if v.rss == 0)
    rss = sum(v.rss for v in vmas)
    anon = sum(v.anon for v in vmas)
    dirty = sum(v.dirty for v in vmas)
    # section footers have no status file; approximate RssFile as rss - anon
    rss_file = sum(v.rss - v.anon for v in vmas)
    return "\n".join([
        "Total memory (VSZ):     %10d KiB" % total_size,
        "Empty reservations:     %10d KiB" % empty,
        "Total w/o reservations: %10d KiB" % (total_size - empty),
        "RSS:                    %10d KiB" % status.get("VmRSS", rss),
        "RssFile:                %10d KiB" % status.get("RssFile", rss_file),
        "RssAnon:                %10d KiB" % status.get("RssAnon", anon),
        "Dirty:                  %10d KiB" % dirty,
        "Anonymous:              %10d KiB" % anon,
        "guest RAM:              %10d KiB RSS (%s, %d region(s))" % gram,
    ])


def write_categories(vmas, path):
    cats = {}
    for v in vmas:
        c = cats.setdefault(categorize(v), [0, 0, 0, 0, 0, 0])
        c[0] += v.size
        c[1] += v.rss
        c[2] += v.anon
        c[{"ro": 3, "rw": 4, "none": 5}[perm_class(v)]] += v.size
    total_res = sum(c[0] for c in cats.values()) or 1
    total_rss = sum(c[1] for c in cats.values()) or 1
    # rows: (name, reservation, rss, anon, ro_res, rw_res, none_res)
    rows = [(n, v[0], v[1], v[2], v[3], v[4], v[5])
            for n, v in sorted(cats.items(), key=lambda kv: -kv[1][0])]
    with open(path, "w") as f:
        f.write("category,reservation_kib,ro_res_kib,rw_res_kib,none_res_kib,"
                "rss_kib,anon_kib,pct_of_reservation,pct_of_rss\n")
        for name, res, rss, anon, ro, rw, none in rows:
            f.write("%s,%d,%d,%d,%d,%d,%d,%.1f,%.1f\n" % (
                name, res, ro, rw, none, rss, anon,
                res * 100.0 / total_res, rss * 100.0 / total_rss))
    return rows


def _esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _arc_path(cx, cy, r1, r2, a0, a1):
    x0, y0 = cx + r1 * math.cos(a0), cy + r1 * math.sin(a0)
    x1, y1 = cx + r1 * math.cos(a1), cy + r1 * math.sin(a1)
    x2, y2 = cx + r2 * math.cos(a1), cy + r2 * math.sin(a1)
    x3, y3 = cx + r2 * math.cos(a0), cy + r2 * math.sin(a0)
    large = 1 if (a1 - a0) > math.pi else 0
    return ("M %.1f %.1f A %d %d 0 %d 1 %.1f %.1f L %.1f %.1f "
            "A %d %d 0 %d 0 %.1f %.1f Z" % (
                x0, y0, r1, r1, large, x1, y1, x2, y2, r2, r2, large, x3, y3))


def write_pie(path, title, unit, rows):
    total = sum(v for _n, v in rows)
    slices = rows[:9]
    if len(rows) > 9:
        slices.append(("other", sum(v for _n, v in rows[9:])))
    n = max(len(slices), 1)
    cx, cy, r1, r2 = 190, 220, 125, 70
    height = max(440, 90 + 24 * n)
    body = []
    if total > 0 and len(slices) == 1:
        body.append('<circle cx="%d" cy="%d" r="%d" fill="none" stroke="%s" '
                    'stroke-width="%d"/>' % (cx, cy, (r1 + r2) // 2,
                                             PALETTE[0], r1 - r2))
    elif total > 0:
        angle = -math.pi / 2
        for i, (name, value) in enumerate(slices):
            span = 2 * math.pi * value / total
            color = PALETTE[9] if name == "other" else PALETTE[i % 9]
            body.append('<path d="%s" fill="%s" stroke="#ffffff" stroke-width="1"/>'
                        % (_arc_path(cx, cy, r1, r2, angle, angle + span), color))
            angle += span
    body.append('<text x="%d" y="%d" text-anchor="middle" font-family="monospace" '
                'font-size="15" fill="#222">%d KiB</text>' % (cx, cy - 2, total))
    body.append('<text x="%d" y="%d" text-anchor="middle" font-family="monospace" '
                'font-size="11" fill="#777">%s</text>' % (cx, cy + 18, _esc(unit)))
    for i, (name, value) in enumerate(slices):
        color = PALETTE[9] if name == "other" else PALETTE[i % 9]
        y = 96 + 24 * i
        body.append('<rect x="360" y="%d" width="14" height="14" fill="%s"/>' % (y, color))
        body.append('<text x="382" y="%d" font-family="monospace" font-size="13" '
                    'fill="#222">%s&#160;&#160;%9d KiB&#160;&#160;%5.1f%%</text>'
                    % (y + 11, _esc(name), value, value * 100.0 / total if total else 0))
    svg = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<svg xmlns="http://www.w3.org/2000/svg" width="780" height="%d" '
           'viewBox="0 0 780 %d">\n'
           '<text x="20" y="32" font-family="monospace" font-size="16" '
           'font-weight="bold" fill="#333">%s</text>\n%s\n</svg>\n'
           % (height, height, _esc(title), "\n".join(body)))
    with open(path, "w") as f:
        f.write(svg)


def write_ro_rw(path, title, rows):
    """rows: [(name, ro_kib, rw_kib, none_kib)] sorted by total desc."""
    n = max(len(rows), 1)
    x0, x1, row_h = 170, 780, 26
    height = 100 + row_h * n + 10
    max_total = max((r + w + o) for _n, r, w, o in rows) if rows else 0
    scale = (x1 - x0) / max_total if max_total else 0
    body = []
    for i, (label, color) in enumerate((("read-only (r--p, r-xp)", COLOR_RO),
                                        ("read-write (rw-p)", COLOR_RW),
                                        ("none (---p)", COLOR_NONE))):
        x = x0 + i * 210
        body.append('<rect x="%d" y="52" width="14" height="14" fill="%s"/>' % (x, color))
        body.append('<text x="%d" y="63" font-family="monospace" font-size="13" '
                    'fill="#222">%s</text>' % (x + 20, _esc(label)))
    for i, (name, ro, rw, none) in enumerate(rows):
        y = 90 + row_h * i
        body.append('<text x="%d" y="%d" text-anchor="end" font-family="monospace" '
                    'font-size="13" fill="#222">%s</text>'
                    % (x0 - 10, y + 17, _esc(name[:20])))
        cx = x0
        for value, color in ((ro, COLOR_RO), (rw, COLOR_RW), (none, COLOR_NONE)):
            if value <= 0:
                continue
            width = int(value * scale)
            body.append('<rect x="%d" y="%d" width="%d" height="%d" fill="%s"/>'
                        % (cx, y, width, row_h - 8, color))
            cx += width
        total = ro + rw + none
        if total > 0:
            body.append('<text x="%d" y="%d" font-family="monospace" font-size="12" '
                        'fill="#444">%d KiB</text>' % (min(cx + 6, 700), y + 17, total))
    svg = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<svg xmlns="http://www.w3.org/2000/svg" width="820" height="%d" '
           'viewBox="0 0 820 %d">\n'
           '<text x="20" y="32" font-family="monospace" font-size="16" '
           'font-weight="bold" fill="#333">%s</text>\n%s\n</svg>\n'
           % (height, height, _esc(title), "\n".join(body)))
    with open(path, "w") as f:
        f.write(svg)


def main():
    ap = argparse.ArgumentParser(
        description="Annotate a libkrun resource-audit memory snapshot.")
    ap.add_argument("test_dir", help="per-test results directory")
    ap.add_argument("--name", required=True, help="test name (output naming, titles)")
    ap.add_argument("--ram-mib", type=int, default=None,
                    help="guest RAM in MiB (default: ram_mib from metrics.txt)")
    ap.add_argument("--no-charts", action="store_true", help="skip chart generation")
    ap.add_argument("--input-prefix", default="final-",
                    help="snapshot file prefix to read (final-, preboot-)")
    ap.add_argument("--output-prefix", default="",
                    help="prefix for generated files (e.g. preboot-)")
    args = ap.parse_args()

    d = args.test_dir
    inp = args.input_prefix
    smaps = os.path.join(d, inp + "smaps.txt")
    if not os.path.exists(smaps):
        smaps = os.path.join(d, inp + "maps.txt")
        if not os.path.exists(smaps):
            print("annotate-maps.py: no %ssmaps.txt/%smaps.txt in %s"
                  % (inp, inp, d), file=sys.stderr)
            return 1
    vmas = parse_smaps(smaps)
    if not vmas:
        print("annotate-maps.py: %s parsed to zero mappings" % smaps, file=sys.stderr)
        return 1

    def prefixed_or_shared(name):
        p = os.path.join(d, inp + name)
        return p if os.path.exists(p) else os.path.join(d, name)

    ram_mib = args.ram_mib
    if ram_mib is None:
        ram_mib = int(parse_metrics(prefixed_or_shared("metrics.txt")).get("ram_mib", 0))
    if ram_mib <= 0:
        print("annotate-maps.py: guest RAM size unknown (--ram-mib)", file=sys.stderr)
        return 1

    tasks = parse_task_stats(prefixed_or_shared("task-stats.txt"))
    status = parse_status(os.path.join(d, inp + "status.txt"))

    gram = mark_guest_ram(vmas, ram_mib * KiB)
    enrich_glibc_stacks(vmas, tasks)
    vmas = mark_thread_stacks(vmas, tasks)
    mark_guards(vmas)
    mark_arenas(vmas)
    cache = {}
    mark_bss(vmas, cache)
    annotate_elf(vmas, cache)
    for v in vmas:
        if v.path == "":
            if not v.label:
                v.label = "[anon]"
            if v.size > 0 and v.rss == 0:
                v.label += " (empty reservation)"

    out = args.output_prefix
    rows = write_categories(vmas, os.path.join(d, out + "categories.csv"))
    write_report(vmas, os.path.join(d, out + "maps-annotated.txt"),
                 status, gram[1], rows)
    if not args.no_charts:
        charts = os.path.join(d, "charts")
        os.makedirs(charts, exist_ok=True)
        res_rows = [(r[0], r[1]) for r in rows]
        rss_rows = [(r[0], r[2]) for r in rows if r[2] > 0]
        perm_rows = [(r[0], r[4], r[5], r[6]) for r in rows]
        write_pie(os.path.join(charts, "%s-reservations-pie.svg" % args.name),
                  "%s — reservations by category" % args.name, "reservation", res_rows)
        write_pie(os.path.join(charts, "%s-rss-pie.svg" % args.name),
                  "%s — RSS by category" % args.name, "resident", rss_rows)
        write_ro_rw(os.path.join(charts, "%s-reservations-ro-rw.svg" % args.name),
                    "%s — reservations by permission" % args.name, perm_rows)

    print(totals_block(vmas, status, gram))
    return 0


if __name__ == "__main__":
    sys.exit(main())
