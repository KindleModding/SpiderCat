#!/usr/bin/env python3
"""
azwjs.py -- build a fixed-layout KF8 (AZW3) ebook that runs arbitrary JavaScript.

Reverse-engineered from H2_FIXED_JS_DOM_ONLY_TEST.azw3 ("H2 fixed-layout
JavaScript test", a kindlegen -c0 build with post-compile patching).

How the trick works
-------------------
kindlegen strips <script> tags and onload attributes from the source, but the
compiled KF8 is rendered by a WebKit-based reader that executes scripts that
are present in the binary. The technique:

  1. The source carries pre-sized "slot" placeholders:
       - padded <div>s            -> become inline <script> blocks
       - a padded class attribute -> becomes an onload="..." handler
       - a deliberately broken GIF data URI -> kindlegen's image converter
         rejects it and merges the raw bytes as a "media file" resource
         record; that record is overwritten with a JS file and served to the
         page as <script src="kindle:embed:0001?mime=text/javascript">
         (kindle:embed indices are 1-based positions in the resource record
         list; the ?mime= override re-types any resource).
  2. kindlegen runs with -c0 (no compression) so the output is patched
     in-place, keeping every byte length identical: records, INDX indexes,
     FDST flow table and trailing-entry descriptors all stay valid.

Slots may span several text records: the reader's text stream is the record
content with the trailing-entry descriptor bytes stripped (kindlegen's own
text_length field proves this), so a script laid linearly across the
fragments is reassembled seamlessly. To survive any per-record straggler
byte, the patcher additionally aligns every record junction with a token
boundary in the script.

Channels
--------
  --js FILE       inline <script> payload (repeat for multiple slots;
                  executed in order, shared globals, no eval)
  --js-big FILE   arbitrary size: payload is split into escaped string
                  literals across several <script> slots and eval()'d
                  (requires eval to be allowed in the reader's WebView)
  --js-media FILE external script served via kindle:embed:0001?mime=...
                  (raw file bytes, no escaping; the media record is small,
                  ~36 bytes by default)
  --js-onload FILE img onload handler (attribute-escaped)

The reader must be the same family the original book was tested on (the
"H2" fixed-layout WebKit renderer). Other readers may ignore scripts.
"""

import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid

# ---------------------------------------------------------------------------
# template pieces

# Broken 1x1 GIF: GCT flag set with zero table entries plus junk; kindlegen's
# image converter rejects it ("Converting and merging media file" in a
# -verbose log) and stores the raw bytes as a media resource record.
BROKEN_GIF_B64 = "R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw=="
# Valid 1x1 GIF: becomes a real image record; the onload <img> uses it so the
# load event actually fires.
VALID_GIF_B64 = "R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs="

STYLE_CSS = """html, body {
  width: 1264px;
  height: 1680px;
  margin: 0;
  padding: 0;
  overflow: hidden;
  background: #ffffff;
  color: #000000;
  font-family: sans-serif;
}

.main {
  box-sizing: border-box;
  width: 100%;
  height: 100%;
  padding: 110px 80px;
}

h1 {
  margin: 0 0 28px;
  font-size: 70px;
}

.build, .note {
  font-size: 38px;
}

.marker {
  margin: 36px 0;
  border: 7px solid #000000;
  padding: 32px;
  font-size: 64px;
  font-weight: bold;
}

.yes {
  color: #000000;
  background: #ffffff;
}

.no {
  color: #ffffff;
  background: #000000;
}

.carrier, .patch-slot {
  position: absolute;
  width: 1px;
  height: 1px;
  left: -10px;
  top: -10px;
}
"""

OPF_TMPL = """<?xml version="1.0" encoding="UTF-8"?>
<package xmlns="http://www.idpf.org/2007/opf"
         xmlns:dc="http://purl.org/dc/elements/1.1/"
         unique-identifier="BookId"
         version="2.0">
  <metadata>
    <dc:title>{title}</dc:title>
    <dc:creator>azwjs</dc:creator>
    <dc:language>en</dc:language>
    <dc:identifier id="BookId">{uuid}</dc:identifier>
    <meta name="fixed-layout" content="true"/>
    <meta name="original-resolution" content="1264x1680"/>
    <meta name="orientation-lock" content="portrait"/>
    <meta name="book-type" content="children"/>
    <meta name="primary-writing-mode" content="horizontal-lr"/>
    <meta name="zero-gutter" content="true"/>
    <meta name="zero-margin" content="true"/>
    <meta name="region-magnification" content="false"/>
  </metadata>
  <manifest>
    <item id="page" href="html/page.xhtml" media-type="application/xhtml+xml"/>
    <item id="style" href="css/style.css" media-type="text/css"/>
    <item id="ncx" href="xml/toc.ncx" media-type="application/x-dtbncx+xml"/>
  </manifest>
  <spine toc="ncx">
    <itemref idref="page"/>
  </spine>
</package>
"""

NCX_TMPL = """<?xml version="1.0" encoding="UTF-8"?>
<ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1">
  <head>
    <meta name="dtb:uid" content="{uuid}"/>
    <meta name="dtb:depth" content="1"/>
    <meta name="dtb:totalPageCount" content="1"/>
    <meta name="dtb:maxPageNumber" content="1"/>
  </head>
  <docTitle><text>{title}</text></docTitle>
  <navMap>
    <navPoint id="page-1" playOrder="1">
      <navLabel><text>{title}</text></navLabel>
      <content src="../html/page.xhtml"/>
    </navPoint>
  </navMap>
</ncx>
"""

# kindle:embed indices use kindlegen's base-32 alphabet, zero-padded to 4
K8_IDX_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUV"


def k8_index(n):
    s = ""
    while n:
        n, r = divmod(n, 32)
        s = K8_IDX_ALPHABET[r] + s
    return s.zfill(4)


def page_xhtml(title, text, slot_sizes, local_len, onload_len):
    """slot_sizes: Q-pad lengths, one <div> per inline slot. local_len: the
    external-script slot div. onload_len: Q-run inside the onload img's class
    attribute."""
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>\n',
        '<!DOCTYPE html>\n',
        '<html xmlns="http://www.w3.org/1999/xhtml">\n',
        "  <head>\n",
        '    <meta name="viewport" content="width=1264,height=1680"/>\n',
        f"    <title>{title}</title>\n",
        '    <link rel="stylesheet" type="text/css" href="../css/style.css"/>\n',
        "  </head>\n",
        "  <body>\n",
        '    <div class="main">\n',
        f"      <h1>{title}</h1>\n",
        '      <p class="build">Built with azwjs</p>\n',
        # status markers, same ids as the original H2 test book so payloads
        # can flip them visibly
        '      <p id="inline" class="marker no">INLINE: NO</p>\n',
        '      <p id="m" class="marker no">LOCAL.JS: NO</p>\n',
        '      <p id="event" class="marker no">ONLOAD: NO</p>\n',
        f'      <p class="note">{text}</p>\n',
    ]
    # ids are deliberately short ("S0", "SL", class "AO_") so the markers
    # rarely straddle a PDB record boundary; the fit loop grows sizes and
    # retries when a marker is still missed.
    for i, size in enumerate(slot_sizes):
        parts.append(
            f'      <div id="S{i}" class="patch-slot">{"Q" * size}</div>\n'
        )
    parts.append(
        f'      <div id="SL" class="patch-slot">{"Q" * local_len}</div>\n'
    )
    parts += [
        "    </div>\n",
        '    <img class="carrier" alt=""\n'
        f'         src="data:image/gif;base64,{BROKEN_GIF_B64}"/>\n',
        f'    <img class="AO_{"Q" * onload_len}" alt=""\n'
        f'         src="data:image/gif;base64,{VALID_GIF_B64}"/>\n',
        "  </body>\n",
        "</html>\n",
    ]
    return "".join(parts)


# ---------------------------------------------------------------------------
# MOBI binary parsing

def u16(b, o):
    return struct.unpack_from(">H", b, o)[0]


def u32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def exth_records(header):
    """Return {exth_id: value_bytes} from a header record."""
    out = {}
    pos = header.find(b"EXTH")
    if pos < 0:
        return out
    exth_len = u32(header, pos + 4)
    q = pos + 12
    end = pos + exth_len
    while q + 8 <= end:
        t, l = u32(header, q), u32(header, q + 4)
        if t == 0 or l < 8 or q + l > end:
            break
        out[t] = header[q + 8:q + l]
        q += l
    return out


class SlotError(Exception):
    pass


class Mobi:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        self.num_records = u16(self.data, 76)
        self.offs = [u32(self.data, 78 + 8 * i) for i in range(self.num_records)]
        self.sizes = [
            (self.offs[i + 1] - self.offs[i]) if i + 1 < self.num_records
            else (len(self.data) - self.offs[i])
            for i in range(self.num_records)
        ]

        # first (mobi7) header record
        self.h0 = self.rec(0)
        self.exth = exth_records(self.h0)
        self.boundary = u32(self.exth[121], 0)      # KF8 header record index
        self.firstres = u32(self.h0, 0x6C)          # first resource record

        # KF8 header at the boundary
        self.h8 = self.rec(self.boundary)
        self.text_records = u16(self.h8, 8)
        self.text_start = self.boundary + 1
        self.text_rec_idx = list(range(self.text_start,
                                       self.text_start + self.text_records))

    def rec(self, i):
        return self.data[self.offs[i]:self.offs[i] + self.sizes[i]]

    # -- resource list: one slot per record in [firstres, boundary) ---------
    def resource_slots(self):
        return list(range(self.firstres, self.boundary))

    def find_media_record(self):
        """Record holding the broken-GIF 'media file': starts with GIF89a and
        the packed byte has the GCT flag 0x80 set."""
        for i in self.resource_slots():
            d = self.rec(i)
            if d[:6] == b"GIF89a" and len(d) > 10 and d[10] & 0x80:
                return i
        return None

    def find_gif_record(self):
        """Record holding the valid 1x1 GIF."""
        for i in self.resource_slots():
            d = self.rec(i)
            if d[:6] == b"GIF89a" and len(d) > 10 and not (d[10] & 0x80):
                return i
        return None

    def find_datp(self):
        for i in range(self.num_records):
            if self.rec(i)[:4] == b"DATP":
                return i
        return None

    def find_css_offset(self):
        """File offset of the flow-2 CSS content (slots must sit before it)."""
        for ri in self.text_rec_idx:
            o = self.offs[ri]
            p = self.data.find(b"html, body {", o, o + self.sizes[ri])
            if p >= 0:
                return p
        return None

    # -- slot discovery -----------------------------------------------------
    # Every patch target may cross record boundaries: a fragment covers the
    # Q-run up to the last Q in the record; the non-Q suffix (the
    # trailing-entry descriptor / carry bytes, at most ~12 bytes) is left
    # untouched. The reader's text stream is the fragments concatenated, so
    # patched content spans them seamlessly.

    def scan_run(self, ri, p, term):
        """Follow a Q-run + terminator across text records. Returns
        [(rec, start, end), ...] or raises SlotError."""
        frags = []
        while True:
            d = self.rec(ri)
            q = p
            while q < len(d) and d[q:q + 1] == b"Q":
                q += 1
            if q < len(d) and d[q:q + len(term)] == term:
                frags.append((ri, p, q + len(term)))
                return frags
            if len(d) - q <= 12:
                # Q-run ends at the record's tail -> continues next record
                frags.append((ri, p, q))
                ri += 1
                if ri not in self.text_rec_idx:
                    raise SlotError("target runs off the end of the text")
                p = 0
                continue
            raise SlotError(f"Q-run interrupted in record {ri} at {q} "
                            f"({d[q:q + 8]!r})")

    def find_slots(self):
        """Locate every patch target in the KF8 text records.

        Returns (slots, local, onload) where each is a list of fragments
        [(rec, start, end), ...]; slots is keyed by slot number.
        """
        slots, local, onload = {}, None, None
        css_off = self.find_css_offset()

        for ri in self.text_rec_idx:
            d = self.rec(ri)

            for m in re.finditer(rb'<div\b[^>]*\bid="(S(\d+)|SL)"[^>]*>', d):
                frags = self.scan_run(ri, m.end(), b"</div>")
                # first fragment must cover the opening tag too
                frags[0] = (frags[0][0], m.start(), frags[0][2])
                if m.group(1).startswith(b"S") and m.group(2) is not None:
                    slots[int(m.group(2))] = frags
                else:
                    local = frags

            for m in re.finditer(rb'class="AO_', d):
                frags = self.scan_run(ri, m.end(), b'"')
                frags[0] = (frags[0][0], m.start(), frags[0][2])
                onload = frags

        if css_off is not None:
            def check_flow1(frags, name):
                for fr, fs, fe in frags:
                    if self.offs[fr] + fs >= css_off:
                        raise SlotError(f"{name} overlaps the CSS flow")

            for num, frags in slots.items():
                check_flow1(frags, f"slot {num}")
            if local is not None:
                check_flow1(local, "local slot")
            if onload is not None:
                check_flow1(onload, "onload slot")

        return slots, local, onload


# ---------------------------------------------------------------------------
# payload encoding

def escape_script(js):
    """Escape JS for inline placement in <script> (HTML script-data rules)."""
    js = re.sub(rb"</script", rb"<\\/script", js, flags=re.IGNORECASE)
    js = js.replace(b"<!--", b"<\\!--")
    return js


def escape_attr(js):
    """Escape JS for a double-quoted HTML attribute value."""
    js = js.replace(b"&", b"&amp;")
    js = js.replace(b"<", b"&lt;")
    js = js.replace(b'"', b"&quot;")
    return js


def escape_chunk(chunk):
    """Escape payload bytes as a single-quoted JS string literal."""
    out = bytearray()
    for b in chunk:
        if b == 0x5C:            # backslash
            out += b"\\\\"
        elif b == 0x27:          # single quote
            out += b"\\'"
        elif b == 0x0A:
            out += b"\\n"
        elif b == 0x0D:
            out += b"\\r"
        elif b == 0x09:
            out += b"\\t"
        elif b < 0x20 or b == 0x7F:   # other control chars
            out += b"\\u%04x" % b
        elif b == 0x3C:          # '<' -> kills </script> / <!-- sequences
            out += b"\\u003c"
        else:
            out.append(b)
    # U+2028/U+2029 are JS line terminators even inside string literals
    out = out.replace(" ".encode(), b"\\u2028")
    out = out.replace(" ".encode(), b"\\u2029")
    return bytes(out)


def build_inline_tag(js):
    return b'<script type="text/javascript">' + escape_script(js) + b"</script>"


def build_local_tag(idx):
    return (b'<script type="text/javascript" '
            b'src="kindle:embed:' + idx.encode() + b'?mime=text/javascript">'
            b'</script>')


def build_chunk_tag(chunk, first, last):
    parts = []
    if first:
        parts.append(b"var __azwjs$p='';")
    parts.append(b"__azwjs$p+=('" + escape_chunk(chunk) + b"');")
    if last:
        parts.append(b"eval(__azwjs$p);")
    return b'<script type="text/javascript">' + b"".join(parts) + b"</script>"


def build_onload_attr(js):
    return b'onload="' + escape_attr(js) + b'"'


# ---------------------------------------------------------------------------
# source generation + kindlegen

class Builder:
    def __init__(self, kindlegen="kindlegen", workdir=None):
        self.kindlegen = kindlegen
        self.workdir = workdir or tempfile.mkdtemp(prefix="azwjs-")
        os.makedirs(self.workdir, exist_ok=True)

    def build(self, title, text, slot_sizes, local_len, onload_len):
        src = os.path.join(self.workdir, "src")
        shutil.rmtree(src, ignore_errors=True)
        for sub in ("html", "css", "xml"):
            os.makedirs(os.path.join(src, sub), exist_ok=True)
        uid = "urn:uuid:" + str(uuid.uuid4())
        with open(os.path.join(src, "content.opf"), "w") as f:
            f.write(OPF_TMPL.format(title=title, uuid=uid))
        with open(os.path.join(src, "css/style.css"), "w") as f:
            f.write(STYLE_CSS)
        with open(os.path.join(src, "xml/toc.ncx"), "w") as f:
            f.write(NCX_TMPL.format(title=title, uuid=uid))
        with open(os.path.join(src, "html/page.xhtml"), "w") as f:
            f.write(page_xhtml(title, text, slot_sizes, local_len, onload_len))

        # kindlegen writes the output next to the input file (cwd == src)
        out_name = "book.azw3"
        out_path = os.path.join(src, out_name)
        if os.path.exists(out_path):
            os.unlink(out_path)
        log_path = os.path.join(self.workdir, "kindlegen.log")
        with open(log_path, "w") as log:
            r = subprocess.run(
                [self.kindlegen, "-c0", "content.opf", "-o", out_name],
                cwd=src, stdout=log, stderr=subprocess.STDOUT)
        # kindlegen exits 0 on clean success, 1 on success-with-warnings,
        # 2 on failure
        if r.returncode not in (0, 1):
            raise SystemExit(f"kindlegen failed (see {log_path})")
        if not os.path.exists(out_path):
            raise SystemExit(f"kindlegen produced no output (see {log_path})")
        return out_path


# ---------------------------------------------------------------------------
# patcher

# Bytes that can absorb a straggler NUL/carry byte at a record junction
# without breaking the script (token boundaries).
WS_SAFE = b" \t\n\r;,{}=()'+"


def build_chunk_crossing(chunk, first, last, lens):
    """Chunk tag with the string literal split at every record junction:
    '...A' + 'B...' -- a straggler byte at the junction lands in the
    whitespace between the quote and the + operator."""
    head = bytearray()
    if first:
        head += b"var __azwjs$p='';"
    head += b"__azwjs$p+=('"
    tail = bytearray(b"');")
    if last:
        tail += b"eval(__azwjs$p);"

    esc = escape_chunk(chunk)
    juncs = []
    cum = 0
    for L in lens[:-1]:
        cum += L
        juncs.append(cum)

    out = bytearray(head)
    prefix = len(head)
    pos = 0
    for j in juncs:
        if j < prefix:
            raise SlotError("record junction falls inside the chunk wrapper; "
                            "increase --slot-size")
        k = j - prefix - pos          # offset into the remaining literal
        if 0 < k < len(esc):          # junction inside the literal -> split
            out += esc[:k] + b"'+'"
            esc = esc[k:]
            pos += k
            prefix += 3               # inserted chars shift later junctions
    out += esc + tail
    return bytes(out)

def align_crossings(script, lens):
    """Pad the script so every record junction lands on a token boundary."""
    total = sum(lens)
    if len(script) > total:
        raise SlotError(f"payload ({len(script)} bytes) does not fit the "
                        f"slot ({total} bytes)")
    slack = total - len(script)
    junctions = []
    cum = 0
    for L in lens[:-1]:
        cum += L
        junctions.append(cum)
    if not junctions:
        return script + b" " * slack
    for pad in range(slack + 1):
        good = True
        for j in junctions:
            idx = j - pad
            if 0 <= idx < len(script) and script[idx:idx + 1] not in WS_SAFE:
                good = False
                break
        if good:
            return b" " * pad + script + b" " * (slack - pad)
    raise SlotError("payload crosses a record boundary at a point that "
                    "would split a JS token; rephrase the JS or use --js-big")


def patch_fragments(mobi, data, fragments, content, align=True):
    lens = [e - s for _, s, e in fragments]
    total = sum(lens)
    if len(content) > total:
        raise SlotError(f"content ({len(content)} bytes) does not fit the "
                        f"slot ({total} bytes)")
    if align:
        content = align_crossings(content, lens)
    else:
        content = content + b" " * (total - len(content))
    pos = 0
    for (ri, s, e), L in zip(fragments, lens):
        data[mobi.offs[ri] + s:mobi.offs[ri] + e] = content[pos:pos + L]
        pos += L


def patch_book(path, out_path, jobs):
    """jobs: list of callables (mobi, data, slots, local, onload) -> None.
    All jobs are length-preserving."""
    mobi = Mobi(path)
    data = bytearray(mobi.data)
    slots, local, onload = mobi.find_slots()
    for job in jobs:
        job(mobi, data, slots, local, onload)

    # zero the DATP tail -- matches the known-working artifact and guards
    # against any resource checksum a reader might validate
    datp = mobi.find_datp()
    if datp is not None:
        o = mobi.offs[datp]
        size = mobi.sizes[datp]
        data[o + size - 2:o + size] = b"\x00\x00"

    with open(out_path, "wb") as f:
        f.write(data)


def job_inline_slots(files):
    """One <script> slot per file, executed in order (shared global scope)."""
    def job(mobi, data, slots, local, onload):
        for i, js in enumerate(files):
            if i not in slots:
                raise SlotError(f"inline slot {i} not found in the compiled book")
            patch_fragments(mobi, data, slots[i], build_inline_tag(js))
    return job


def fit_chunk(payload, pos, cap):
    """Largest raw chunk size n such that its escaped form fits in cap bytes.
    (Escaping only ever grows, so raw size <= cap always.)"""
    hi = min(len(payload) - pos, cap)
    if hi == 0 or len(escape_chunk(payload[pos:pos + hi])) <= cap:
        return hi
    lo = 0
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(escape_chunk(payload[pos:pos + mid])) <= cap:
            lo = mid
        else:
            hi = mid - 1
    return lo


def job_chunked(js, chunk_sizes):
    """chunk_sizes: byte sizes per chunk; slots 0..n-1 are used in order."""
    chunks = []
    pos = 0
    for n in chunk_sizes:
        chunks.append(js[pos:pos + n])
        pos += n
    if pos < len(js):
        raise SlotError("chunk sizes do not cover the payload")

    def job(mobi, data, slots, local, onload):
        for i, ch in enumerate(chunks):
            if i not in slots:
                raise SlotError(f"chunk slot {i} not found in the compiled book")
            lens = [e - s for _, s, e in slots[i]]
            patch_fragments(mobi, data, slots[i],
                            build_chunk_crossing(ch, first=(i == 0),
                                                 last=(i == len(chunks) - 1),
                                                 lens=lens),
                            align=False)
    return job


def job_media(js):
    def job(mobi, data, slots, local, onload):
        media = mobi.find_media_record()
        if media is None:
            raise SlotError("media record (broken-GIF fallback) not found")
        size = mobi.sizes[media]
        if len(js) > size:
            raise SlotError(
                f"media payload ({len(js)} bytes) does not fit the media "
                f"record ({size} bytes)")
        o = mobi.offs[media]
        data[o:o + size] = js + b" " * (size - len(js))
    return job


def job_local(js_media_given):
    """Patch the external-script slot div into a kindle:embed script tag, and
    rewrite the <img> src indices to the actual resource slots."""
    def job(mobi, data, slots, local, onload):
        media = mobi.find_media_record()
        gif = mobi.find_gif_record()
        rslots = mobi.resource_slots()
        media_idx = (k8_index(rslots.index(media) + 1)
                     if media in rslots else "0000")
        gif_idx = (k8_index(rslots.index(gif) + 1) if gif in rslots else "0000")

        if js_media_given:
            if local is None:
                raise SlotError("LOCAL slot not found in the compiled book")
            patch_fragments(mobi, data, local, build_local_tag(media_idx))

        # rewrite the img src URLs: the carrier points at the media record
        # (broken decode, hidden by CSS) -> repoint it at the valid gif, which
        # the onload img already references.
        for ri in mobi.text_rec_idx:
            o = mobi.offs[ri]
            size = mobi.sizes[ri]
            d = data[o:o + size]
            d = re.sub(rb'src="kindle:embed:[0-9A-V]{4}\?mime=image/gif"',
                       b'src="kindle:embed:' + gif_idx.encode() +
                       b'?mime=image/gif"', d)
            data[o:o + size] = d
    return job


# ---------------------------------------------------------------------------
# CLI

def load_payload(path):
    if path is None:
        return None
    with open(path, "rb") as f:
        return f.read()


def main():
    ap = argparse.ArgumentParser(
        description="Build a fixed-layout AZW3 ebook that runs arbitrary JavaScript.")
    ap.add_argument("--js", metavar="FILE", action="append",
                    help="inline <script> payload; repeat for several slots "
                         "(executed in order, shared global scope, no eval)")
    ap.add_argument("--js-big", metavar="FILE",
                    help="arbitrary-size payload (chunked string literals + eval)")
    ap.add_argument("--js-media", metavar="FILE",
                    help="external script via kindle:embed (small, raw bytes)")
    ap.add_argument("--js-onload", metavar="FILE", help="img onload handler")
    ap.add_argument("-o", "--out", default="book.azw3", help="output file")
    ap.add_argument("--title", default="JS book", help="book title / page heading")
    ap.add_argument("--text", default="azwjs demo book - pass --text to customize",
                    help="visible text under the heading")
    ap.add_argument("--slot-size", type=int, default=1800,
                    help="inline slot pad size (default %(default)s)")
    ap.add_argument("--onload-slot-size", type=int, default=400,
                    help="onload slot pad size (default %(default)s)")
    ap.add_argument("--kindlegen", default="kindlegen",
                    help="path to the kindlegen binary")
    ap.add_argument("--keep-base", metavar="FILE",
                    help="also save the unpatched kindlegen output")
    ap.add_argument("--workdir", help="keep build sources in this directory")
    args = ap.parse_args()

    js = [load_payload(p) for p in (args.js or [])]
    js_big = load_payload(args.js_big)
    js_media = load_payload(args.js_media)
    js_onload = load_payload(args.js_onload)

    if not js and js_big is None and js_media is None and js_onload is None:
        ap.error("no payload given: use --js / --js-big / --js-media / --js-onload")
    if js and js_big is not None:
        ap.error("--js and --js-big are mutually exclusive")

    if js_big is not None:
        slot_sizes = [args.slot_size] * max(1, len(js_big) // args.slot_size + 1)
    elif js:
        slot_sizes = [args.slot_size] * len(js)
    else:
        slot_sizes = []

    local_len = 200

    builder = Builder(kindlegen=args.kindlegen,
                      workdir=args.workdir if args.workdir else None)

    final = None
    # iterate: grow slot sizes when a payload does not fit its measured span
    for attempt in range(10):
        base = builder.build(args.title, args.text, slot_sizes, local_len,
                             args.onload_slot_size)
        mobi = Mobi(base)
        slots, local, onload = mobi.find_slots()

        # ---- compute the patch plan; re-iterate if it does not fit --------
        jobs = []
        ok = True

        if js:
            if any(i not in slots for i in range(len(js))):
                # a marker was missed (probably split across a record
                # boundary); growing shifts the layout
                slot_sizes = [s + 512 for s in slot_sizes]
                ok = False
            else:
                for i, f in enumerate(js):
                    total = sum(e - s for _, s, e in slots[i])
                    if len(build_inline_tag(f)) > total:
                        slot_sizes[i] += 512
                        ok = False
                if ok:
                    jobs.append(job_inline_slots(js))

        if js_big is not None:
            spans = [slots[i] for i in range(len(slot_sizes)) if i in slots]
            if len(spans) != len(slot_sizes):
                slot_sizes = [s + 512 for s in slot_sizes]
                ok = False
            else:
                caps = [sum(e - s for _, s, e in frags) -
                        len(build_chunk_tag(b"", i == 0, i == len(spans) - 1)) -
                        3 * (len(frags) - 1)   # room for literal splits
                        for i, frags in enumerate(spans)]
                chunk_sizes, pos = [], 0
                for c in caps:
                    n = fit_chunk(js_big, pos, c)
                    chunk_sizes.append(n)
                    pos += n
                if pos < len(js_big):
                    slot_sizes = [s + 512 for s in slot_sizes]
                    ok = False
                else:
                    jobs.append(job_chunked(js_big, chunk_sizes))

        if js_media is not None:
            if local is None:
                local_len += 128
                ok = False
            else:
                jobs.append(job_media(js_media))
        if js_onload is not None:
            if onload is None:
                args.onload_slot_size += 128
                ok = False
            else:
                def _onload_job(mobi, data, slots, local, onload, _js=js_onload):
                    patch_fragments(mobi, data, onload, build_onload_attr(_js))
                jobs.append(_onload_job)
        jobs.append(job_local(js_media is not None))

        if not ok:
            continue

        tmp_out = os.path.join(builder.workdir, "patched.azw3")
        patch_book(base, tmp_out, jobs)
        final = tmp_out
        if args.keep_base:
            shutil.copy(base, args.keep_base)
        break
    else:
        raise SystemExit("could not fit the payload into a slot-safe layout")

    shutil.copy(final, args.out)
    print(f"wrote {args.out}")
    print(f"  records: {mobi.num_records}, KF8 text records: {mobi.text_records}")
    media, gif = mobi.find_media_record(), mobi.find_gif_record()
    if media is not None:
        print(f"  media record: {media} ({mobi.sizes[media]} bytes)")
    if gif is not None:
        print(f"  gif record: {gif}")
    if js_media is not None and media is not None:
        print(f"  external script: kindle:embed:"
              f"{k8_index(mobi.resource_slots().index(media) + 1)}?mime=text/javascript")


if __name__ == "__main__":
    main()
