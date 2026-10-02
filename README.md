# SpiderCat

> [!NOTE]
> This repository contains the source code and process explanation for building the SpiderCat jailbreak book.
> If you're looking for instructions on how to actually perform the jailbreak, go to [KindleModding](https://kindlemodding.org/jailbreaking/SpiderCat/)!

`build.py` builds `spidercat.azw3`, a fixed-layout Kindle book that, when opened, runs a shell command (by default, executing `jb.sh` Kindle jailbreak) via a `JSArray::sort` use-after-free in webreader's WebKit.

Supported firmware: Kindle OS **5.16.3 through 5.19.5** (hard-float builds).
5.19.6 and later patched the entry point by sandboxing the webreader iframe.

## Requirements

- **Python3** (runs the build)
- **`azwjs.py`** (MOBI/AZW3 container library)
- **`kindlegen` on `PATH`** (Amazon's KF8 compiler; see below)

`kindlegen` is Amazon's proprietary KF8 compiler. It is not open source; it was historically a standalone download and is now bundled inside **Kindle Previewer** (macOS/Windows, free from Amazon). Point `kindlegen` on your `PATH` at that binary, e.g.:

```sh
# macOS / Windows (Kindle Previewer install)
ln -s "/Applications/Kindle Previewer 3.app/Contents/MacOS/lib/fc/bin/kindlegen" ~/.local/bin/kindlegen
```

On Linux, Amazon provides no current Kindle Previewer build. Options:

- Use the legacy standalone Linux `kindlegen` (a 32-bit x86 binary; Amazon no longer distributes it officially). On 64-bit Linux you must install 32-bit compatibility libraries first, at minimum the 32-bit C library:
    - Debian/Ubuntu: `sudo dpkg --add-architecture i386 && sudo apt update && sudo apt install libc6:i386`
    - Fedora:        `sudo dnf install glibc.i686`
    - Arch:          `enable [multilib], then sudo pacman -S lib32-glibc`
 
    If running it says "No such file or directory" even though the file exists, the 32-bit libraries are missing. `ldd ./kindlegen` shows which ones.
- Or run Kindle Previewer's kindlegen inside a Windows or macOS VM.

Verify with:

```sh
kindlegen -locale en 2>&1 | head -1   # should print kindlegen + a version
```

### Optional: 

- **Pillow** (resizes the cover/thumbnail)

kindlegen's output thumbnail is a small, low-resolution GIF that looks pretty bad even in e-ink. Thumbnail seems to only appear in firmwares 5.19.x. Automatically installed if you use `uv`, or:

```sh
pip install pillow
```

## Inputs

- `offsets.json`: per-firmware constants (entry-point fingerprint, libc offsets)
- `page.xhtml`: the visible page shown while the exploit runs
- `style.css`: its stylesheet
- `cover.png`: optional library thumbnail (shows on 5.19.x only?)

## Build

```sh
python3 build.py
```

This produces `spidercat.azw3`.

## Adding a new firmware

Derive the per-firmware constants from three binaries pulled from a firmware rootfs (either from a device or from an OTA update package):

- `lib/libc.so.6`
- `usr/lib/libwebkitgtk-1.0.so.0`
- `usr/bin/webreader`

Run `derive_offsets.py` (in this directory; needs `nm` + `readelf` from binutils on `PATH`):

```sh
python3 derive_offsets.py --json libc.so.6 libwebkitgtk-1.0.so.0 webreader
```

`build.py` only consumes four of the emitted fields, `e_entry`, `system`, `g_strcmp0_got`, `candidates`, and they must be stored as `0x…` hex strings. Add them to `offsets.json` under a `"Model-version"` key (matching the shape of the existing entries) and rebuild:

```sh
python3 build.py
```
