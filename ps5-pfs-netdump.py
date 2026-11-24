#!/usr/bin/env python3
"""ps5-pfs-netdump: dump a running PS5 game over the network, matching ps5-app-dumper.

While a game runs on a jailbroken PS5, the kernel exposes its decrypted,
decompressed inner PFS image at

    /mnt/sandbox/pfsmnt/<TITLEID>-app0-nest/pfs_image.dat

Read over FTP, this file is a plain PFS v2 image. The superblock, inode table
and directories sit near the end of the image. ps5-pfs-netdump finds the
superblock, walks the directory tree and then streams the image once from
start to end, writing each file as its bytes go past. It then adds what
ps5-app-dumper adds, in the same order, so the result is the same dump:

  1. sce_sys entries from the installed package (/user/app/<ID>/app.pkg)
  2. the game files (streamed from the -nest image; app0 wins over step 1)
  3. /user/appmeta/<ID> and /system_data/priv/appmeta/<ID> into sce_sys
  4. trophy and uds data, found through the NPWR id in npbind.dat
  5. decrypted executables, read through the regular app0 mount

Standard library only. Python 3.9+.
"""
from __future__ import annotations

import argparse
import ftplib
import json
import os
import re
import shutil
import socket
import struct
import sys
import time

__version__ = "0.2.0"

PFS_MAGIC = 20130315          # 0x01332A0B
INODE_SIZE = 0xA8
DIRENT_FILE = 2
DIRENT_DIR = 3
PFSMNT = "/mnt/sandbox/pfsmnt"
TITLE_RE = re.compile(r"^([A-Z]{4}\d{5})-app0-nest$")
MB = 1 << 20
SELF_MAGIC = b"\x54\x14\xf5\xee"
ELF_MAGIC = b"\x7fELF"
CNT_MAGIC = b"\x7fCNT"
MANIFEST = ".ps5-pfs-netdump.json"   # written as <outdir>.ps5-pfs-netdump.json


class DumpError(Exception):
    pass


# --------------------------------------------------------------------------
# The console's filesystem: over FTP, or a local folder laid out the same way
# (for tests and offline runs)
# --------------------------------------------------------------------------

class FtpConsole:
    def __init__(self, host: str, port: int = 2121, timeout: float = 30):
        self.host, self.port, self.timeout = host, port, timeout

    def _connect(self) -> ftplib.FTP:
        ftp = ftplib.FTP(timeout=self.timeout)
        ftp.connect(self.host, self.port)
        ftp.login()
        ftp.voidcmd("TYPE I")
        return ftp

    def listdir(self, path: str):
        """[(name, is_dir, size)], or None if path is not a readable directory.
        Uses LIST: the PS5 ftpsrv payload doesn't implement NLST."""
        ftp = self._connect()
        lines: list[str] = []
        try:
            ftp.retrlines(f"LIST {path}", lines.append)
        except ftplib.Error:
            return None
        finally:
            _quit(ftp)
        out = []
        for line in lines:
            p = line.split(None, 8)
            if len(p) < 9 or p[8] in (".", ".."):
                continue
            out.append((p[8], line.startswith("d"), int(p[4]) if p[4].isdigit() else 0))
        return out

    def size(self, path: str):
        ftp = self._connect()
        try:
            try:
                n = ftp.size(path)
                if n is not None:
                    return n
            except ftplib.error_perm:
                pass
        finally:
            _quit(ftp)
        parent, name = path.rsplit("/", 1)
        for n, is_dir, sz in self.listdir(parent) or []:
            if n == name and not is_dir:
                return sz
        return None

    def read(self, path: str, off: int, n: int) -> bytes:
        ftp = self._connect()
        try:
            conn = ftp.transfercmd(f"RETR {path}", rest=off)
            buf = bytearray()
            while len(buf) < n:
                chunk = conn.recv(min(n - len(buf), 4 * MB))
                if not chunk:
                    break
                buf += chunk
            conn.close()
            return bytes(buf[:n])
        finally:
            _quit(ftp)

    def stream(self, path: str, off: int):
        return _FtpStream(self._connect(), path, off)

    def fetch(self, path: str, local: str):
        ftp = self._connect()
        try:
            with open(local, "wb") as f:
                ftp.retrbinary(f"RETR {path}", f.write, blocksize=4 * MB)
        finally:
            _quit(ftp)


class _FtpStream:
    def __init__(self, ftp: ftplib.FTP, path: str, off: int):
        self.ftp = ftp
        self.conn = ftp.transfercmd(f"RETR {path}", rest=off)
        self.f = self.conn.makefile("rb")

    def read(self, n: int) -> bytes:
        return self.f.read(n)

    def close(self):
        for c in (self.f, self.conn):
            try:
                c.close()
            except OSError:
                pass
        _quit(self.ftp)


def _quit(ftp: ftplib.FTP):
    # The PS5 FTP payloads answer an early-closed RETR inconsistently, so do not
    # wait for a reply; just drop the control connection.
    try:
        ftp.close()
    except OSError:
        pass


class DirConsole:
    """A local folder standing in for the console's root filesystem."""

    def __init__(self, root: str):
        self.root = root

    def _p(self, path: str) -> str:
        return os.path.join(self.root, path.lstrip("/"))

    def listdir(self, path: str):
        p = self._p(path)
        if not os.path.isdir(p):
            return None
        return [(n, os.path.isdir(os.path.join(p, n)),
                 0 if os.path.isdir(os.path.join(p, n)) else os.path.getsize(os.path.join(p, n)))
                for n in sorted(os.listdir(p))]

    def size(self, path: str):
        p = self._p(path)
        return os.path.getsize(p) if os.path.isfile(p) else None

    def read(self, path: str, off: int, n: int) -> bytes:
        with open(self._p(path), "rb") as f:
            f.seek(off)
            return f.read(n)

    def stream(self, path: str, off: int):
        f = open(self._p(path), "rb")
        f.seek(off)
        return f

    def fetch(self, path: str, local: str):
        shutil.copyfile(self._p(path), local)


class ImageReader:
    """One file on the console, as the PFS code wants it."""

    def __init__(self, console, path: str):
        self.console, self.path = console, path

    def size(self) -> int:
        n = self.console.size(self.path)
        if not n:
            raise DumpError(f"{self.path} not found. Is the game running?")
        return n

    def read(self, off: int, n: int) -> bytes:
        return self.console.read(self.path, off, n)

    def stream(self, off: int):
        return self.console.stream(self.path, off)


def list_nest_titles(console) -> list[str]:
    out = []
    for name, is_dir, _ in console.listdir(PFSMNT) or []:
        m = TITLE_RE.match(name)
        if m and is_dir:
            out.append(m.group(1))
    return sorted(set(out))


# --------------------------------------------------------------------------
# PFS parsing
# --------------------------------------------------------------------------

class Superblock:
    def __init__(self, offset: int, raw: bytes):
        self.offset = offset
        self.version, self.magic = struct.unpack_from("<QQ", raw, 0)
        self.mode = struct.unpack_from("<H", raw, 0x1C)[0]
        self.block_size = struct.unpack_from("<I", raw, 0x20)[0]
        self.inode_count = struct.unpack_from("<Q", raw, 0x30)[0]
        self.block_count = struct.unpack_from("<Q", raw, 0x38)[0]

    def __repr__(self):
        return (f"Superblock(offset={self.offset}, version={self.version}, mode={self.mode:#x}, "
                f"block_size={self.block_size:#x}, inodes={self.inode_count}, blocks={self.block_count})")


def _superblock_at(buf: bytes, pos: int, base: int, image_size: int):
    version, magic = struct.unpack_from("<QQ", buf, pos)
    if magic != PFS_MAGIC or version not in (1, 2, 3):
        return None
    sb = Superblock(base + pos, buf[pos:pos + 0x400])
    bs = sb.block_size
    if bs == 0 or bs % 0x1000 or bs > MB:
        return None
    if sb.block_count * bs != image_size or sb.offset % bs:
        return None
    return sb


def find_superblock(src, image_size: int, windows=(64 * MB, 256 * MB, 1024 * MB, 4096 * MB), log=print):
    """Scan the end of the image for the inner superblock, widening the window.

    Returns (superblock, tail_bytes, tail_base). The tail runs from the
    superblock to the end of the image, so it holds all the metadata.
    """
    have = b""          # bytes from (image_size - len(have)) to the end
    for win in windows:
        win = min(win, image_size)
        if win > len(have):
            start = image_size - win
            log(f"searching the last {win / MB:.0f} MB for the superblock ...")
            have = src.read(start, win - len(have)) + have
        base = image_size - len(have)
        # Scan from the end backwards: the superblock nearest the end is the inner one.
        first = (len(have) - 0x400) & ~0xFFF
        for pos in range(first, -1, -0x1000):
            if (base + pos) % 0x1000:
                continue
            sb = _superblock_at(have, pos, base, image_size)
            if sb:
                return sb, have[pos:], sb.offset
        if win >= image_size:
            break
    raise DumpError("no PFS superblock found near the end of the image "
                    "(is the game still running, and is this a -nest mount?)")


class Image:
    def __init__(self, src, sb: Superblock, tail: bytes, tail_base: int):
        self.src, self.sb, self.tail, self.base = src, sb, tail, tail_base
        bs = sb.block_size
        per_block = bs // INODE_SIZE
        table = sb.offset + bs
        self.inodes = []
        for i in range(sb.inode_count):
            at = table + (i // per_block) * bs + (i % per_block) * INODE_SIZE
            raw = self.read(at, INODE_SIZE)
            mode = struct.unpack_from("<H", raw, 0)[0]
            size = struct.unpack_from("<Q", raw, 0x08)[0]
            loc = struct.unpack_from("<Q", raw, 0x60)[0]
            self.inodes.append((mode, size, loc))

    def read(self, off: int, n: int) -> bytes:
        s = off - self.base
        if 0 <= s and s + n <= len(self.tail):
            return self.tail[s:s + n]
        data = self.src.read(off, n)
        if len(data) != n:
            raise DumpError(f"short read at {off}")
        return data

    def dirents(self, ino: int):
        _, size, loc = self.inodes[ino]
        buf = self.read(loc, size)
        bs = self.sb.block_size
        pos = 0
        while pos + 16 <= len(buf):
            child, kind, name_len, rec_len = struct.unpack_from("<IIII", buf, pos)
            if rec_len == 0:            # rest of this block is padding
                pos += bs - pos % bs
                continue
            yield child, kind, buf[pos + 16:pos + 16 + name_len].decode("utf-8", "replace")
            pos += rec_len

    def walk(self):
        """Return (files, dirs). files: [(path, offset, size)], paths relative to the super-root."""
        files, dirs, seen = [], [], set()
        stack = [(0, "")]
        while stack:
            ino, path = stack.pop()
            if ino in seen:
                continue
            seen.add(ino)
            for child, kind, name in self.dirents(ino):
                if name in (".", ".."):
                    continue
                if "/" in name or name == "":
                    raise DumpError(f"bad file name {name!r} in {path or '/'}")
                p = f"{path}/{name}"
                if kind == DIRENT_DIR:
                    dirs.append(p)
                    stack.append((child, p))
                elif kind == DIRENT_FILE:
                    _, size, loc = self.inodes[child]
                    files.append((p, loc, size))
        return files, dirs


# --------------------------------------------------------------------------
# Streaming
# --------------------------------------------------------------------------

def plan(files, root="/uroot"):
    """Game files under root, as (offset, size, relative path), sorted by offset."""
    prefix = root.rstrip("/") + "/"
    out = sorted((off, size, p[len(prefix):]) for p, off, size in files if p.startswith(prefix))
    for (o1, s1, p1), (o2, _, p2) in zip(out, out[1:]):
        if s1 and o1 + s1 > o2:
            raise DumpError(f"files overlap in the image: {p1} and {p2}")
    return out


def _magic(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(4)
    except OSError:
        return b""


def _done(path: str, size: int) -> bool:
    """True if the file is complete. An ELF in place of the image's SELF counts as
    complete: it is the decrypted copy fetched from app0, and its size differs."""
    try:
        if os.path.getsize(path) == size:
            return True
    except OSError:
        return False
    return _magic(path) == ELF_MAGIC


def stream_files(src, entries, outdir: str, log=print, progress_every=10_000_000_000):
    """Write every entry. Files already on disk at the right size are skipped (resume)."""
    todo = []
    for off, size, rel in entries:
        dst = os.path.join(outdir, rel)
        if size == 0:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            open(dst, "wb").close()
        elif not _done(dst, size):
            todo.append((off, size, rel, dst))
    if not todo:
        log("all files already present")
        return 0, 0
    total = sum(t[1] for t in todo)
    start, end = todo[0][0], todo[-1][0] + todo[-1][1]
    log(f"{len(todo)} files, {total / 1e9:.2f} GB to write; streaming {(end - start) / 1e9:.2f} GB")
    s = src.stream(start)
    pos, written, t0, next_mark = start, 0, time.time(), progress_every
    try:
        for off, size, rel, dst in todo:
            gap = off - pos
            while gap:
                k = len(s.read(min(gap, 4 * MB)))
                if not k:
                    raise DumpError("stream ended early (did the game close?)")
                gap -= k
                pos += k
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            tmp = dst + ".part"
            with open(tmp, "wb") as f:
                n = size
                while n:
                    chunk = s.read(min(n, 4 * MB))
                    if not chunk:
                        raise DumpError(f"stream ended early in {rel} (did the game close?)")
                    f.write(chunk)
                    n -= len(chunk)
            os.replace(tmp, dst)
            pos += size
            written += size
            if written >= next_mark:
                dt = time.time() - t0
                log(f"  {written / 1e9:.0f} / {total / 1e9:.0f} GB, {(pos - start) / dt / 1e6:.0f} MB/s")
                next_mark += progress_every
    finally:
        s.close()
    dt = max(time.time() - t0, 1e-9)
    log(f"wrote {written / 1e9:.2f} GB in {dt:.0f} s ({(pos - start) / dt / 1e6:.0f} MB/s)")
    return len(todo), written


def verify(entries, outdir: str):
    bad = [rel for _, size, rel in entries if not _done(os.path.join(outdir, rel), size)]
    return bad


def elf_ok(path: str) -> bool:
    """A light sanity check on a decrypted ELF: the header and every program
    header's file range must fit inside the file."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            h = f.read(64)
            if len(h) < 64 or h[:4] != ELF_MAGIC or h[4] != 2:   # ELFCLASS64
                return False
            phoff = struct.unpack_from("<Q", h, 0x20)[0]
            phentsize, phnum = struct.unpack_from("<HH", h, 0x36)
            if phnum == 0 or phentsize < 56 or phoff + phnum * phentsize > size:
                return False
            f.seek(phoff)
            ph = f.read(phnum * phentsize)
        for i in range(phnum):
            off = struct.unpack_from("<Q", ph, i * phentsize + 0x08)[0]
            filesz = struct.unpack_from("<Q", ph, i * phentsize + 0x20)[0]
            if filesz and off + filesz > size:
                return False
        return True
    except (OSError, struct.error):
        return False


def find_selfs(entries, outdir: str):
    """Files in the dump that are still encrypted SELFs."""
    return [rel for _, size, rel in entries
            if size >= 4 and _magic(os.path.join(outdir, rel)) == SELF_MAGIC]


def decrypt_selfs(console, app0: str, selfs, outdir: str, log=print):
    """Replace each encrypted SELF with the decrypted ELF that the game's app0 mount
    serves. Returns the list that failed (those keep the encrypted SELF)."""
    failed = []
    for rel in selfs:
        dst = os.path.join(outdir, rel)
        tmp = dst + ".elf.part"
        try:
            console.fetch(f"{app0}/{rel}", tmp)
        except (OSError, ftplib.Error, socket.timeout) as e:
            log(f"  {rel}: download failed ({e}); kept the encrypted SELF")
            failed.append(rel)
            continue
        if _magic(tmp) != ELF_MAGIC or not elf_ok(tmp):
            log(f"  {rel}: app0 did not return a valid ELF; kept the encrypted SELF")
            os.remove(tmp)
            failed.append(rel)
            continue
        os.replace(tmp, dst)
        log(f"  {rel}: decrypted ELF, {os.path.getsize(dst):,} bytes")
    return failed


# --------------------------------------------------------------------------
# The rest of a ps5-app-dumper dump: package sce_sys entries, appmeta,
# trophy and uds
# --------------------------------------------------------------------------

# Names for package entries that have none in the package's name table.
PKG_ENTRY_NAMES = {
    0x0400: "license.dat", 0x0401: "license.info", 0x0402: "nptitle.dat",
    0x0403: "npbind.dat", 0x0404: "selfinfo.dat", 0x0406: "imageinfo.dat",
    0x0407: "target-deltainfo.dat", 0x0408: "origin-deltainfo.dat",
    0x0409: "psreserved.dat", 0x1000: "param.json", 0x1001: "playgo-chunk.dat",
    0x1002: "playgo-chunk.sha", 0x1003: "playgo-manifest.xml",
    0x1004: "pronunciation.xml", 0x1005: "pronunciation.sig", 0x1006: "pic1.png",
    0x1007: "pubtoolinfo.dat", 0x1200: "icon0.png", 0x1220: "pic0.png",
    0x1240: "snd0.at9", 0x1260: "changeinfo/changeinfo.xml", 0x1280: "icon0.dds",
    0x12A0: "pic0.dds", 0x12C0: "pic1.dds",
}
PKG_NAME_TABLE = 0x0200


def _safe_rel(name: str):
    """A relative path that stays inside its folder, or None."""
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or ".." in parts or name.startswith("/"):
        return None
    return "/".join(parts)


def sc_pkg_offset(app_json: bytes):
    """The offset of the _sc.pkg piece (the package's CNT header) inside app.pkg."""
    try:
        doc = json.loads(app_json)
    except ValueError:
        return None
    for piece in doc.get("pieces", []):
        if "_sc.pkg" in str(piece.get("url", "")):
            return int(piece["fileOffset"])
    return None


def pkg_sce_sys_entries(read, base: int):
    """[(name, offset, size)] for the sce_sys files in a CNT package whose header
    starts at base. read(off, n) reads the package. All fields are big-endian."""
    hdr = read(base, 0x20)
    if hdr[:4] != CNT_MAGIC:
        raise DumpError(f"no CNT header at {base:#x} in app.pkg")
    n_entries = struct.unpack_from(">H", hdr, 0x12)[0]
    table_off = struct.unpack_from(">I", hdr, 0x18)[0]
    raw = read(base + table_off, n_entries * 32)
    if len(raw) != n_entries * 32:
        raise DumpError("short read of the app.pkg entry table")
    entries = [struct.unpack_from(">IIIIIIII", raw, i * 32) for i in range(n_entries)]
    names = b""
    for typ, _, _, _, off, size, _, _ in entries:
        if typ == PKG_NAME_TABLE:
            if 0 < size <= 64 * 1024:
                names = read(base + off, size)
            break
    out = []
    for typ, name_off, _, _, off, size, _, _ in entries:
        if size == 0:
            continue
        name = ""
        if name_off < len(names):
            name = names[name_off:].split(b"\0", 1)[0].decode("utf-8", "replace")
        if not name:
            name = PKG_ENTRY_NAMES.get(typ, "")
        rel = _safe_rel(name) if name else None
        if rel:
            out.append((rel, off, size))
    return out


def npwr_id(npbind: bytes):
    """The trophy/uds communication id: the printable run starting at 'NPWR'."""
    i = npbind.find(b"NPWR")
    if i < 0:
        return None
    j = i
    while j < len(npbind) and j - i < 31 and 0x20 <= npbind[j] < 0x7F:
        j += 1
    return npbind[i:j].decode()


def _write_atomic(dst: str, data: bytes):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    tmp = dst + ".part"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, dst)


def _fetch_atomic(console, src: str, dst: str):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    tmp = dst + ".part"
    console.fetch(src, tmp)
    os.replace(tmp, dst)


def copy_tree(console, src: str, dst: str, log=print):
    """Copy a console folder into dst recursively, overwriting. Returns the file count."""
    items = console.listdir(src)
    if items is None:
        return None
    os.makedirs(dst, exist_ok=True)
    n = 0
    for name, is_dir, _ in items:
        if _safe_rel(name) != name:
            continue
        if is_dir:
            n += copy_tree(console, f"{src}/{name}", os.path.join(dst, name), log) or 0
        else:
            _fetch_atomic(console, f"{src}/{name}", os.path.join(dst, name))
            n += 1
    return n


def pkg_sce_sys(console, title: str, outdir: str, skip: set, log=print):
    """Step 1: write the package's sce_sys entries, except paths the game files
    provide (the dumper copies app0 afterwards, so app0 wins)."""
    for root in ("/user/app", "/mnt/ext1/user/app", "/mnt/ext0/user/app"):
        pkg = f"{root}/{title}/app.pkg"
        if console.size(pkg):
            break
    else:
        log("  no installed app.pkg found; skipping package sce_sys entries")
        return 0
    js = console.size(pkg[:-4] + ".json")
    base = sc_pkg_offset(console.read(pkg[:-4] + ".json", 0, js)) if js else None
    if base is None:
        log(f"  no _sc.pkg piece in {pkg[:-4]}.json; skipping package sce_sys entries")
        return 0
    entries = pkg_sce_sys_entries(lambda off, n: console.read(pkg, off, n), base)
    n = 0
    for rel, off, size in entries:
        rel = f"sce_sys/{rel}"
        if rel in skip:
            continue
        data = console.read(pkg, base + off, size)
        if len(data) != size:
            raise DumpError(f"short read of {rel} from {pkg}")
        _write_atomic(os.path.join(outdir, rel), data)
        n += 1
    log(f"  {pkg}: {n} sce_sys files")
    return n


def appmeta_trophy_uds(console, title: str, outdir: str, log=print):
    """Steps 3 and 4, in the dumper's order."""
    sce_sys = os.path.join(outdir, "sce_sys")
    for src in (f"/user/appmeta/{title}", f"/system_data/priv/appmeta/{title}"):
        n = copy_tree(console, src, sce_sys, log)
        log(f"  {src}: {n} files" if n is not None else f"  {src}: not found")
    os.makedirs(os.path.join(sce_sys, "trophy2"), exist_ok=True)
    os.makedirs(os.path.join(sce_sys, "uds"), exist_ok=True)
    npbind = None
    for p in (f"/system_data/priv/appmeta/{title}/trophy2/npbind.dat",
              f"/system_data/priv/appmeta/{title}/uds/npbind.dat"):
        n = console.size(p)
        if n:
            npbind = console.read(p, 0, min(n, 4096))
            break
    np_id = npwr_id(npbind) if npbind else None
    if not np_id:
        log("  no NPWR id in npbind.dat; no trophy or uds data")
        return
    for src, rel in ((f"/user/trophy2/nobackup/conf/{np_id}/TROPHY.UCP", "trophy2/trophy00.ucp"),
                     (f"/user/np_uds/nobackup/conf/{np_id}/uds.ucp", "uds/uds00.ucp")):
        if console.size(src):
            _fetch_atomic(console, src, os.path.join(sce_sys, rel))
            log(f"  {src} -> sce_sys/{rel}")
        else:
            log(f"  {src}: not found")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="ps5-pfs-netdump",
        description="Dump a running PS5 game over FTP, producing the same dump as ps5-app-dumper.")
    ap.add_argument("host", help="PS5 IP address")
    ap.add_argument("title", nargs="?", help="title ID, e.g. PPSA01234 (omit to list running titles)")
    ap.add_argument("outdir", nargs="?", help="output folder (default: ./<TITLEID>-app0)")
    ap.add_argument("--port", type=int, default=2121, help="FTP port (default 2121)")
    ap.add_argument("--list-only", action="store_true", help="parse and print the file list, do not download")
    ap.add_argument("--keep-encrypted", action="store_true",
                    help="keep the encrypted SELF executables; don't fetch decrypted ELFs from app0")
    ap.add_argument("--game-files-only", action="store_true",
                    help="only the files in the game image: skip package sce_sys, appmeta, trophy and uds")
    ap.add_argument("--local-root", help=argparse.SUPPRESS)   # tests: a folder standing in for the console
    ap.add_argument("--version", action="version", version=f"ps5-pfs-netdump {__version__}")
    a = ap.parse_args(argv)

    console = DirConsole(a.local_root) if a.local_root else FtpConsole(a.host, a.port)
    try:
        if not a.title:
            titles = list_nest_titles(console)
            if not titles:
                print(f"no -nest mounts in {PFSMNT}. Start the game on the PS5 and leave it running.")
                return 1
            print("running titles with a -nest mount:")
            for t in titles:
                print(f"  {t}")
            return 0
        title = a.title.upper()
        src = ImageReader(console, f"{PFSMNT}/{title}-app0-nest/pfs_image.dat")
        outdir = a.outdir or f"{title}-app0"

        size = src.size()
        print(f"pfs_image.dat: {size / 1e9:.2f} GB")
        sb, tail, base = find_superblock(src, size)
        print(f"superblock at {sb.offset} ({(size - sb.offset) / MB:.0f} MB from the end), "
              f"block size {sb.block_size:#x}, {sb.inode_count} inodes")
        img = Image(src, sb, tail, base)
        files, dirs = img.walk()
        entries = plan(files)
        total = sum(e[1] for e in entries)
        print(f"{len(entries)} game files, {total / 1e9:.2f} GB")

        os.makedirs(outdir, exist_ok=True)
        # Next to the dump, not inside it, so the folder matches ps5-app-dumper's.
        with open(outdir.rstrip("/\\") + MANIFEST, "w") as f:
            json.dump({"title": title, "image_size": size, "superblock": sb.offset,
                       "files": [[rel, off, sz] for off, sz, rel in entries]}, f)
        if a.list_only:
            for off, sz, rel in entries:
                print(f"{off:>14} {sz:>12} {rel}")
            return 0

        game_paths = {rel for _, _, rel in entries}
        if not a.game_files_only:
            print("package sce_sys entries:")
            pkg_sce_sys(console, title, outdir, game_paths)

        for d in dirs:
            if d.startswith("/uroot/"):
                os.makedirs(os.path.join(outdir, d[len("/uroot/"):]), exist_ok=True)
        stream_files(src, entries, outdir)
        bad = verify(entries, outdir)
        if bad:
            print(f"{len(bad)} files have the wrong size, e.g. {bad[0]}. Run again to resume.")
            return 1

        if not a.game_files_only:
            print("appmeta, trophy and uds:")
            appmeta_trophy_uds(console, title, outdir)

        selfs = find_selfs(entries, outdir)
        failed = selfs
        if selfs and not a.keep_encrypted:
            print(f"decrypted executables from {title}-app0:")
            failed = decrypt_selfs(console, f"{PFSMNT}/{title}-app0", selfs, outdir)
        print(f"done: {outdir}")
        if failed:
            print(f"note: {len(failed)} executables are still encrypted SELFs (e.g. {failed[0]}).")
        return 0
    except (DumpError, OSError, ftplib.Error, socket.timeout) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted; run the same command again to resume", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
