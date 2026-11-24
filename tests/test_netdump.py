"""Tests against a fake console: a folder laid out like the PS5's filesystem, with
a synthetic -nest pfs_image.dat (file data first, then the superblock, inode
table and directories at the end), an app0 mount, an installed app.pkg,
appmeta, trophy and uds data."""
import importlib.util
import io
import json
import os
import struct
import tempfile
import unittest
from contextlib import redirect_stdout

_spec = importlib.util.spec_from_file_location(
    "netdump", os.path.join(os.path.dirname(__file__), "..", "ps5-pfs-netdump.py"))
netdump = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(netdump)

BS = 0x10000
TITLE = "TEST00000"
SELF = b"\x54\x14\xf5\xee"


def build_image(tree):
    """tree: {"name": bytes | dict}. Returns the image bytes."""
    data = bytearray()
    inodes = []
    dirs = []

    def alloc(mode, size, loc):
        inodes.append([mode, size, loc])
        return len(inodes) - 1

    def add_dir(node):
        ino = alloc(0x41ED, 0, 0)
        entries = [(ino, netdump.DIRENT_DIR, "."), (ino, netdump.DIRENT_DIR, "..")]
        dirs.append((ino, entries))
        for name, val in node.items():
            if isinstance(val, dict):
                entries.append((add_dir(val), netdump.DIRENT_DIR, name))
            else:
                data.extend(b"\xAA" * 37)              # gap between files
                entries.append((alloc(0x81A4, len(val), len(data)), netdump.DIRENT_FILE, name))
                data.extend(val)
        return ino

    add_dir(tree)
    data.extend(b"\0" * (-len(data) % BS))
    sb_off = len(data)
    per = BS // netdump.INODE_SIZE
    table_blocks = -(-len(inodes) // per)
    cur = sb_off + BS + table_blocks * BS
    blobs = []
    for ino, entries in dirs:
        blob = bytearray()
        for i, (child, kind, name) in enumerate(entries):
            nb = name.encode()
            rec = (16 + len(nb) + 7) & ~7
            blob += struct.pack("<IIII", child, kind, len(nb), rec) + nb + b"\0" * (rec - 16 - len(nb))
            if i == 2:   # an empty record forces a skip to the next block
                blob += b"\0" * (BS - len(blob) % BS)
        blob += b"\0" * (-len(blob) % BS)
        inodes[ino][1], inodes[ino][2] = len(blob), cur
        blobs.append(blob)
        cur += len(blob)
    table = bytearray()
    for i, (mode, size, loc) in enumerate(inodes):
        if i and i % per == 0:
            table += b"\0" * (-len(table) % BS)
        rec = bytearray(netdump.INODE_SIZE)
        struct.pack_into("<H", rec, 0, mode)
        struct.pack_into("<Q", rec, 8, size)
        struct.pack_into("<Q", rec, 0x60, loc)
        table += rec
    table += b"\0" * (table_blocks * BS - len(table))
    sb = bytearray(BS)
    struct.pack_into("<QQ", sb, 0, 2, netdump.PFS_MAGIC)
    struct.pack_into("<H", sb, 0x1C, 0x18)
    struct.pack_into("<I", sb, 0x20, BS)
    struct.pack_into("<Q", sb, 0x30, len(inodes))
    struct.pack_into("<Q", sb, 0x38, cur // BS)
    img = bytes(data) + bytes(sb) + bytes(table) + b"".join(blobs)
    assert len(img) == cur
    return img


def build_pkg(entries, prefix=0x3000):
    """A CNT package after `prefix` junk bytes. entries: [(type, name or None, data)].
    Returns (pkg bytes, CNT offset)."""
    names = bytearray(b"\0")
    name_offs = []
    for _, name, _ in entries:
        if name is None:
            name_offs.append(0)            # points at the empty string -> type name
        else:
            name_offs.append(len(names))
            names += name.encode() + b"\0"
    all_entries = [(netdump.PKG_NAME_TABLE, 0, bytes(names))] + [
        (t, o, d) for (t, _, d), o in zip(entries, name_offs)]
    table_off = 0x1000
    data_off = table_off + 32 * len(all_entries)
    table, body = bytearray(), bytearray()
    for typ, name_off, d in all_entries:
        table += struct.pack(">IIIIIIII", typ, name_off, 0, 0, data_off + len(body), len(d), 0, 0)
        body += d
    hdr = bytearray(table_off)
    hdr[:4] = netdump.CNT_MAGIC
    struct.pack_into(">H", hdr, 0x12, len(all_entries))
    struct.pack_into(">I", hdr, 0x18, table_off)
    return b"\x11" * prefix + bytes(hdr) + bytes(table) + bytes(body), prefix


def make_elf(payload=b"code" * 100):
    """A minimal ELF64 with one program header covering the payload."""
    hdr = bytearray(64)
    hdr[:4] = b"\x7fELF"
    hdr[4] = 2
    struct.pack_into("<Q", hdr, 0x20, 64)
    struct.pack_into("<HH", hdr, 0x36, 56, 1)
    ph = bytearray(56)
    struct.pack_into("<Q", ph, 0x08, 120)
    struct.pack_into("<Q", ph, 0x20, len(payload))
    return bytes(hdr + ph + payload)


GAME = {
    "eboot.bin": SELF + b"\x00" * 4000,
    "lib.prx": SELF + b"\x01" * 900,
    "empty.txt": b"",
    "data": {
        "level1.pak": os.urandom(300_000),
        "nested": {"deep.bin": os.urandom(5000), "tiny": b"x"},
    },
    "sce_sys": {"keystone": b"K" * 96, "pfs-version.dat": b"0123456789"},
}
ELF = make_elf()


def _flatten(tree, prefix=""):
    out = {}
    for k, v in tree.items():
        p = f"{prefix}{k}"
        out.update(_flatten(v, p + "/") if isinstance(v, dict) else {p: v})
    return out


def _put(root, path, data):
    p = os.path.join(root, path.lstrip("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)


def build_console(root):
    """Lay out a fake console. Returns {relpath: bytes} that a ps5-app-dumper dump would hold."""
    _put(root, f"/mnt/sandbox/pfsmnt/{TITLE}-app0-nest/pfs_image.dat",
         build_image({"uroot": GAME, "inode_flat_path_table": b"meta" * 10}))
    # app0: same files, but eboot.bin decrypts; lib.prx comes back still encrypted
    for rel, data in _flatten(GAME).items():
        _put(root, f"/mnt/sandbox/pfsmnt/{TITLE}-app0/{rel}", ELF if rel == "eboot.bin" else data)
    pkg, cnt = build_pkg([
        (0x1000, "param.json", b'{"from":"pkg"}'),
        (0x1001, None, b"playgo chunk"),               # unnamed -> playgo-chunk.dat
        (0x1006, "pic1.png", b"PNG pic1"),
        (0x9999, "keystone", b"pkg keystone"),         # the game image's copy must win
        (0x9998, "../escape.txt", b"nope"),            # must be ignored
        (0x0400, "license.dat", b""),                  # empty -> skipped
    ])
    _put(root, f"/user/app/{TITLE}/app.pkg", pkg)
    _put(root, f"/user/app/{TITLE}/app.json", json.dumps({"pieces": [
        {"fileOffset": 0, "fileSize": cnt, "url": "http://x/IP9100-TEST_0.pkg"},
        {"fileOffset": cnt, "fileSize": len(pkg) - cnt, "url": "http://x/IP9100-TEST_sc.pkg"}]}).encode())
    _put(root, f"/user/appmeta/{TITLE}/icon0.png", b"icon")
    _put(root, f"/user/appmeta/{TITLE}/param.json", b'{"from":"user appmeta"}')
    _put(root, f"/system_data/priv/appmeta/{TITLE}/param.json", b'{"from":"system appmeta"}')
    _put(root, f"/system_data/priv/appmeta/{TITLE}/nptitle.dat", b"nptitle")
    npbind = b"\x00\x01junk\x00NPWR12345_00\x00more"
    _put(root, f"/system_data/priv/appmeta/{TITLE}/trophy2/npbind.dat", npbind)
    _put(root, f"/system_data/priv/appmeta/{TITLE}/uds/npbind.dat", npbind)
    _put(root, "/user/trophy2/nobackup/conf/NPWR12345_00/TROPHY.UCP", b"trophies")
    _put(root, "/user/np_uds/nobackup/conf/NPWR12345_00/uds.ucp", b"uds")

    expected = {rel: data for rel, data in _flatten(GAME).items()}
    expected["eboot.bin"] = ELF
    expected.update({
        "sce_sys/param.json": b'{"from":"system appmeta"}',
        "sce_sys/playgo-chunk.dat": b"playgo chunk",
        "sce_sys/pic1.png": b"PNG pic1",
        "sce_sys/icon0.png": b"icon",
        "sce_sys/nptitle.dat": b"nptitle",
        "sce_sys/trophy2/npbind.dat": npbind,
        "sce_sys/uds/npbind.dat": npbind,
        "sce_sys/trophy2/trophy00.ucp": b"trophies",
        "sce_sys/uds/uds00.ucp": b"uds",
    })
    return expected


def read_tree(root):
    out = {}
    for d, _, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, root)] = fh.read()
    return out


class NetdumpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "console")
        self.expected = build_console(self.root)
        self.out = os.path.join(self.tmp.name, "out")
        self.console = netdump.DirConsole(self.root)
        self.img = netdump.ImageReader(self.console, f"{netdump.PFSMNT}/{TITLE}-app0-nest/pfs_image.dat")

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *extra, title=TITLE):
        buf = io.StringIO()
        args = ["0.0.0.0"] + ([title, self.out] if title else []) + ["--local-root", self.root, *extra]
        with redirect_stdout(buf):
            rc = netdump.main(args)
        return rc, buf.getvalue()

    def entries(self):
        sb, tail, base = netdump.find_superblock(self.img, self.img.size(), log=lambda *_: None)
        return netdump.plan(netdump.Image(self.img, sb, tail, base).walk()[0])

    # --- PFS image -------------------------------------------------------

    def test_finds_superblock(self):
        size = self.img.size()
        sb, tail, base = netdump.find_superblock(self.img, size, log=lambda *_: None)
        self.assertEqual(sb.block_size, BS)
        self.assertEqual(sb.block_count * BS, size)
        self.assertEqual(len(tail), size - base)

    def test_widens_search_window(self):
        logs = []
        netdump.find_superblock(self.img, self.img.size(), windows=(0x4000, 0x8000, 0x200000),
                                log=logs.append)
        self.assertEqual(len(logs), 3)

    def test_rejects_fake_magic_in_file_data(self):
        p = os.path.join(self.root, f"mnt/sandbox/pfsmnt/{TITLE}-app0-nest/pfs_image.dat")
        with open(p, "r+b") as f:
            f.seek(0xF000)
            f.write(struct.pack("<QQ", 2, netdump.PFS_MAGIC))
        sb, _, _ = netdump.find_superblock(self.img, self.img.size(), log=lambda *_: None)
        self.assertEqual(sb.block_count * BS, self.img.size())

    # --- full pipeline ---------------------------------------------------

    def test_lists_running_titles(self):
        rc, out = self.run_cli(title=None)
        self.assertEqual(rc, 0)
        self.assertIn(TITLE, out)

    def test_dump_matches_dumper_layout(self):
        rc, out = self.run_cli()
        self.assertEqual(rc, 0, out)
        got = read_tree(self.out)
        self.assertEqual(sorted(got), sorted(self.expected))
        for rel, data in self.expected.items():
            self.assertEqual(got[rel], data, rel)
        self.assertIn("1 executables are still encrypted", out)       # lib.prx
        self.assertTrue(os.path.exists(self.out + netdump.MANIFEST))   # beside, not inside

    def test_game_files_only(self):
        rc, out = self.run_cli("--game-files-only", "--keep-encrypted")
        self.assertEqual(rc, 0, out)
        self.assertEqual(read_tree(self.out), _flatten(GAME))

    def test_resume_rewrites_only_broken_files(self):
        self.assertEqual(self.run_cli()[0], 0)
        broken = os.path.join(self.out, "data", "nested", "deep.bin")
        with open(broken, "wb") as f:
            f.write(b"partial")
        intact = os.path.join(self.out, "data", "level1.pak")
        mtime = os.path.getmtime(intact)
        rc, out = self.run_cli()
        self.assertEqual(rc, 0, out)
        self.assertIn("1 files", out)
        self.assertEqual(read_tree(self.out), self.expected)
        self.assertEqual(os.path.getmtime(intact), mtime)

    def test_truncated_stream_fails_cleanly(self):
        entries = self.entries()
        short = os.path.join(self.tmp.name, "short.dat")
        with open(self.img.console._p(self.img.path), "rb") as f:
            data = f.read(200_000)
        with open(short, "wb") as f:
            f.write(data)
        src = netdump.ImageReader(netdump.DirConsole("/"), short)
        with self.assertRaises(netdump.DumpError):
            netdump.stream_files(src, entries, self.out, log=lambda *_: None)

    # --- pieces ----------------------------------------------------------

    def test_pkg_entry_names(self):
        with open(os.path.join(self.root, f"user/app/{TITLE}/app.pkg"), "rb") as f:
            pkg = f.read()
        rd = lambda off, n: pkg[off:off + n]
        names = [n for n, _, _ in netdump.pkg_sce_sys_entries(rd, 0x3000)]
        self.assertEqual(names, ["param.json", "playgo-chunk.dat", "pic1.png", "keystone"])
        with self.assertRaises(netdump.DumpError):
            netdump.pkg_sce_sys_entries(rd, 0)

    def test_npwr_id(self):
        self.assertEqual(netdump.npwr_id(b"\x00xNPWR20188_00\x00"), "NPWR20188_00")
        self.assertIsNone(netdump.npwr_id(b"nothing here"))

    def test_elf_ok_rejects_truncated(self):
        path = os.path.join(self.tmp.name, "x.elf")
        with open(path, "wb") as f:
            f.write(ELF)
        self.assertTrue(netdump.elf_ok(path))
        with open(path, "wb") as f:
            f.write(ELF[:-10])
        self.assertFalse(netdump.elf_ok(path))


if __name__ == "__main__":
    unittest.main()
