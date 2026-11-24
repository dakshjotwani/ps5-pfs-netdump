"""End to end against the fake console: the single-pass .ffpkg must hold the same game as
the two-step path (the Python folder dump, then Forge's own conversion).

Needs the Rust tool and Forge's CLI built:
    cargo build                                   # this repo
    cargo build -p ps5-dump-forge-cli             # in ../ps5-dump-forge
Override their paths with NETDUMP_BIN and FORGE_BIN.
"""
import json
import os
import subprocess
import tempfile
import unittest

import test_netdump as t

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
NETDUMP_BIN = os.environ.get("NETDUMP_BIN", os.path.join(REPO, "target", "debug", "ps5-pfs-netdump"))
FORGE_BIN = os.environ.get(
    "FORGE_BIN", os.path.join(REPO, "..", "ps5-dump-forge", "target", "debug", "ps5-dump-forge"))


def run(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def inspect(path):
    r = run(FORGE_BIN, "inspect", path, "--json")
    assert r.returncode == 0, r.stderr
    info = json.loads(r.stdout)
    info.pop("cover", None)
    info.pop("describe", None)   # names the path
    return info


def unpack(image, out):
    r = run(FORGE_BIN, "convert", image, "--to", "folder", "-o", out)
    assert r.returncode == 0, r.stderr + r.stdout[-2000:]
    return t.read_tree(out)


@unittest.skipUnless(os.path.exists(NETDUMP_BIN) and os.path.exists(FORGE_BIN), "binaries not built")
class SinglePassTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "console")
        t.build_console(self.root)
        self.p = lambda *a: os.path.join(self.tmp.name, *a)

    def tearDown(self):
        self.tmp.cleanup()

    def decrypt_all(self):
        """app0 serves every executable decrypted (the fake console leaves lib.prx encrypted)."""
        t._put(self.root, f"/mnt/sandbox/pfsmnt/{t.TITLE}-app0/lib.prx", t.make_elf(b"lib" * 50))
        # Forge's preflight wants a real param.json; the system appmeta copy is the one kept.
        t._put(self.root, f"/system_data/priv/appmeta/{t.TITLE}/param.json", json.dumps({
            "titleId": t.TITLE,
            "contentId": f"IP9100-{t.TITLE}_00-0000000000000000",
            "contentVersion": "01.000.000",
            "localizedParameters": {"defaultLanguage": "en-US", "en-US": {"titleName": "Test Game"}},
        }).encode())

    def single_pass(self, out, *extra):
        return run(NETDUMP_BIN, "0.0.0.0", t.TITLE, out, "--local-root", self.root, *extra)

    def test_same_game_as_folder_then_forge(self):
        self.decrypt_all()
        # The two-step reference: folder dump, then Forge.
        folder = self.p("ref-folder")
        rc = t.netdump.main(["0.0.0.0", t.TITLE, folder, "--local-root", self.root])
        self.assertEqual(rc, 0)
        ref = self.p("ref.ffpkg")
        r = run(FORGE_BIN, "convert", folder, "--to", "ffpkg", "-o", ref)
        self.assertEqual(r.returncode, 0, r.stderr)

        new = self.p("new.ffpkg")
        r = self.single_pass(new, "--full-verify")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("0 reopen(s)", r.stderr)

        self.assertEqual(inspect(new), inspect(ref))
        a, b = unpack(ref, self.p("ref-back")), unpack(new, self.p("new-back"))
        self.assertEqual(sorted(a), sorted(b))
        for k in a:
            self.assertEqual(a[k], b[k], k)
        # And the executables went in fake-signed from the decrypted ELFs, not as SELFs.
        self.assertNotEqual(b["eboot.bin"][:4], t.SELF)

    def test_refuses_when_an_executable_stays_encrypted(self):
        new = self.p("new.ffpkg")
        r = self.single_pass(new)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("could not be fetched decrypted", r.stderr)
        self.assertFalse(os.path.exists(new))

    def test_list_only(self):
        r = self.single_pass(self.p("x.ffpkg"), "--list-only")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("data/level1.pak", r.stdout)
        self.assertFalse(os.path.exists(self.p("x.ffpkg")))


if __name__ == "__main__":
    unittest.main()
