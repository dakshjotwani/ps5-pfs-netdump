# ps5-pfs-netdump

Dump a game running on a jailbroken PS5 straight to your computer over the network. The result is **the same dump ps5-app-dumper writes to a USB drive**, file for file and byte for byte. You don't need a USB drive, and the console only has to run an FTP server payload.

It's fast because it doesn't copy files one by one. It reads the game's decrypted filesystem image as **one sequential stream**, so it runs at whatever your network can carry.

> **Status: experimental.** It has been tested on one console (firmware 13.60) with a small number of titles. Expect rough edges.

## Tested result

Astro's Playroom (PPSA01325), wired gigabit:

| | ps5-app-dumper (USB) | ps5-pfs-netdump |
|---|---|---|
| Files / folders | 34,382 / 533 | 34,382 / 533 |
| Size | 29.620 GB | 29.620 GB |
| Game data rate | | 101 MB/s (5 min 40 s total) |
| Byte comparison | | **all 34,382 files identical** |

For comparison, reading the dumper's output back file by file over the same network managed about 60 MB/s.

## How it works

While a game is running, the PS5 kernel mounts its image at

```
/mnt/sandbox/pfsmnt/<TITLEID>-app0-nest/pfs_image.dat
```

Read over FTP, this file is the game's inner PFS image, already **decrypted and decompressed**: the kernel handles the NAPS/Kraken layer. It's a PFS v2 filesystem in flat mode, with its superblock, inode table and directories in the last few hundred MB.

ps5-pfs-netdump goes through the same steps as ps5-app-dumper, in the same order. Where two steps write the same file, the later one wins, as in the dumper:

1. **Package `sce_sys` entries.** It reads `/user/app/<ID>/app.json` to find the `_sc.pkg` piece of the installed `app.pkg`, then extracts that package's entries into `sce_sys/` (playgo files, `pic1.png`, `origin-param.json` and so on). Entries that the game image also contains are skipped, because the dumper's `app0` copy overwrites them.
2. **Game files.** It finds the superblock near the end of `pfs_image.dat` (magic `20130315`, where block count × block size = image size), walks the inode and directory tree, then downloads the image **once, in order**, writing each file as its bytes go past.
3. **Appmeta.** It copies `/user/appmeta/<ID>`, then `/system_data/priv/appmeta/<ID>`, into `sce_sys/`.
4. **Trophy and uds.** It reads the `NPWR…` ID from `npbind.dat` and copies `TROPHY.UCP` → `sce_sys/trophy2/trophy00.ucp` and `uds.ucp` → `sce_sys/uds/uds00.ucp`.
5. **Executables.** `eboot.bin`, `.prx` and `.sprx` files are encrypted SELFs in the `-nest` image. Read through the game's regular mount (`<ID>-app0`), they come back as decrypted ELFs. Each one is downloaded from there, checked (ELF header, and every program header must fit in the file), and swapped in. If the check fails, the encrypted SELF stays and the tool says so.

## Requirements

- A jailbroken PS5 that can load ELF payloads.
- An FTP server payload running on the console, such as [ftpsrv](https://github.com/ps5-payload-dev/ftpsrv) (port 2121 by default).
- The game installed on the console (step 1 reads its `app.pkg`).
- Python 3.9 or newer on your computer. It uses only the standard library.
- Enough free disk space for the whole game.

## Usage

Start the game on the PS5 and **leave it running**. Then:

```bash
# list titles that currently have a -nest mount
python3 ps5-pfs-netdump.py 192.168.1.50

# list a title's game files without downloading them
python3 ps5-pfs-netdump.py 192.168.1.50 PPSA01234 --list-only

# dump it
python3 ps5-pfs-netdump.py 192.168.1.50 PPSA01234 ./PPSA01234-app0
```

| Option | Does |
|---|---|
| `--port N` | FTP port (default 2121) |
| `--list-only` | Print the game files with their offsets and sizes, download nothing |
| `--keep-encrypted` | Keep the encrypted SELF executables |
| `--game-files-only` | Only the files in the game image: skip steps 1, 3 and 4 |

If the transfer stops partway, run the same command again. Game files that are already complete are skipped, and the stream restarts at the first missing one. Each file is written as `<name>.part` and renamed when it's complete.

Next to the output folder (not inside it, so the folder stays identical to the dumper's), the tool writes `<outdir>.ps5-pfs-netdump.json`. It lists each game file's path, offset and size in the image.

ps5-app-dumper names its folder `<ID>-app0_<TITLE>`. ps5-pfs-netdump uses whatever `outdir` you give it.

## Single pass to `.ffpkg` (Rust)

`ps5-pfs-netdump` (the Rust binary) skips the folder: it streams the game straight into a ShadowMountPlus `.ffpkg` image built by [PS5 Dump Forge](https://github.com/quer3q/ps5-dump-forge), used as a library. Until its `data_order` option is upstream, Cargo builds Forge from [a fork](https://github.com/dakshjotwani/ps5-dump-forge/tree/data-order).

```bash
cargo build --release
./target/release/ps5-pfs-netdump 192.168.1.50 PPSA01234            # -> "PPSA01234 <Title>.ffpkg"
./target/release/ps5-pfs-netdump 192.168.1.50 PPSA01234 out.ffpkg --full-verify
```

How it differs from the folder dump:

1. It reads the file list from the image, then fetches everything that isn't game data first and keeps it in memory: the package `sce_sys` entries, appmeta, trophy and uds data, and the decrypted executables from `app0`. If an executable can't be fetched decrypted, it stops before writing anything.
2. It hands Forge that folder through Forge's `Remote` hook. Forge runs its normal conversion: fake-signing the executables, the backport checks, the UFS2 writer and verification.
3. Forge's UFS2 writer normally lays file data out in name order. A small Forge patch (`data_order`) lets it use the image's own order instead, so the game data is still read **as one sequential stream**. The resulting image holds the same files with the same contents. Only where each file's data sits inside the image differs.

`tests/test_ffpkg.py` checks this against the fake console: the single-pass image must unpack (through Forge) to exactly the same files as the folder dump converted by Forge.

There's no resume yet: if the transfer stops, run it again from the start.

## ⚠️ Warnings

- **Don't close the game while a transfer is running.** The mount disappears when the game closes. With on-console dumpers, that has crashed the console. Nobody has tested what happens with ps5-pfs-netdump, so assume it could crash too.
- **Turn off rest mode** and HDMI-CEC "power off link". Rest mode kills payloads and the transfer.
- **Stop the FTP payload when you're done.** Most PS5 FTP payloads have no password and expose the whole filesystem to your network.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests build a fake console in a temporary folder, with a synthetic PFS image, an `app0` mount, an installed `app.pkg`, appmeta, trophy and uds data. They run the whole pipeline against it and check the result file by file. That includes the cases where two steps write the same file, package entries with no name, path-escaping names, resume, and a stream that ends early.

## Legal

ps5-pfs-netdump doesn't bypass any protection itself. It reads files that the console's own kernel exposes on a console you've already jailbroken. Use it only to back up games you own. It includes no game data, keys or Sony code. Laws on circumvention and backups differ by country, and you're responsible for following yours.

## Credits

- [ps5-payload-dev](https://github.com/ps5-payload-dev) for elfldr, ftpsrv and shsrv.
- [PS5 Dump Forge](https://github.com/quer3q/ps5-dump-forge): the `.ffpkg` conversion, verification and UFS2 writer the Rust tool builds on.
- [ps5-app-dumper](https://github.com/EchoStretch/ps5-app-dumper): its dump layout is the reference this tool reproduces and was checked against. No code was copied (ps5-app-dumper is GPL-3.0).
- The PFS layout notes in the pkg-to-anyps5 / LibProsperoPKG projects.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE). The Rust tool links PS5 Dump Forge, which is GPL-3.0-or-later.
