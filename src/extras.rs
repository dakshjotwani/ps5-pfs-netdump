//! What ps5-app-dumper adds around the game files, fetched before the stream and kept in
//! memory: the installed package's `sce_sys` entries, appmeta, trophy and uds data, and the
//! decrypted executables the `app0` mount serves.

use std::collections::BTreeMap;

use anyhow::{Result, bail};

use crate::console::Console;
use crate::pfs::File;

pub const SELF_MAGIC: [u8; 4] = [0x54, 0x14, 0xf5, 0xee];
pub const ELF_MAGIC: [u8; 4] = *b"\x7fELF";
const CNT_MAGIC: [u8; 4] = *b"\x7fCNT";
const PKG_NAME_TABLE: u32 = 0x0200;

/// Names for package entries that have none in the package's name table.
fn pkg_entry_name(typ: u32) -> Option<&'static str> {
    Some(match typ {
        0x0400 => "license.dat",
        0x0401 => "license.info",
        0x0402 => "nptitle.dat",
        0x0403 => "npbind.dat",
        0x0404 => "selfinfo.dat",
        0x0406 => "imageinfo.dat",
        0x0407 => "target-deltainfo.dat",
        0x0408 => "origin-deltainfo.dat",
        0x0409 => "psreserved.dat",
        0x1000 => "param.json",
        0x1001 => "playgo-chunk.dat",
        0x1002 => "playgo-chunk.sha",
        0x1003 => "playgo-manifest.xml",
        0x1004 => "pronunciation.xml",
        0x1005 => "pronunciation.sig",
        0x1006 => "pic1.png",
        0x1007 => "pubtoolinfo.dat",
        0x1200 => "icon0.png",
        0x1220 => "pic0.png",
        0x1240 => "snd0.at9",
        0x1260 => "changeinfo/changeinfo.xml",
        0x1280 => "icon0.dds",
        0x12A0 => "pic0.dds",
        0x12C0 => "pic1.dds",
        _ => return None,
    })
}

/// A relative path that stays inside its folder, or `None`.
pub fn safe_rel(name: &str) -> Option<String> {
    if name.starts_with('/') {
        return None;
    }
    let n = name.replace('\\', "/");
    let parts: Vec<&str> = n.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
    if parts.is_empty() || parts.contains(&"..") {
        return None;
    }
    Some(parts.join("/"))
}

/// The offset of the `_sc.pkg` piece (the package's CNT header) inside `app.pkg`.
pub fn sc_pkg_offset(app_json: &[u8]) -> Option<u64> {
    let doc: serde_json::Value = serde_json::from_slice(app_json).ok()?;
    doc.get("pieces")?.as_array()?.iter().find_map(|p| {
        p.get("url")?.as_str()?.contains("_sc.pkg").then(|| p.get("fileOffset")?.as_u64())?
    })
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
}

/// `(name, offset, size)` for the files in a CNT package whose header starts at `base`.
pub fn pkg_entries(read: &dyn Fn(u64, usize) -> Result<Vec<u8>>, base: u64) -> Result<Vec<(String, u64, u64)>> {
    let hdr = read(base, 0x20)?;
    if hdr.len() < 0x20 || hdr[..4] != CNT_MAGIC {
        bail!("no CNT header at {base:#x} in app.pkg");
    }
    let n = u16::from_be_bytes([hdr[0x12], hdr[0x13]]) as usize;
    let table = u64::from(be32(&hdr, 0x18));
    let raw = read(base + table, n * 32)?;
    if raw.len() != n * 32 {
        bail!("short read of the app.pkg entry table");
    }
    let entries: Vec<[u32; 8]> =
        (0..n).map(|i| std::array::from_fn(|k| be32(&raw, i * 32 + k * 4))).collect();
    let mut names = Vec::new();
    if let Some(e) = entries.iter().find(|e| e[0] == PKG_NAME_TABLE)
        && e[5] > 0
        && e[5] <= 64 * 1024
    {
        names = read(base + u64::from(e[4]), e[5] as usize)?;
    }
    let mut out = Vec::new();
    for e in &entries {
        let (typ, name_off, off, size) = (e[0], e[1] as usize, e[4], e[5]);
        if size == 0 {
            continue;
        }
        let mut name = String::new();
        if name_off < names.len() {
            let end = names[name_off..].iter().position(|&b| b == 0).map_or(names.len(), |p| name_off + p);
            name = String::from_utf8_lossy(&names[name_off..end]).into_owned();
        }
        if name.is_empty() {
            name = pkg_entry_name(typ).unwrap_or_default().to_string();
        }
        if let Some(rel) = (!name.is_empty()).then(|| safe_rel(&name)).flatten() {
            out.push((rel, u64::from(off), u64::from(size)));
        }
    }
    Ok(out)
}

/// The trophy/uds communication id: the printable run starting at `NPWR`.
pub fn npwr_id(npbind: &[u8]) -> Option<String> {
    let i = npbind.windows(4).position(|w| w == b"NPWR")?;
    let mut j = i;
    while j < npbind.len() && j - i < 31 && (0x20..0x7F).contains(&npbind[j]) {
        j += 1;
    }
    Some(String::from_utf8_lossy(&npbind[i..j]).into_owned())
}

/// A light check on a decrypted ELF: the header, and every program header's file range
/// inside the file.
pub fn elf_ok(b: &[u8]) -> bool {
    if b.len() < 64 || b[..4] != ELF_MAGIC || b[4] != 2 {
        return false;
    }
    let phoff = u64::from_le_bytes(b[0x20..0x28].try_into().unwrap()) as usize;
    let (phent, phnum) =
        (u16::from_le_bytes([b[0x36], b[0x37]]) as usize, u16::from_le_bytes([b[0x38], b[0x39]]) as usize);
    if phnum == 0 || phent < 56 || phoff.saturating_add(phnum * phent) > b.len() {
        return false;
    }
    (0..phnum).all(|i| {
        let at = phoff + i * phent;
        let off = u64::from_le_bytes(b[at + 8..at + 16].try_into().unwrap());
        let filesz = u64::from_le_bytes(b[at + 32..at + 40].try_into().unwrap());
        filesz == 0 || off.saturating_add(filesz) <= b.len() as u64
    })
}

/// Paths that may hold an executable: the only files whose magic is checked up front.
pub fn may_be_executable(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [".bin", ".prx", ".sprx", ".elf", ".self"].iter().any(|e| p.ends_with(e))
}

/// Files that replace or join the game files, in the dumper's order (a later step wins).
#[derive(Default)]
pub struct Extras {
    pub files: BTreeMap<String, Vec<u8>>,
    pub log: Vec<String>,
}

impl Extras {
    fn put(&mut self, rel: String, data: Vec<u8>) {
        self.files.insert(rel, data);
    }

    /// Step 1: the package's `sce_sys` entries, except paths the game files provide (the
    /// dumper copies `app0` afterwards, so `app0` wins).
    pub fn package(&mut self, c: &dyn Console, title: &str, game: &[File]) -> Result<()> {
        let mut pkg = None;
        for root in ["/user/app", "/mnt/ext1/user/app", "/mnt/ext0/user/app"] {
            let p = format!("{root}/{title}/app.pkg");
            if c.size(&p)?.is_some_and(|n| n > 0) {
                pkg = Some(p);
                break;
            }
        }
        let Some(pkg) = pkg else {
            self.log.push("no installed app.pkg found; skipping package sce_sys entries".into());
            return Ok(());
        };
        let json = pkg.trim_end_matches(".pkg").to_string() + ".json";
        let base = match c.size(&json)? {
            Some(_) => sc_pkg_offset(&c.read_all(&json)?),
            None => None,
        };
        let Some(base) = base else {
            self.log.push(format!("no _sc.pkg piece in {json}; skipping package sce_sys entries"));
            return Ok(());
        };
        let read = |off: u64, n: usize| -> Result<Vec<u8>> { Ok(c.read(&pkg, off, n)?) };
        let game: std::collections::HashSet<&str> = game.iter().map(|f| f.path.as_str()).collect();
        let mut n = 0;
        for (rel, off, size) in pkg_entries(&read, base)? {
            let rel = format!("sce_sys/{rel}");
            if game.contains(rel.as_str()) {
                continue;
            }
            let data = c.read(&pkg, base + off, size as usize)?;
            if data.len() as u64 != size {
                bail!("short read of {rel} from {pkg}");
            }
            self.put(rel, data);
            n += 1;
        }
        self.log.push(format!("{pkg}: {n} sce_sys files"));
        Ok(())
    }

    fn copy_tree(&mut self, c: &dyn Console, src: &str, dst: &str) -> Result<Option<usize>> {
        let Some(items) = c.list(src)? else { return Ok(None) };
        let mut n = 0;
        for (name, is_dir, _) in items {
            if safe_rel(&name).as_deref() != Some(name.as_str()) {
                continue;
            }
            let (s, d) = (format!("{src}/{name}"), format!("{dst}/{name}"));
            if is_dir {
                n += self.copy_tree(c, &s, &d)?.unwrap_or(0);
            } else {
                self.put(d, c.read_all(&s)?);
                n += 1;
            }
        }
        Ok(Some(n))
    }

    /// Steps 3 and 4: appmeta, then trophy and uds through the NPWR id in `npbind.dat`.
    pub fn appmeta_trophy_uds(&mut self, c: &dyn Console, title: &str) -> Result<()> {
        for src in [format!("/user/appmeta/{title}"), format!("/system_data/priv/appmeta/{title}")] {
            let line = match self.copy_tree(c, &src, "sce_sys")? {
                Some(n) => format!("{src}: {n} files"),
                None => format!("{src}: not found"),
            };
            self.log.push(line);
        }
        let mut npbind = None;
        for p in [
            format!("/system_data/priv/appmeta/{title}/trophy2/npbind.dat"),
            format!("/system_data/priv/appmeta/{title}/uds/npbind.dat"),
        ] {
            if let Some(n) = c.size(&p)?.filter(|&n| n > 0) {
                npbind = Some(c.read(&p, 0, n.min(4096) as usize)?);
                break;
            }
        }
        let Some(id) = npbind.as_deref().and_then(npwr_id) else {
            self.log.push("no NPWR id in npbind.dat; no trophy or uds data".into());
            return Ok(());
        };
        for (src, rel) in [
            (format!("/user/trophy2/nobackup/conf/{id}/TROPHY.UCP"), "sce_sys/trophy2/trophy00.ucp"),
            (format!("/user/np_uds/nobackup/conf/{id}/uds.ucp"), "sce_sys/uds/uds00.ucp"),
        ] {
            if c.size(&src)?.is_some_and(|n| n > 0) {
                self.put(rel.to_string(), c.read_all(&src)?);
                self.log.push(format!("{src} -> {rel}"));
            } else {
                self.log.push(format!("{src}: not found"));
            }
        }
        Ok(())
    }

    /// Step 5: every game file that is an encrypted SELF, replaced by the decrypted ELF the
    /// `app0` mount serves. Returns the ones that stay encrypted.
    pub fn executables(&mut self, c: &dyn Console, nest: &str, app0: &str, game: &[File]) -> Result<Vec<String>> {
        let mut failed = Vec::new();
        for f in game.iter().filter(|f| f.size >= 4 && may_be_executable(&f.path)) {
            if c.read(nest, f.offset, 4)? != SELF_MAGIC {
                continue;
            }
            let src = format!("{app0}/{}", f.path);
            match c.read_all(&src) {
                Ok(elf) if elf_ok(&elf) => {
                    self.log.push(format!("{}: decrypted ELF, {} bytes", f.path, elf.len()));
                    self.put(f.path.clone(), elf);
                }
                Ok(_) => {
                    self.log.push(format!("{}: app0 did not return a valid ELF; keeping the encrypted SELF", f.path));
                    failed.push(f.path.clone());
                }
                Err(e) => {
                    self.log.push(format!("{}: download failed ({e}); keeping the encrypted SELF", f.path));
                    failed.push(f.path.clone());
                }
            }
        }
        Ok(failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_rel_refuses_escapes() {
        assert_eq!(safe_rel("a/./b"), Some("a/b".into()));
        assert_eq!(safe_rel("a\\b"), Some("a/b".into()));
        assert_eq!(safe_rel("../x"), None);
        assert_eq!(safe_rel("/x"), None);
        assert_eq!(safe_rel(""), None);
    }

    #[test]
    fn npwr() {
        assert_eq!(npwr_id(b"\0\0NPWR21008_00\0junk").as_deref(), Some("NPWR21008_00"));
        assert_eq!(npwr_id(b"nothing"), None);
    }

    #[test]
    fn sc_offset() {
        let j = br#"{"pieces":[{"fileOffset":0,"url":"x_0.pkg"},{"fileOffset":4096,"url":"x_sc.pkg"}]}"#;
        assert_eq!(sc_pkg_offset(j), Some(4096));
    }
}
