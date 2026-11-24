//! The game's inner PFS image as the kernel serves it through the `-nest` mount: decrypted,
//! decompressed, flat. Its superblock, inode table and directories sit near the end.

use anyhow::{Result, anyhow, bail};

use crate::console::Console;

pub const PFS_MAGIC: u64 = 20130315; // 0x01332A0B
const INODE_SIZE: u64 = 0xA8;
const DIRENT_FILE: u32 = 2;
const DIRENT_DIR: u32 = 3;
const MB: u64 = 1 << 20;

#[derive(Debug, Clone)]
pub struct Superblock {
    pub offset: u64,
    pub block_size: u64,
    pub inode_count: u64,
}

fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn superblock_at(buf: &[u8], pos: usize, base: u64, image_size: u64) -> Option<Superblock> {
    if pos + 0x40 > buf.len() {
        return None;
    }
    let (version, magic) = (u64le(buf, pos), u64le(buf, pos + 8));
    if magic != PFS_MAGIC || !(1..=3).contains(&version) {
        return None;
    }
    let block_size = u64::from(u32le(buf, pos + 0x20));
    let inode_count = u64le(buf, pos + 0x30);
    let block_count = u64le(buf, pos + 0x38);
    let offset = base + pos as u64;
    if block_size == 0 || block_size % 0x1000 != 0 || block_size > MB {
        return None;
    }
    if block_count.checked_mul(block_size) != Some(image_size) || offset % block_size != 0 {
        return None;
    }
    let _ = u16le(buf, pos + 0x1C); // mode: flat images are 0x18; not checked
    Some(Superblock { offset, block_size, inode_count })
}

/// A file in the image: path relative to the super-root, data offset, size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub path: String,
    pub offset: u64,
    pub size: u64,
}

pub struct Image<'a> {
    console: &'a dyn Console,
    path: String,
    pub size: u64,
    pub sb: Superblock,
    tail: Vec<u8>,
    tail_base: u64,
    inodes: Vec<(u64, u64)>, // (size, location)
}

impl<'a> Image<'a> {
    /// Finds the superblock in the last 64 MB … 4 GB of the image, nearest the end first.
    pub fn open(console: &'a dyn Console, path: &str, log: &dyn Fn(String)) -> Result<Self> {
        let size = console
            .size(path)?
            .filter(|&n| n > 0)
            .ok_or_else(|| anyhow!("{path} not found. Is the game running?"))?;
        let mut have: Vec<u8> = Vec::new();
        for win in [64 * MB, 256 * MB, 1024 * MB, 4096 * MB] {
            let win = win.min(size);
            if win > have.len() as u64 {
                log(format!("searching the last {} MB for the superblock ...", win / MB));
                let start = size - win;
                let mut more = console.read(path, start, (win - have.len() as u64) as usize)?;
                more.extend_from_slice(&have);
                have = more;
            }
            let base = size - have.len() as u64;
            let mut pos = (have.len().saturating_sub(0x400)) & !0xFFF;
            loop {
                if (base + pos as u64) % 0x1000 == 0
                    && let Some(sb) = superblock_at(&have, pos, base, size)
                {
                    let tail = have.split_off(pos);
                    let mut img = Image {
                        console,
                        path: path.to_string(),
                        size,
                        tail_base: sb.offset,
                        sb,
                        tail,
                        inodes: Vec::new(),
                    };
                    img.read_inodes()?;
                    return Ok(img);
                }
                if pos < 0x1000 {
                    break;
                }
                pos -= 0x1000;
            }
            if win >= size {
                break;
            }
        }
        bail!("no PFS superblock found near the end of the image (is the game still running, and is this a -nest mount?)")
    }

    fn read(&self, off: u64, n: u64) -> Result<Vec<u8>> {
        if off >= self.tail_base && off + n <= self.tail_base + self.tail.len() as u64 {
            let s = (off - self.tail_base) as usize;
            return Ok(self.tail[s..s + n as usize].to_vec());
        }
        let data = self.console.read(&self.path, off, n as usize)?;
        if data.len() as u64 != n {
            bail!("short read at {off}");
        }
        Ok(data)
    }

    fn read_inodes(&mut self) -> Result<()> {
        let bs = self.sb.block_size;
        let per_block = bs / INODE_SIZE;
        let table = self.sb.offset + bs;
        let blocks = self.sb.inode_count.div_ceil(per_block);
        let raw = self.read(table, blocks * bs)?;
        self.inodes = (0..self.sb.inode_count)
            .map(|i| {
                let at = ((i / per_block) * bs + (i % per_block) * INODE_SIZE) as usize;
                (u64le(&raw, at + 0x08), u64le(&raw, at + 0x60))
            })
            .collect();
        Ok(())
    }

    fn dirents(&self, ino: u64) -> Result<Vec<(u64, u32, String)>> {
        let &(size, loc) = self.inodes.get(ino as usize).ok_or_else(|| anyhow!("inode {ino} out of range"))?;
        let buf = self.read(loc, size)?;
        let bs = self.sb.block_size as usize;
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos + 16 <= buf.len() {
            let (child, kind, name_len, rec_len) =
                (u32le(&buf, pos), u32le(&buf, pos + 4), u32le(&buf, pos + 8) as usize, u32le(&buf, pos + 12) as usize);
            if rec_len == 0 {
                pos += bs - pos % bs; // the rest of this block is padding
                continue;
            }
            let end = (pos + 16 + name_len).min(buf.len());
            out.push((u64::from(child), kind, String::from_utf8_lossy(&buf[pos + 16..end]).into_owned()));
            pos += rec_len;
        }
        Ok(out)
    }

    /// Every file and directory, paths relative to the super-root ("/uroot/...").
    pub fn walk(&self) -> Result<(Vec<File>, Vec<String>)> {
        let (mut files, mut dirs) = (Vec::new(), Vec::new());
        let mut seen = std::collections::HashSet::new();
        let mut stack = vec![(0u64, String::new())];
        while let Some((ino, path)) = stack.pop() {
            if !seen.insert(ino) {
                continue;
            }
            for (child, kind, name) in self.dirents(ino)? {
                if name == "." || name == ".." {
                    continue;
                }
                if name.is_empty() || name.contains('/') {
                    bail!("bad file name {name:?} in {}", if path.is_empty() { "/" } else { &path });
                }
                let p = format!("{path}/{name}");
                match kind {
                    DIRENT_DIR => {
                        dirs.push(p.clone());
                        stack.push((child, p));
                    }
                    DIRENT_FILE => {
                        let &(size, offset) =
                            self.inodes.get(child as usize).ok_or_else(|| anyhow!("{p}: inode out of range"))?;
                        files.push(File { path: p, offset, size });
                    }
                    _ => {}
                }
            }
        }
        Ok((files, dirs))
    }
}

/// Game files under `/uroot`, relative to it and sorted by offset; overlapping files refused.
pub fn game_files(files: &[File]) -> Result<Vec<File>> {
    let mut out: Vec<File> = files
        .iter()
        .filter_map(|f| {
            f.path.strip_prefix("/uroot/").map(|p| File { path: p.to_string(), offset: f.offset, size: f.size })
        })
        .collect();
    out.sort_by(|a, b| (a.offset, &a.path).cmp(&(b.offset, &b.path)));
    for w in out.windows(2) {
        if w[0].size > 0 && w[0].offset + w[0].size > w[1].offset {
            bail!("files overlap in the image: {} and {}", w[0].path, w[1].path);
        }
    }
    Ok(out)
}
