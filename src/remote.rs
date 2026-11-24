//! The game as a read-only folder Forge reads through its `Remote` hook: game files served
//! from one front-to-back stream of the `-nest` image, the extras from memory.

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read};
use std::sync::{Arc, Mutex};

use ps5_dump_forge_core::remote::{FlinkPath, Remote, RemoteEntry, RemoteStat};

use crate::console::Console;

/// The key id of the `flink://` paths this serves (any 32 hex digits do).
pub const KEY_ID: &str = "00000000000000000000000000000005";
/// The folder the game is served as.
pub const ROOT: &str = "game";

/// Forward gaps up to this are read through; a longer one reopens the stream there.
const SKIP_MAX: u64 = 64 << 20;
/// A read off the stream's path up to this size is served by a one-off ranged read, so a
/// probe (a magic number, a header) doesn't move the stream.
const ONE_OFF_MAX: usize = 4 << 20;
/// The last bytes streamed are kept this long, for a read just behind the stream: Forge
/// reads ahead one chunk, and where the writer then asks for a shorter range (a file's data
/// split at an indirect block or a cylinder group) its next request starts behind the guess.
const BEHIND_MAX: usize = 32 << 20;

enum Node {
    Dir,
    Mem(Arc<Vec<u8>>),
    /// A game file: its data offset in the image and size.
    Image { offset: u64, size: u64 },
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub streamed: u64,
    pub skipped: u64,
    pub reopened: u64,
    pub one_off_reads: u64,
    pub one_off_bytes: u64,
    /// Bytes served again from the kept tail of the stream.
    pub from_memory: u64,
}

struct Stream {
    reader: Option<Box<dyn Read + Send>>,
    pos: u64,
    /// The stream's last bytes, ending at `pos`.
    tail: VecDeque<u8>,
    stats: Stats,
}

pub struct GameRemote {
    console: Arc<dyn Console>,
    image: String,
    nodes: BTreeMap<String, Node>,
    stream: Mutex<Stream>,
}

impl GameRemote {
    /// `game`: (path, offset, size) of the files to serve from the image; `mem`: the rest.
    pub fn new(
        console: Arc<dyn Console>,
        image: &str,
        game: impl IntoIterator<Item = (String, u64, u64)>,
        mem: impl IntoIterator<Item = (String, Vec<u8>)>,
        dirs: impl IntoIterator<Item = String>,
    ) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(String::new(), Node::Dir);
        let add_dirs = |nodes: &mut BTreeMap<String, Node>, path: &str| {
            let mut at = 0;
            while let Some(i) = path[at..].find('/') {
                nodes.entry(path[..at + i].to_string()).or_insert(Node::Dir);
                at += i + 1;
            }
        };
        for d in dirs {
            add_dirs(&mut nodes, &d);
            nodes.insert(d, Node::Dir);
        }
        for (p, offset, size) in game {
            add_dirs(&mut nodes, &p);
            nodes.insert(p, Node::Image { offset, size });
        }
        for (p, data) in mem {
            add_dirs(&mut nodes, &p);
            nodes.insert(p, Node::Mem(Arc::new(data)));
        }
        Self {
            console,
            image: image.to_string(),
            nodes,
            stream: Mutex::new(Stream { reader: None, pos: 0, tail: VecDeque::new(), stats: Stats::default() }),
        }
    }

    pub fn stats(&self) -> Stats {
        self.stream.lock().unwrap_or_else(|e| e.into_inner()).stats
    }

    fn rel<'a>(&self, path: &'a FlinkPath) -> io::Result<&'a str> {
        let p = path.path.as_str();
        if p == ROOT {
            return Ok("");
        }
        p.strip_prefix(ROOT).and_then(|r| r.strip_prefix('/')).ok_or_else(|| not_found(p))
    }

    fn node(&self, path: &FlinkPath) -> io::Result<(&str, &Node)> {
        let rel = self.rel(path)?;
        self.nodes.get_key_value(rel).map(|(k, v)| (k.as_str(), v)).ok_or_else(|| not_found(&path.path))
    }

    /// `len` bytes of the image at `at`.
    fn image_read(&self, at: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut s = self.stream.lock().unwrap_or_else(|e| e.into_inner());
        let tail_start = s.pos - s.tail.len() as u64;
        if s.reader.is_some() && at >= tail_start && at < s.pos {
            let from = (at - tail_start) as usize;
            let have = (s.tail.len() - from).min(len);
            let mut out: Vec<u8> = s.tail.range(from..from + have).copied().collect();
            s.stats.from_memory += have as u64;
            if have < len {
                let pos = s.pos;
                out.extend(self.pull(&mut s, pos, len - have)?);
            }
            return Ok(out);
        }
        let on_stream = s.reader.is_some() && at >= s.pos && at - s.pos <= SKIP_MAX;
        // A small read off the stream (or before it opens: Forge's preflight probes headers)
        // is a one-off, so the stream opens where the writer starts.
        if !on_stream && len <= ONE_OFF_MAX {
            s.stats.one_off_reads += 1;
            s.stats.one_off_bytes += len as u64;
            drop(s);
            return self.console.read(&self.image, at, len);
        }
        if !on_stream {
            if s.reader.is_some() {
                s.stats.reopened += 1;
            }
            s.reader = Some(self.console.stream(&self.image, at)?);
            s.pos = at;
            s.tail.clear();
        }
        self.pull(&mut s, at, len)
    }

    /// Reads on along the open stream (which is at or before `at`) and returns `len` bytes at
    /// `at`; everything read joins the kept tail.
    fn pull(&self, s: &mut Stream, at: u64, len: usize) -> io::Result<Vec<u8>> {
        let gap = at - s.pos;
        let r = s.reader.as_mut().expect("an open stream");
        let res = (|| -> io::Result<(Vec<u8>, Vec<u8>)> {
            let mut skipped = Vec::with_capacity(gap as usize);
            r.by_ref().take(gap).read_to_end(&mut skipped)?;
            if skipped.len() as u64 != gap {
                return Err(early_end());
            }
            let mut buf = vec![0u8; len];
            r.read_exact(&mut buf).map_err(|e| {
                if e.kind() == io::ErrorKind::UnexpectedEof { early_end() } else { e }
            })?;
            Ok((skipped, buf))
        })();
        let (skipped, buf) = match res {
            Ok(v) => v,
            Err(e) => {
                s.reader = None;
                s.tail.clear();
                return Err(e);
            }
        };
        s.pos = at + len as u64;
        s.stats.skipped += gap;
        s.stats.streamed += len as u64;
        s.tail.extend(&skipped);
        s.tail.extend(&buf);
        if s.tail.len() > BEHIND_MAX {
            let extra = s.tail.len() - BEHIND_MAX;
            s.tail.drain(..extra);
        }
        Ok(buf)
    }
}

fn not_found(p: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("{p}: not found"))
}

fn early_end() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "the image stream ended early (did the game close?)")
}

fn read_only() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "the game is read only")
}

fn stat_of(node: &Node) -> RemoteStat {
    match node {
        Node::Dir => RemoteStat { dir: true, size: 0, mtime: None, link: false },
        Node::Mem(d) => RemoteStat { dir: false, size: d.len() as u64, mtime: None, link: false },
        Node::Image { size, .. } => RemoteStat { dir: false, size: *size, mtime: None, link: false },
    }
}

impl Remote for GameRemote {
    fn stat(&self, path: &FlinkPath) -> io::Result<RemoteStat> {
        Ok(stat_of(self.node(path)?.1))
    }

    fn list(&self, path: &FlinkPath) -> io::Result<Vec<RemoteEntry>> {
        let (rel, node) = self.node(path)?;
        if !matches!(node, Node::Dir) {
            return Err(io::Error::new(io::ErrorKind::NotADirectory, path.path.clone()));
        }
        let prefix = if rel.is_empty() { String::new() } else { format!("{rel}/") };
        let mut out = Vec::new();
        for (k, v) in self.nodes.range(prefix.clone()..) {
            let Some(name) = k.strip_prefix(&prefix) else { break };
            if name.is_empty() || name.contains('/') {
                continue;
            }
            let st = stat_of(v);
            out.push(RemoteEntry { name: name.to_string(), dir: st.dir, size: st.size, ..Default::default() });
        }
        Ok(out)
    }

    fn read_at(&self, path: &FlinkPath, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        match self.node(path)?.1 {
            Node::Dir => Err(io::Error::new(io::ErrorKind::IsADirectory, path.path.clone())),
            Node::Mem(d) => {
                let s = (offset.min(d.len() as u64)) as usize;
                Ok(d[s..(s + len).min(d.len())].to_vec())
            }
            Node::Image { offset: base, size } => {
                let len = len.min(size.saturating_sub(offset) as usize);
                if len == 0 {
                    return Ok(Vec::new());
                }
                self.image_read(base + offset, len)
            }
        }
    }

    fn mkdir(&self, _: &FlinkPath) -> io::Result<()> {
        Err(read_only())
    }
    fn create(&self, _: &FlinkPath) -> io::Result<u64> {
        Err(read_only())
    }
    fn write_at(&self, _: u64, _: u64, _: &[u8]) -> io::Result<()> {
        Err(read_only())
    }
    fn sync(&self, _: u64) -> io::Result<()> {
        Err(read_only())
    }
    fn close(&self, _: u64) -> io::Result<()> {
        Err(read_only())
    }
    fn rename_no_replace(&self, _: &FlinkPath, _: &FlinkPath) -> io::Result<()> {
        Err(read_only())
    }
    fn rename_replace(&self, _: &FlinkPath, _: &FlinkPath) -> io::Result<()> {
        Err(read_only())
    }
    fn remove(&self, _: &FlinkPath) -> io::Result<()> {
        Err(read_only())
    }
    fn free_space(&self, _: &FlinkPath) -> io::Result<u64> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::console::Entry;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// An image in memory that counts the streams opened on it.
    struct Mem(Vec<u8>, AtomicU64);

    impl Console for Mem {
        fn list(&self, _: &str) -> io::Result<Option<Vec<Entry>>> {
            Ok(None)
        }
        fn size(&self, _: &str) -> io::Result<Option<u64>> {
            Ok(Some(self.0.len() as u64))
        }
        fn read(&self, _: &str, offset: u64, len: usize) -> io::Result<Vec<u8>> {
            let s = (offset as usize).min(self.0.len());
            Ok(self.0[s..(s + len).min(self.0.len())].to_vec())
        }
        fn stream(&self, _: &str, offset: u64) -> io::Result<Box<dyn Read + Send>> {
            self.1.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(io::Cursor::new(self.0[offset as usize..].to_vec())))
        }
    }

    fn path(p: &str) -> FlinkPath {
        FlinkPath { key_id: KEY_ID.into(), path: format!("{ROOT}/{p}"), scheme: ps5_dump_forge_core::remote::Scheme::Flink }
    }

    /// Forge's read-ahead guesses one 8 MiB chunk past the last; the writer then asks for a
    /// shorter range there (a block map boundary). That must not reopen the stream.
    #[test]
    fn a_read_behind_a_read_ahead_guess_is_served_from_memory() {
        let image: Vec<u8> = (0..64u32 << 20).map(|i| (i * 7 + i / 251) as u8).collect();
        let mem = Arc::new(Mem(image.clone(), AtomicU64::new(0)));
        let r = GameRemote::new(
            mem.clone(),
            "img",
            [("a".to_string(), 1 << 20, 40 << 20), ("b".to_string(), 42 << 20, 20 << 20)],
            [],
            [],
        );
        let (a, b) = (path("a"), path("b"));
        let mb = 1usize << 20;
        let expect = |at: usize, len: usize| image[at..at + len].to_vec();
        assert_eq!(r.read_at(&a, 0, 8 * mb).unwrap(), expect(mb, 8 * mb));
        assert_eq!(r.read_at(&a, 8 * mb as u64, 8 * mb).unwrap(), expect(9 * mb, 8 * mb)); // the guess
        // The writer asks for 3 MiB there, then 8 MiB from the end of that.
        assert_eq!(r.read_at(&a, 8 * mb as u64, 3 * mb).unwrap(), expect(9 * mb, 3 * mb));
        assert_eq!(r.read_at(&a, 11 * mb as u64, 8 * mb).unwrap(), expect(12 * mb, 8 * mb));
        assert_eq!(r.read_at(&a, 19 * mb as u64, 21 * mb).unwrap(), expect(20 * mb, 21 * mb));
        assert_eq!(r.read_at(&b, 0, 20 * mb).unwrap(), expect(42 * mb, 20 * mb));
        let st = r.stats();
        assert_eq!((mem.1.load(Ordering::SeqCst), st.reopened, st.one_off_reads), (1, 0, 0));
        assert_eq!((st.streamed, st.skipped), (60 * mb as u64, mb as u64));
        assert_eq!(st.from_memory, 8 * mb as u64);
    }

    /// Header probes before the writer starts must not open the stream where they look.
    #[test]
    fn probes_before_the_first_write_do_not_open_the_stream() {
        let image: Vec<u8> = (0..32u32 << 20).map(|i| (i ^ (i >> 9)) as u8).collect();
        let mem = Arc::new(Mem(image.clone(), AtomicU64::new(0)));
        let r = GameRemote::new(
            mem.clone(),
            "img",
            [("a".to_string(), 0, 16 << 20), ("b".to_string(), 16 << 20, 16 << 20)],
            [],
            [],
        );
        let mb = 1usize << 20;
        assert_eq!(r.read_at(&path("b"), 0, 0x40).unwrap(), image[16 * mb..16 * mb + 0x40]);
        for (p, base) in [("a", 0), ("b", 16 * mb)] {
            for at in (0..16 * mb).step_by(8 * mb) {
                assert_eq!(r.read_at(&path(p), at as u64, 8 * mb).unwrap(), image[base + at..base + at + 8 * mb]);
            }
        }
        let st = r.stats();
        assert_eq!((mem.1.load(Ordering::SeqCst), st.reopened, st.one_off_reads), (1, 0, 1));
    }
}
